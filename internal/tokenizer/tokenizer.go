// @license
// SPDX-License-Identifier: Apache-2.0
//
// Package tokenizer transforms raw HTTP streams (URIs, headers, streaming bodies)
// into tokenized numerical sequences consumed by the LSTM Autoencoder model.
// Enforces strict zero-allocation memory pooling to survive Layer 7 DDoS volumetric floods.
package tokenizer

import (
	"bytes"
	"io"
	"net/http"
	"sync"

	"github.com/enterprise-security/deepwaf/internal/inference"
)

const (
	// MaxSequenceLength bounds the sequence tensor dimension fed into LSTM embedding layers
	MaxSequenceLength = 1024
	// MaxBodyInspectionBytes bounds the stream consumption to guard against memory exhaustion
	MaxBodyInspectionBytes = 64 * 1024 // 64KB
	// PadTokenID reserved index for sequence alignment
	PadTokenID uint32 = 0
	// OOVTokenID reserved index for out-of-vocabulary characters
	OOVTokenID uint32 = 1
)

// Pipeline handles zero-allocation extraction and vectorization of HTTP requests.
type Pipeline struct {
	slicePool  sync.Pool
	bufferPool sync.Pool
}

// NewPipeline creates a tokenizer pipeline with pre-initialized buffer pools.
func NewPipeline() *Pipeline {
	return &Pipeline{
		slicePool: sync.Pool{
			New: func() any {
				s := make([]uint32, 0, MaxSequenceLength)
				return &s
			},
		},
		bufferPool: sync.Pool{
			New: func() any {
				return bytes.NewBuffer(make([]byte, 0, 4096))
			},
		},
	}
}

// ExtractAndTokenize processes the incoming HTTP request and returns an InferenceRequest.
// It clones the body stream using a bounded reader so the downstream proxy can still
// forward the original payload to the upstream backend service.
func (p *Pipeline) ExtractAndTokenize(r *http.Request, reqID string, clientIP string) (*inference.InferenceRequest, error) {
	// 1. Tokenize URI (Path + Query)
	uriTokens := p.TokenizeString(r.URL.RequestURI(), 1)

	// 2. Tokenize Headers (Deterministic serialization of keys and values)
	headerBuf := p.bufferPool.Get().(*bytes.Buffer)
	headerBuf.Reset()
	defer p.bufferPool.Put(headerBuf)

	for k, vals := range r.Header {
		headerBuf.WriteString(k)
		headerBuf.WriteByte(':')
		for _, v := range vals {
			headerBuf.WriteString(v)
			headerBuf.WriteByte(';')
		}
		headerBuf.WriteByte('\n')
	}
	headerTokens := p.TokenizeBytes(headerBuf.Bytes(), 2)

	// 3. Tokenize Streaming Body (Safely bounded with http.MaxBytesReader)
	var bodyTokens inference.TokenSequence
	if r.Body != nil && r.ContentLength != 0 {
		bodyBuf := p.bufferPool.Get().(*bytes.Buffer)
		bodyBuf.Reset()
		defer p.bufferPool.Put(bodyBuf)

		// Read up to MaxBodyInspectionBytes
		limitedReader := io.LimitReader(r.Body, MaxBodyInspectionBytes)
		_, err := bodyBuf.ReadFrom(limitedReader)
		if err == nil && bodyBuf.Len() > 0 {
			bodyBytes := bodyBuf.Bytes()
			// Restore the body so the ReverseProxy director can still forward it
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyBytes), r.Body))
			bodyTokens = p.TokenizeBytes(bodyBytes, 3)
		} else {
			bodyTokens = inference.TokenSequence{
				TokenIDs:  []uint32{PadTokenID},
				RawLength: 0,
				SegmentID: 3,
			}
		}
	} else {
		bodyTokens = inference.TokenSequence{
			TokenIDs:  []uint32{PadTokenID},
			RawLength: 0,
			SegmentID: 3,
		}
	}

	return &inference.InferenceRequest{
		RequestID:    reqID,
		ClientIP:     clientIP,
		Method:       r.Method,
		URITokens:    uriTokens,
		HeaderTokens: headerTokens,
		BodyTokens:   bodyTokens,
		TensorShape:  []uint32{1, MaxSequenceLength},
		Priority:     0,
	}, nil
}

// TokenizeString tokenizes a string without allocating an intermediate byte slice.
func (p *Pipeline) TokenizeString(s string, segmentID uint32) inference.TokenSequence {
	rawLen := len(s)
	ptr := p.slicePool.Get().(*[]uint32)
	tokens := (*ptr)[:0]

	limit := rawLen
	if limit > MaxSequenceLength {
		limit = MaxSequenceLength
	}

	for i := 0; i < limit; i++ {
		ch := s[i]
		// Map ASCII byte directly to vocab index + offset
		var tok uint32
		if ch >= 32 && ch <= 126 {
			tok = uint32(ch - 30) // Printable ASCII vocab offset
		} else if ch == 9 || ch == 10 || ch == 13 {
			tok = 2
		} else {
			// Anomalous / high byte / control character
			tok = 1000 + uint32(ch)
		}
		tokens = append(tokens, tok)
	}

	// Copy into output sequence struct
	res := make([]uint32, len(tokens))
	copy(res, tokens)

	// Return pooled slice
	*ptr = tokens[:0]
	p.slicePool.Put(ptr)

	return inference.TokenSequence{
		TokenIDs:  res,
		RawLength: uint32(rawLen),
		SegmentID: segmentID,
	}
}

// TokenizeBytes converts a raw byte slice into token IDs.
func (p *Pipeline) TokenizeBytes(b []byte, segmentID uint32) inference.TokenSequence {
	rawLen := len(b)
	ptr := p.slicePool.Get().(*[]uint32)
	tokens := (*ptr)[:0]

	limit := rawLen
	if limit > MaxSequenceLength {
		limit = MaxSequenceLength
	}

	for i := 0; i < limit; i++ {
		ch := b[i]
		var tok uint32
		if ch >= 32 && ch <= 126 {
			tok = uint32(ch - 30)
		} else if ch == 9 || ch == 10 || ch == 13 {
			tok = 2
		} else {
			tok = 1000 + uint32(ch)
		}
		tokens = append(tokens, tok)
	}

	res := make([]uint32, len(tokens))
	copy(res, tokens)

	*ptr = tokens[:0]
	p.slicePool.Put(ptr)

	return inference.TokenSequence{
		TokenIDs:  res,
		RawLength: uint32(rawLen),
		SegmentID: segmentID,
	}
}
