// @license
// SPDX-License-Identifier: Apache-2.0

package tokenizer

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTokenizerExtractAndTokenize(t *testing.T) {
	pipe := NewPipeline()

	req := httptest.NewRequest(http.MethodGet, "/api/v2/products?sort=asc&limit=10", nil)
	req.Header.Set("User-Agent", "Go-Unit-Test/1.0")

	res, err := pipe.ExtractAndTokenize(req, "test-req-1", "192.168.1.100")
	if err != nil {
		t.Fatalf("ExtractAndTokenize returned unexpected error: %v", err)
	}

	if res.RequestID != "test-req-1" {
		t.Errorf("Expected RequestID 'test-req-1', got %s", res.RequestID)
	}
	if res.ClientIP != "192.168.1.100" {
		t.Errorf("Expected ClientIP '192.168.1.100', got %s", res.ClientIP)
	}
	if len(res.URITokens.TokenIDs) == 0 {
		t.Errorf("Expected non-empty URI tokens")
	}
	if len(res.HeaderTokens.TokenIDs) == 0 {
		t.Errorf("Expected non-empty header tokens")
	}
}

func TestTokenizerBodyStreamPreservation(t *testing.T) {
	pipe := NewPipeline()
	bodyContent := []byte(`{"action":"login","username":"admin"}`)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(bodyContent))
	req.Header.Set("Content-Type", "application/json")

	res, err := pipe.ExtractAndTokenize(req, "test-req-2", "10.0.0.1")
	if err != nil {
		t.Fatalf("ExtractAndTokenize error: %v", err)
	}

	if len(res.BodyTokens.TokenIDs) == 0 {
		t.Errorf("Expected body tokens to be extracted")
	}

	// Verify request body can still be read downstream by httputil.ReverseProxy
	var buf bytes.Buffer
	_, err = buf.ReadFrom(req.Body)
	if err != nil {
		t.Fatalf("Failed to re-read body after tokenization: %v", err)
	}

	if !bytes.Equal(buf.Bytes(), bodyContent) {
		t.Errorf("Body content was corrupted by tokenizer stream inspection")
	}
}

func BenchmarkTokenizer(b *testing.B) {
	pipe := NewPipeline()
	rawURI := "/api/v1/orders/lookup?transaction_id=894104810&currency=USD"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = pipe.TokenizeString(rawURI, 1)
	}
}
