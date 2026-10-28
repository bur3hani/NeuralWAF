// @license
// SPDX-License-Identifier: Apache-2.0

package inference

import (
	"context"
	"testing"
	"time"
)

func TestClientConfigDefaults(t *testing.T) {
	cfg := DefaultClientConfig()
	if cfg.PoolSize != 8 {
		t.Errorf("Expected pool size 8, got %d", cfg.PoolSize)
	}
	if cfg.TimeoutMicroseconds != 3000 {
		t.Errorf("Expected timeout 3000us, got %d", cfg.TimeoutMicroseconds)
	}
	if !cfg.FailOpenOnTimeout {
		t.Errorf("Expected FailOpenOnTimeout true by default")
	}
}

func TestSimulateLSTMAutoencoderInference(t *testing.T) {
	// Normal traffic test
	req := &InferenceRequest{
		RequestID: "benign-1",
		URITokens: TokenSequence{
			TokenIDs: []uint32{15, 20, 25},
		},
		BodyTokens: TokenSequence{
			TokenIDs: []uint32{10, 12},
		},
	}

	res := simulateLSTMAutoencoderInference(req)
	if res.IsAnomaly {
		t.Errorf("Benign request should not be flagged as anomaly")
	}
	if res.AnomalyScore >= res.Threshold {
		t.Errorf("Anomaly score %f should be lower than threshold %f", res.AnomalyScore, res.Threshold)
	}

	// Malicious out-of-vocabulary attack payload test
	maliciousReq := &InferenceRequest{
		RequestID: "attack-1",
		URITokens: TokenSequence{
			TokenIDs: []uint32{1000, 1255, 1040, 1020, 1030, 1050},
		},
		BodyTokens: TokenSequence{
			TokenIDs: []uint32{1000, 1100, 1200},
		},
	}

	malRes := simulateLSTMAutoencoderInference(maliciousReq)
	if !malRes.IsAnomaly {
		t.Errorf("Attack sequence with OOV bytes must be flagged as anomaly")
	}
	if malRes.AnomalyScore < malRes.Threshold {
		t.Errorf("Anomaly score %f must exceed threshold %f", malRes.AnomalyScore, malRes.Threshold)
	}
}
