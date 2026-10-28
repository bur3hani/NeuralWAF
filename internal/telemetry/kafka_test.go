// @license
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"testing"
	"time"
)

func TestTelemetryConfig(t *testing.T) {
	cfg := DefaultTelemetryConfig()
	if cfg.QueueCapacity != 65536 {
		t.Errorf("Expected queue capacity 65536, got %d", cfg.QueueCapacity)
	}
	if cfg.MaxPayloadBytes != 4096 {
		t.Errorf("Expected max payload bytes 4096, got %d", cfg.MaxPayloadBytes)
	}
}

func TestEmitBlockedEventMemoryTruncation(t *testing.T) {
	pipe := &Pipeline{
		config: TelemetryConfig{
			MaxPayloadBytes: 16,
			QueueCapacity:   10,
		},
		queue: make(chan *BlockedEvent, 10),
	}

	largePayload := "0123456789ABCDEFEXTRA_BYTES_THAT_SHOULD_BE_TRUNCATED"
	ev := &BlockedEvent{
		EventID:        "ev-test",
		BlockedPayload: largePayload,
	}

	ok := pipe.EmitBlockedEvent(ev)
	if !ok {
		t.Fatalf("EmitBlockedEvent failed to enqueue")
	}

	queued := <-pipe.queue
	if len(queued.BlockedPayload) > 16 {
		t.Errorf("Payload was not truncated to MaxPayloadBytes, len=%d", len(queued.BlockedPayload))
	}
	if !queued.PayloadTruncated {
		t.Errorf("PayloadTruncated flag should be true")
	}
}

func TestEmitBlockedEventNonBlockingDrop(t *testing.T) {
	// Ring buffer with capacity 1
	pipe := &Pipeline{
		config: TelemetryConfig{
			MaxPayloadBytes: 1024,
			QueueCapacity:   1,
		},
		queue: make(chan *BlockedEvent, 1),
	}

	ev1 := &BlockedEvent{EventID: "1"}
	ev2 := &BlockedEvent{EventID: "2"}

	if !pipe.EmitBlockedEvent(ev1) {
		t.Errorf("First event should enqueue")
	}

	// Channel is full: second event must immediately drop with zero blocking
	start := time.Now()
	dropped := !pipe.EmitBlockedEvent(ev2)
	elapsed := time.Since(start)

	if !dropped {
		t.Errorf("Second event should be dropped due to queue saturation")
	}
	if elapsed > 5*time.Millisecond {
		t.Errorf("EmitBlockedEvent blocked for %v, must be strictly non-blocking", elapsed)
	}

	_, _, droppedCount, _, _ := pipe.Metrics()
	if droppedCount != 1 {
		t.Errorf("Expected dropped count 1, got %d", droppedCount)
	}
}
