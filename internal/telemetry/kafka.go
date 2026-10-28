// @license
// SPDX-License-Identifier: Apache-2.0
//
// Package telemetry provides an asynchronous, non-blocking Kafka streaming pipeline
// utilizing segmentio/kafka-go. It delivers security telemetry, blocked payloads,
// client IPs, and deep learning anomaly scores to Zima MDR without adding latency
// to the Edge Proxy HTTP data plane.
package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/compress"
)

var (
	// ErrTelemetryQueueFull is recorded when the non-blocking ring buffer is saturated.
	ErrTelemetryQueueFull = errors.New("telemetry: internal event ring buffer saturated (dropped)")
)

// TelemetryConfig configures the Kafka writer, batching, and async queue parameters.
type TelemetryConfig struct {
	Brokers             []string      `yaml:"brokers"`
	Topic               string        `yaml:"topic"`
	QueueCapacity       int           `yaml:"queue_capacity"`        // Bounded ring-buffer size
	WorkerCount         int           `yaml:"worker_count"`          // Parallel async consumer routines
	BatchSize           int           `yaml:"batch_size"`            // Messages per Kafka batch
	BatchTimeout        time.Duration `yaml:"batch_timeout"`         // Max delay before flushing partial batch
	MaxPayloadBytes     int           `yaml:"max_payload_bytes"`     // Truncation limit to prevent memory bloat
	CompressionCodec    string        `yaml:"compression_codec"`     // snappy, lz4, gzip, none
	RequiredAcks        int           `yaml:"required_acks"`         // 0=NoAck, 1=Leader, -1=AllISR
	FlushTimeout        time.Duration `yaml:"flush_timeout"`
	MaxRetries          int           `yaml:"max_retries"`
}

// DefaultTelemetryConfig provides tuned production parameters for 100k+ RPS data planes.
func DefaultTelemetryConfig() TelemetryConfig {
	return TelemetryConfig{
		Brokers:          []string{"127.0.0.1:9092"},
		Topic:            "zima-mdr.security.waf.anomalies",
		QueueCapacity:    65536, // Large ring-buffer amortizes burst spikes
		WorkerCount:      4,     // Concurrent Kafka flushers
		BatchSize:        500,   // Batch writes for minimal network overhead
		BatchTimeout:     20 * time.Millisecond,
		MaxPayloadBytes:  4096,  // Truncate payloads to 4KB for telemetry to prevent memory exhaustion
		CompressionCodec: "snappy",
		RequiredAcks:     1,     // Leader ack offers high throughput with adequate durability
		FlushTimeout:     5 * time.Second,
		MaxRetries:       3,
	}
}

// BlockedEvent encapsulates security event metadata destined for Zima MDR.
type BlockedEvent struct {
	EventID             string             `json:"event_id"`
	Timestamp           int64              `json:"timestamp"`
	ClientIP            string             `json:"client_ip"`
	Method              string             `json:"method"`
	Host                string             `json:"host"`
	URI                 string             `json:"uri"`
	Headers             map[string]string  `json:"headers"`
	BlockedPayload      string             `json:"blocked_payload"`
	PayloadTruncated    bool               `json:"payload_truncated"`
	AnomalyScore        float32            `json:"anomaly_score"`
	ReconstructionError float32            `json:"reconstruction_error"`
	AnomalyThreshold    float32            `json:"anomaly_threshold"`
	InferenceLatencyUs  uint64             `json:"inference_latency_us"`
	ModelVersion        string             `json:"model_version"`
	LossAttributions    map[string]float32 `json:"loss_attributions,omitempty"`
	ActionTaken         string             `json:"action_taken"` // e.g. "BLOCK_HTTP_403"
	TLSFingerprint      string             `json:"tls_fingerprint,omitempty"`
}

// Pipeline coordinates non-blocking telemetry ingestion and pooled Kafka writes.
type Pipeline struct {
	config        TelemetryConfig
	writer        *kafka.Writer
	queue         chan *BlockedEvent
	droppedEvents uint64
	enqueuedEvents uint64
	flushedEvents uint64
	writeErrors   uint64
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	isClosed      atomic.Bool
}

// NewPipeline creates and starts an asynchronous Kafka telemetry pipeline.
func NewPipeline(cfg TelemetryConfig) (*Pipeline, error) {
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("telemetry: at least one Kafka broker must be specified")
	}
	if cfg.QueueCapacity <= 0 {
		cfg.QueueCapacity = 10000
	}
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = 2
	}
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = 4096
	}

	// Select compression codec
	var compression kafka.Compression
	switch cfg.CompressionCodec {
	case "lz4":
		compression = compress.Lz4
	case "gzip":
		compression = compress.Gzip
	case "snappy":
		compression = compress.Snappy
	default:
		compression = kafka.Snappy
	}

	// Initialize segmentio/kafka-go Writer with pooled transport
	writer := &kafka.Writer{
		Addr:         kafka.TCP(cfg.Brokers...),
		Topic:        cfg.Topic,
		Balancer:     &kafka.LeastBytes{}, // Dynamic load balancing across partitions
		MaxAttempts:  cfg.MaxRetries,
		BatchSize:    cfg.BatchSize,
		BatchTimeout: cfg.BatchTimeout,
		Compression:  compression,
		RequiredAcks: kafka.RequiredAcks(cfg.RequiredAcks),
		Async:        false, // Workers handle batching and sync delivery loop
		Transport: &kafka.Transport{
			IdleTimeout: 30 * time.Second,
			MetadataTTL: 60 * time.Second,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &Pipeline{
		config: cfg,
		writer: writer,
		queue:  make(chan *BlockedEvent, cfg.QueueCapacity),
		ctx:    ctx,
		cancel: cancel,
	}

	// Start asynchronous worker pool
	for i := 0; i < cfg.WorkerCount; i++ {
		p.wg.Add(1)
		go p.workerRoutine(i)
	}

	return p, nil
}

// EmitBlockedEvent dispatches an event into the asynchronous ring buffer.
// CRITICAL: This function NEVER blocks the main HTTP request thread under any condition.
// If the buffer is full during an extreme L7 DDoS burst, the event is dropped,
// the drop counter is atomically incremented, and the proxy continues unimpeded.
func (p *Pipeline) EmitBlockedEvent(event *BlockedEvent) bool {
	if p.isClosed.Load() || event == nil {
		atomic.AddUint64(&p.droppedEvents, 1)
		return false
	}

	// Sanitize and bound payload memory before queueing
	if len(event.BlockedPayload) > p.config.MaxPayloadBytes {
		event.BlockedPayload = event.BlockedPayload[:p.config.MaxPayloadBytes]
		event.PayloadTruncated = true
	}

	// Strict non-blocking select with default branch
	select {
	case p.queue <- event:
		atomic.AddUint64(&p.enqueuedEvents, 1)
		return true
	default:
		// Ring-buffer saturated: drop immediately, zero wait
		atomic.AddUint64(&p.droppedEvents, 1)
		return false
	}
}

// workerRoutine consumes events from the bounded channel and flushes them to Kafka.
func (p *Pipeline) workerRoutine(workerID int) {
	defer p.wg.Done()

	batch := make([]kafka.Message, 0, p.config.BatchSize)
	ticker := time.NewTicker(p.config.BatchTimeout)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		writeCtx, writeCancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := p.writer.WriteMessages(writeCtx, batch...)
		writeCancel()

		if err != nil {
			atomic.AddUint64(&p.writeErrors, uint64(len(batch)))
		} else {
			atomic.AddUint64(&p.flushedEvents, uint64(len(batch)))
		}
		// Reset batch slice reusing underlying capacity
		batch = batch[:0]
	}

	for {
		select {
		case <-p.ctx.Done():
			// Drain remaining events in channel on shutdown
			for {
				select {
				case ev := <-p.queue:
					if msg, err := p.marshalToKafkaMessage(ev); err == nil {
						batch = append(batch, msg)
						if len(batch) >= p.config.BatchSize {
							flush()
						}
					}
				default:
					flush()
					return
				}
			}

		case ev := <-p.queue:
			if msg, err := p.marshalToKafkaMessage(ev); err == nil {
				batch = append(batch, msg)
				if len(batch) >= p.config.BatchSize {
					flush()
				}
			}

		case <-ticker.C:
			flush()
		}
	}
}

// marshalToKafkaMessage serializes the event to JSON and partitions by ClientIP.
func (p *Pipeline) marshalToKafkaMessage(ev *BlockedEvent) (kafka.Message, error) {
	data, err := json.Marshal(ev)
	if err != nil {
		return kafka.Message{}, err
	}

	return kafka.Message{
		Key:   []byte(ev.ClientIP), // Partition key: ensures IP-based stateful correlation in Zima MDR
		Value: data,
		Time:  time.Unix(0, ev.Timestamp),
		Headers: []kafka.Header{
			{Key: "event_type", Value: []byte("waf_deep_learning_anomaly")},
			{Key: "model_version", Value: []byte(ev.ModelVersion)},
		},
	}, nil
}

// Metrics returns telemetry pipeline counters for Prometheus and health endpoints.
func (p *Pipeline) Metrics() (enqueued, flushed, dropped, writeErrors uint64, queueDepth int) {
	return atomic.LoadUint64(&p.enqueuedEvents),
		atomic.LoadUint64(&p.flushedEvents),
		atomic.LoadUint64(&p.droppedEvents),
		atomic.LoadUint64(&p.writeErrors),
		len(p.queue)
}

// Close initiates graceful shutdown: cancels worker context, drains remaining queue, and closes writer.
func (p *Pipeline) Close() error {
	if !p.isClosed.CompareAndSwap(false, true) {
		return nil
	}

	// Trigger worker drain
	p.cancel()

	// Wait with timeout for workers to drain
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(p.config.FlushTimeout):
	}

	return p.writer.Close()
}
