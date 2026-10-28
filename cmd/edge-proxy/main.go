// @license
// SPDX-License-Identifier: Apache-2.0
//
// Edge Proxy (Data Plane & Ingestion Engine)
// High-concurrency enterprise reverse proxy integrating deep learning anomaly inference
// via gRPC and non-blocking security telemetry via Kafka.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/enterprise-security/deepwaf/internal/inference"
	"github.com/enterprise-security/deepwaf/internal/telemetry"
	"github.com/enterprise-security/deepwaf/internal/tokenizer"
)

// Global Prometheus metrics for telemetry and observability
var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "waf_http_requests_total",
			Help: "Total HTTP requests ingested by Edge Proxy data plane",
		},
		[]string{"action", "method"},
	)
	inferenceLatencyHistogram = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "waf_inference_latency_microseconds",
			Help:    "Inference latency distribution in microseconds",
			Buckets: []float64{200, 500, 1000, 2000, 3000, 5000, 10000, 20000},
		},
	)
	anomalyScoreGauge = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "waf_anomaly_score_distribution",
			Help:    "Deep learning LSTM Autoencoder anomaly score distribution",
			Buckets: []float64{0.1, 0.2, 0.4, 0.5, 0.6, 0.65, 0.7, 0.8, 0.9, 0.95},
		},
	)
	activeConnectionsGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "waf_active_connections",
			Help: "Current active TCP connections to the edge proxy",
		},
	)
)

func init() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(inferenceLatencyHistogram)
	prometheus.MustRegister(anomalyScoreGauge)
	prometheus.MustRegister(activeConnectionsGauge)
}

// Config maps the runtime parameters across data, control, and telemetry planes.
type Config struct {
	ProxyListenAddr     string `yaml:"proxy_listen_addr"`
	ControlListenAddr   string `yaml:"control_listen_addr"`
	UpstreamURL         string `yaml:"upstream_url"`
	MaxBodyBytes        int64  `yaml:"max_body_bytes"`
	InferenceAddr       string `yaml:"inference_addr"`
	InferenceTimeoutUs  int64  `yaml:"inference_timeout_us"`
	InferencePoolSize   int    `yaml:"inference_pool_size"`
	KafkaBrokers        string `yaml:"kafka_brokers"`
	KafkaTopic          string `yaml:"kafka_topic"`
	MaxActiveConns      int64  `yaml:"max_active_conns"`
	ReadHeaderTimeout   time.Duration
	IdleTimeout         time.Duration
}

// EdgeProxy coordinates the three enterprise planes.
type EdgeProxy struct {
	config          Config
	reverseProxy    *httputil.ReverseProxy
	inferencePool   *inference.ClientPool
	telemetryPipe   *telemetry.Pipeline
	tokenizerPipe   *tokenizer.Pipeline
	activeConns     int64
	upstreamTarget  *url.URL
}

func main() {
	cfgFile := flag.String("config", "configs/waf.yaml", "Path to WAF configuration file")
	listenPort := flag.String("port", "8080", "Data plane listening port")
	upstream := flag.String("upstream", "http://127.0.0.1:8000", "Protected upstream backend URL")
	inferenceHost := flag.String("inference", "127.0.0.1:50051", "LSTM Autoencoder gRPC server address")
	kafkaBrokers := flag.String("kafka", "127.0.0.1:9092", "Kafka broker endpoints for Zima MDR")
	flag.Parse()

	log.Printf("[NeuralWAF] Initializing Enterprise Deep Learning Web Application Firewall...")
	log.Printf("[NeuralWAF] Architectural Model: Ingestion Data Plane -> LSTM Autoencoder Inference -> Async Zima MDR Telemetry")

	targetURL, err := url.Parse(*upstream)
	if err != nil {
		log.Fatalf("Fatal: Invalid upstream URL %q: %v", *upstream, err)
	}

	cfg := Config{
		ProxyListenAddr:    ":" + *listenPort,
		ControlListenAddr:  ":9090",
		UpstreamURL:        *upstream,
		MaxBodyBytes:       2 * 1024 * 1024, // 2MB hard ceiling per request to prevent memory starvation
		InferenceAddr:      *inferenceHost,
		InferenceTimeoutUs: 3500, // 3.5ms SLA
		InferencePoolSize:  16,
		KafkaBrokers:       *kafkaBrokers,
		KafkaTopic:         "zima-mdr.security.waf.anomalies",
		MaxActiveConns:     100000,
		ReadHeaderTimeout:  2 * time.Second,
		IdleTimeout:        60 * time.Second,
	}

	// 1. Initialize Inference gRPC Client Pool (Control & Inference plane)
	infConfig := inference.DefaultClientConfig()
	infConfig.TargetAddress = cfg.InferenceAddr
	infConfig.PoolSize = cfg.InferencePoolSize
	infConfig.TimeoutMicroseconds = cfg.InferenceTimeoutUs

	infPool, err := inference.NewClientPool(infConfig)
	if err != nil {
		log.Fatalf("Fatal: Failed to initialize inference gRPC pool: %v", err)
	}
	defer infPool.Close()

	// 2. Initialize Telemetry Pipeline (Async Kafka plane to Zima MDR)
	telConfig := telemetry.DefaultTelemetryConfig()
	telConfig.Brokers = strings.Split(cfg.KafkaBrokers, ",")
	telConfig.Topic = cfg.KafkaTopic

	telPipe, err := telemetry.NewPipeline(telConfig)
	if err != nil {
		log.Fatalf("Fatal: Failed to initialize Kafka telemetry pipeline: %v", err)
	}
	defer telPipe.Close()

	// 3. Initialize Tokenizer Pipeline (Strict memory management / sync.Pool)
	tokPipe := tokenizer.NewPipeline()

	// 4. Construct Edge Proxy with ReverseProxy director
	proxy := &EdgeProxy{
		config:         cfg,
		inferencePool:  infPool,
		telemetryPipe:  telPipe,
		tokenizerPipe:  tokPipe,
		upstreamTarget: targetURL,
	}
	proxy.setupReverseProxy()

	// 5. Start Control Plane (Health checks, dynamic config, Prometheus metrics)
	go proxy.startControlPlane()

	// 6. Start Data Plane Server
	server := &http.Server{
		Addr:              cfg.ProxyListenAddr,
		Handler:           proxy,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    1 << 20, // 1MB
		ConnState: func(conn net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				atomic.AddInt64(&proxy.activeConns, 1)
				activeConnectionsGauge.Inc()
			case http.StateClosed, http.StateHijacked:
				atomic.AddInt64(&proxy.activeConns, -1)
				activeConnectionsGauge.Dec()
			}
		},
	}

	// Graceful shutdown channel
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[NeuralWAF:DataPlane] Edge Proxy listening on %s -> Upstream %s", cfg.ProxyListenAddr, cfg.UpstreamURL)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Data plane fatal error: %v", err)
		}
	}()

	<-shutdownChan
	log.Printf("[NeuralWAF] Shutdown signal received. Initiating graceful drain...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	log.Printf("[NeuralWAF] Edge Proxy successfully terminated.")
}

// setupReverseProxy builds the tuned net/http/httputil.ReverseProxy.
func (p *EdgeProxy) setupReverseProxy() {
	director := func(req *http.Request) {
		req.URL.Scheme = p.upstreamTarget.Scheme
		req.URL.Host = p.upstreamTarget.Host
		req.Host = p.upstreamTarget.Host

		// Set forwarding headers
		clientIP := extractClientIP(req)
		if prior, ok := req.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		req.Header.Set("X-Forwarded-For", clientIP)
		req.Header.Set("X-Forwarded-Proto", req.URL.Scheme)
		req.Header.Set("X-WAF-Engine", "NeuralWAF-LSTM-v2")
	}

	// High throughput HTTP Transport pooling
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10000,
		MaxIdleConnsPerHost:   2000,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxResponseHeaderBytes: 64 * 1024,
	}

	p.reverseProxy = &httputil.ReverseProxy{
		Director:  director,
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[NeuralWAF:UpstreamError] Failed to proxy to upstream: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":   "Upstream gateway error",
				"message": "Protected service is currently unreachable",
			})
		},
	}
}

// ServeHTTP is the core Data Plane entrypoint.
// Memory safety during Layer 7 DDoS: bounded reader, zero regex rules, fast inference timeout.
func (p *EdgeProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Defend against memory bloat: bound the incoming request body
	r.Body = http.MaxBytesReader(w, r.Body, p.config.MaxBodyBytes)

	reqID := uuid.New().String()
	clientIP := extractClientIP(r)

	// 2. Tokenize HTTP stream (Strict zero-allocation memory pooling)
	tokenizedReq, err := p.tokenizerPipe.ExtractAndTokenize(r, reqID, clientIP)
	if err != nil {
		httpRequestsTotal.WithLabelValues("rejected_bad_payload", r.Method).Inc()
		http.Error(w, `{"error":"Malformed HTTP payload"}`, http.StatusBadRequest)
		return
	}

	// 3. Dispatch to Inference Engine (gRPC client with microsecond timeout context)
	startInf := time.Now()
	res, err := p.inferencePool.Predict(r.Context(), tokenizedReq)
	elapsedUs := float64(time.Since(startInf).Microseconds())
	inferenceLatencyHistogram.Observe(elapsedUs)

	if err != nil {
		// Log inference failure (e.g., timeout or circuit breaker)
		log.Printf("[NeuralWAF:InferenceWarning] Request %s: inference degraded: %v", reqID, err)
	}

	// 4. Anomaly Decision Logic (No static regex; strictly DL reconstruction loss)
	if res != nil {
		anomalyScoreGauge.Observe(float64(res.AnomalyScore))

		if res.IsAnomaly {
			// ACTION: Block anomaly and emit non-blocking telemetry to Zima MDR
			httpRequestsTotal.WithLabelValues("blocked", r.Method).Inc()
			p.handleBlockedRequest(w, r, reqID, clientIP, res)
			return
		}
	}

	// 5. Normal traffic: forward through Reverse Proxy to upstream application
	httpRequestsTotal.WithLabelValues("allowed", r.Method).Inc()
	w.Header().Set("X-Request-ID", reqID)
	p.reverseProxy.ServeHTTP(w, r)
}

// handleBlockedRequest writes the 403 Forbidden response and pushes non-blocking telemetry.
func (p *EdgeProxy) handleBlockedRequest(w http.ResponseWriter, r *http.Request, reqID, clientIP string, res *inference.InferenceResponse) {
	// Fast HTTP 403 response to client
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-ID", reqID)
	w.Header().Set("X-WAF-Action", "BLOCKED_BY_DEEP_LEARNING_ANOMALY")
	w.WriteHeader(http.StatusForbidden)

	responsePayload := map[string]any{
		"error":                "Request blocked by Web Application Firewall",
		"reference_id":         reqID,
		"status":               403,
		"reconstruction_error": res.ReconstructionError,
		"anomaly_score":        res.AnomalyScore,
		"timestamp":            time.Now().UTC().Format(time.RFC3339),
	}
	_ = json.NewEncoder(w).Encode(responsePayload)

	// Stream to Telemetry Plane: ENTIRELY NON-BLOCKING
	// Even if Kafka is unresponsive, this call completes in nanoseconds.
	event := &telemetry.BlockedEvent{
		EventID:             reqID,
		Timestamp:           time.Now().UnixNano(),
		ClientIP:            clientIP,
		Method:              r.Method,
		Host:                r.Host,
		URI:                 r.RequestURI,
		Headers:             flattenHeaders(r.Header),
		BlockedPayload:      fmt.Sprintf("Method: %s, URI: %s", r.Method, r.RequestURI),
		AnomalyScore:        res.AnomalyScore,
		ReconstructionError: res.ReconstructionError,
		AnomalyThreshold:    res.Threshold,
		InferenceLatencyUs:  res.InferenceLatencyUs,
		ModelVersion:        res.ModelVersion,
		LossAttributions:    res.TokenLossAttributions,
		ActionTaken:         "BLOCK_HTTP_403",
	}

	p.telemetryPipe.EmitBlockedEvent(event)
}

// startControlPlane serves /metrics, /healthz, and /readyz on a segregated management port.
func (p *EdgeProxy) startControlPlane() {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		calls, timeouts, circuit := p.inferencePool.Stats()
		enqueued, flushed, dropped, writeErrs, depth := p.telemetryPipe.Metrics()

		resp := map[string]any{
			"status": "ready",
			"inference_plane": map[string]any{
				"total_calls":    calls,
				"total_timeouts": timeouts,
				"circuit_open":   circuit,
			},
			"telemetry_plane": map[string]any{
				"enqueued":     enqueued,
				"flushed":      flushed,
				"dropped":      dropped,
				"write_errors": writeErrs,
				"queue_depth":  depth,
			},
			"active_conns": atomic.LoadInt64(&p.activeConns),
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	server := &http.Server{
		Addr:              p.config.ControlListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}

	log.Printf("[NeuralWAF:ControlPlane] Management & Prometheus server listening on %s", p.config.ControlListenAddr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("Control plane error: %v", err)
	}
}

// extractClientIP retrieves the real client IP accounting for cloud load balancers.
func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if net.ParseIP(strings.TrimSpace(xri)) != nil {
			return strings.TrimSpace(xri)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func flattenHeaders(h http.Header) map[string]string {
	flat := make(map[string]string, len(h))
	for k, v := range h {
		flat[k] = strings.Join(v, "; ")
	}
	return flat
}
