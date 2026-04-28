// Package metrics implements Prometheus-compatible metrics for SRMTA observability.
// Uses sync/atomic for thread-safe counter and gauge operations.
package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/srmta/srmta/internal/config"
)

const headerContentType = "Content-Type"

// ── Thread-Safe Prometheus-Compatible Metrics ──────────────────────────────
// All counters and gauges use atomic operations for safe concurrent access.

// Counter tracks a monotonically increasing value (thread-safe).
type Counter struct {
	name  string
	value uint64
}

// Inc increments the counter by 1.
func (c *Counter) Inc() { atomic.AddUint64(&c.value, 1) }

// Add adds n to the counter.
func (c *Counter) Add(n float64) {
	for {
		old := atomic.LoadUint64(&c.value)
		new := old + uint64(n)
		if atomic.CompareAndSwapUint64(&c.value, old, new) {
			return
		}
	}
}

// Value returns the current counter value.
func (c *Counter) Value() float64 { return float64(atomic.LoadUint64(&c.value)) }

// Gauge tracks a value that can go up and down (thread-safe).
type Gauge struct {
	name  string
	value uint64 // stored as bits of float64
}

// Set sets the gauge to a value.
func (g *Gauge) Set(v float64) { atomic.StoreUint64(&g.value, math.Float64bits(v)) }

// Inc increments the gauge by 1.
func (g *Gauge) Inc() {
	for {
		old := atomic.LoadUint64(&g.value)
		new := math.Float64bits(math.Float64frombits(old) + 1)
		if atomic.CompareAndSwapUint64(&g.value, old, new) {
			return
		}
	}
}

// Dec decrements the gauge by 1.
func (g *Gauge) Dec() {
	for {
		old := atomic.LoadUint64(&g.value)
		new := math.Float64bits(math.Float64frombits(old) - 1)
		if atomic.CompareAndSwapUint64(&g.value, old, new) {
			return
		}
	}
}

// Value returns the current gauge value.
func (g *Gauge) Value() float64 { return math.Float64frombits(atomic.LoadUint64(&g.value)) }

// Histogram tracks the distribution of observed values (thread-safe).
type Histogram struct {
	name  string
	count uint64
	sum   uint64 // stored as bits of float64
	mu    sync.Mutex
}

// Observe records a value in the histogram.
func (h *Histogram) Observe(v float64) {
	atomic.AddUint64(&h.count, 1)
	for {
		old := atomic.LoadUint64(&h.sum)
		new := math.Float64bits(math.Float64frombits(old) + v)
		if atomic.CompareAndSwapUint64(&h.sum, old, new) {
			return
		}
	}
}

// Count returns the number of observations.
func (h *Histogram) Count() uint64 { return atomic.LoadUint64(&h.count) }

// Sum returns the sum of observations.
func (h *Histogram) Sum() float64 { return math.Float64frombits(atomic.LoadUint64(&h.sum)) }

// LabeledCounter supports label-based counters (with mutex for map safety).
type LabeledCounter struct {
	name     string
	counters map[string]*Counter
	mu       sync.RWMutex
}

// WithLabelValues returns a counter for specific label values.
func (lc *LabeledCounter) WithLabelValues(labels ...string) *Counter {
	key := ""
	for _, l := range labels {
		key += l + ","
	}
	lc.mu.RLock()
	if lc.counters != nil {
		if c, ok := lc.counters[key]; ok {
			lc.mu.RUnlock()
			return c
		}
	}
	lc.mu.RUnlock()

	lc.mu.Lock()
	defer lc.mu.Unlock()
	if lc.counters == nil {
		lc.counters = make(map[string]*Counter)
	}
	c, ok := lc.counters[key]
	if !ok {
		c = &Counter{name: lc.name}
		lc.counters[key] = c
	}
	return c
}

// LabeledGauge supports label-based gauges (with mutex for map safety).
type LabeledGauge struct {
	name   string
	gauges map[string]*Gauge
	mu     sync.RWMutex
}

// WithLabelValues returns a gauge for specific label values.
func (lg *LabeledGauge) WithLabelValues(labels ...string) *Gauge {
	key := ""
	for _, l := range labels {
		key += l + ","
	}
	lg.mu.RLock()
	if lg.gauges != nil {
		if g, ok := lg.gauges[key]; ok {
			lg.mu.RUnlock()
			return g
		}
	}
	lg.mu.RUnlock()

	lg.mu.Lock()
	defer lg.mu.Unlock()
	if lg.gauges == nil {
		lg.gauges = make(map[string]*Gauge)
	}
	g, ok := lg.gauges[key]
	if !ok {
		g = &Gauge{name: lg.name}
		lg.gauges[key] = g
	}
	return g
}

// ── Global Metrics ──────────────────────────────────────────────────────────

var (
	// SMTP Server Metrics
	ConnectionsTotal    = &Counter{name: "srmta_smtp_connections_total"}
	ConnectionsActive   = &Gauge{name: "srmta_smtp_connections_active"}
	ConnectionsRejected = &Counter{name: "srmta_smtp_connections_rejected"}
	SMTPCommandsTotal   = &LabeledCounter{name: "srmta_smtp_commands_total"}
	MessagesAccepted    = &Counter{name: "srmta_smtp_messages_accepted_total"}
	MessageSizeBytes    = &Histogram{name: "srmta_smtp_message_size_bytes"}
	ProcessingLatency   = &Histogram{name: "srmta_smtp_processing_latency_seconds"}

	// Authentication Metrics
	AuthSuccessTotal = &Counter{name: "srmta_auth_success_total"}
	AuthFailureTotal = &Counter{name: "srmta_auth_failure_total"}

	// TLS Metrics
	TLSConnectionsTotal = &Counter{name: "srmta_tls_connections_total"}
	TLSHandshakeErrors  = &Counter{name: "srmta_tls_handshake_errors_total"}

	// Queue Metrics
	QueueDepth      = &LabeledGauge{name: "srmta_queue_depth"}
	QueueEnqueued   = &Counter{name: "srmta_queue_enqueued_total"}
	QueueDeferred   = &Counter{name: "srmta_queue_deferred_total"}
	QueueDeadLetter = &Counter{name: "srmta_queue_dead_letter_total"}
	QueueFailed     = &Counter{name: "srmta_queue_failed_total"}
	QueueCompleted  = &Counter{name: "srmta_queue_completed_total"}
	QueueProcessing = &Counter{name: "srmta_queue_processing_total"}
	EnqueueErrors   = &Counter{name: "srmta_queue_enqueue_errors_total"}

	// Delivery Metrics
	DeliveredTotal   = &Counter{name: "srmta_delivery_success_total"}
	DeliveryErrors   = &LabeledCounter{name: "srmta_delivery_errors_total"}
	DeliveryDuration = &Histogram{name: "srmta_delivery_duration_seconds"}

	// IP Health Metrics
	IPHealthScore = &LabeledGauge{name: "srmta_ip_health_score"}
	IPDisabled    = &LabeledCounter{name: "srmta_ip_disabled_total"}

	// Bounce Metrics
	BounceTotal = &LabeledCounter{name: "srmta_bounce_total"}
)

// Register initializes all metrics — in production, register with Prometheus registry.
func Register() {
	// Metrics are already initialized as globals.
	// With prometheus/client_golang, this would register with prometheus.DefaultRegisterer.
}

// Server serves the /metrics and /health endpoints for Prometheus scraping.
type Server struct {
	cfg    config.MetricsConfig
	server *http.Server
}

// NewServer creates a new metrics HTTP server.
func NewServer(cfg config.MetricsConfig) *Server {
	mux := http.NewServeMux()
	mux.HandleFunc(cfg.Path, metricsHandler)
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/health/full", fullHealthHandler)

	return &Server{
		cfg: cfg,
		server: &http.Server{
			Addr:         cfg.ListenAddr,
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		},
	}
}

// Start begins serving metrics.
func (s *Server) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.server.Shutdown(shutdownCtx)
	}()

	if err := s.server.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

// metricsHandler serves Prometheus-format metrics (thread-safe reads).
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headerContentType, "text/plain; version=0.0.4")

	// SMTP metrics
	writeMetric(w, "srmta_smtp_connections_total", "counter", ConnectionsTotal.Value())
	writeMetric(w, "srmta_smtp_connections_active", "gauge", ConnectionsActive.Value())
	writeMetric(w, "srmta_smtp_connections_rejected", "counter", ConnectionsRejected.Value())
	writeMetric(w, "srmta_smtp_messages_accepted_total", "counter", MessagesAccepted.Value())

	// Auth metrics
	writeMetric(w, "srmta_auth_success_total", "counter", AuthSuccessTotal.Value())
	writeMetric(w, "srmta_auth_failure_total", "counter", AuthFailureTotal.Value())

	// TLS metrics
	writeMetric(w, "srmta_tls_connections_total", "counter", TLSConnectionsTotal.Value())
	writeMetric(w, "srmta_tls_handshake_errors_total", "counter", TLSHandshakeErrors.Value())

	// Queue metrics
	writeMetric(w, "srmta_queue_enqueued_total", "counter", QueueEnqueued.Value())
	writeMetric(w, "srmta_queue_deferred_total", "counter", QueueDeferred.Value())
	writeMetric(w, "srmta_queue_dead_letter_total", "counter", QueueDeadLetter.Value())
	writeMetric(w, "srmta_queue_failed_total", "counter", QueueFailed.Value())
	writeMetric(w, "srmta_queue_completed_total", "counter", QueueCompleted.Value())
	writeMetric(w, "srmta_queue_processing_total", "counter", QueueProcessing.Value())
	writeMetric(w, "srmta_queue_enqueue_errors_total", "counter", EnqueueErrors.Value())

	// Delivery metrics
	writeMetric(w, "srmta_delivery_success_total", "counter", DeliveredTotal.Value())
	writeHistogram(w, "srmta_delivery_duration_seconds", DeliveryDuration)
	writeHistogram(w, "srmta_smtp_processing_latency_seconds", ProcessingLatency)
	writeHistogram(w, "srmta_smtp_message_size_bytes", MessageSizeBytes)
}

func writeMetric(w http.ResponseWriter, name, metricType string, value float64) {
	fmt.Fprintf(w, "# HELP %s SRMTA metric\n", name)
	fmt.Fprintf(w, "# TYPE %s %s\n", name, metricType)
	fmt.Fprintf(w, "%s %g\n", name, value)
}

func writeHistogram(w http.ResponseWriter, name string, h *Histogram) {
	fmt.Fprintf(w, "# HELP %s SRMTA metric\n", name)
	fmt.Fprintf(w, "# TYPE %s histogram\n", name)
	fmt.Fprintf(w, "%s_count %d\n", name, h.Count())
	fmt.Fprintf(w, "%s_sum %g\n", name, h.Sum())
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headerContentType, "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy","service":"srmta"}`))
}

// fullHealthHandler returns detailed health with subsystem status.
func fullHealthHandler(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":  "healthy",
		"service": "srmta",
		"subsystems": map[string]interface{}{
			"smtp": map[string]interface{}{
				"active_connections": ConnectionsActive.Value(),
				"total_connections":  ConnectionsTotal.Value(),
				"rejected":           ConnectionsRejected.Value(),
			},
			"queue": map[string]interface{}{
				"enqueued":    QueueEnqueued.Value(),
				"completed":   QueueCompleted.Value(),
				"deferred":    QueueDeferred.Value(),
				"failed":      QueueFailed.Value(),
				"dead_letter": QueueDeadLetter.Value(),
			},
			"delivery": map[string]interface{}{
				"delivered":      DeliveredTotal.Value(),
				"avg_latency_ms": avgLatency(DeliveryDuration),
			},
			"auth": map[string]interface{}{
				"successes": AuthSuccessTotal.Value(),
				"failures":  AuthFailureTotal.Value(),
			},
			"tls": map[string]interface{}{
				"connections":      TLSConnectionsTotal.Value(),
				"handshake_errors": TLSHandshakeErrors.Value(),
			},
		},
	}

	w.Header().Set(headerContentType, "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(health)
}

// avgLatency computes average latency from a histogram.
func avgLatency(h *Histogram) float64 {
	count := h.Count()
	if count == 0 {
		return 0
	}
	return (h.Sum() / float64(count)) * 1000 // Convert to milliseconds
}
