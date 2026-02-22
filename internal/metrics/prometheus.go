// Package metrics implements Prometheus metrics for SRMTA observability.
package metrics

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/srmta/srmta/internal/config"
)

// ── Prometheus-compatible Metrics ───────────────────────────────────────────
// These are simple counters/gauges/histograms that expose /metrics endpoint.
// In production, use prometheus/client_golang. Below is a lightweight shim
// that implements the interface without external dependencies for compilation.

// Counter tracks a monotonically increasing value.
type Counter struct {
	name  string
	value float64
}

// Inc increments the counter by 1.
func (c *Counter) Inc() { c.value++ }

// Add adds n to the counter.
func (c *Counter) Add(n float64) { c.value += n }

// Gauge tracks a value that can go up and down.
type Gauge struct {
	name  string
	value float64
}

// Set sets the gauge to a value.
func (g *Gauge) Set(v float64) { g.value = v }

// Inc increments the gauge.
func (g *Gauge) Inc() { g.value++ }

// Dec decrements the gauge.
func (g *Gauge) Dec() { g.value-- }

// Histogram tracks the distribution of observed values.
type Histogram struct {
	name    string
	buckets []float64
	count   int64
	sum     float64
}

// Observe records a value in the histogram.
func (h *Histogram) Observe(v float64) {
	h.count++
	h.sum += v
}

// LabeledCounter supports label-based counters.
type LabeledCounter struct {
	name     string
	counters map[string]*Counter
}

// WithLabelValues returns a counter for specific label values.
func (lc *LabeledCounter) WithLabelValues(labels ...string) *Counter {
	key := ""
	for _, l := range labels {
		key += l + ","
	}
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

// LabeledGauge supports label-based gauges.
type LabeledGauge struct {
	name   string
	gauges map[string]*Gauge
}

// WithLabelValues returns a gauge for specific label values.
func (lg *LabeledGauge) WithLabelValues(labels ...string) *Gauge {
	key := ""
	for _, l := range labels {
		key += l + ","
	}
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

// Server serves the /metrics endpoint for Prometheus scraping.
type Server struct {
	cfg    config.MetricsConfig
	server *http.Server
}

// NewServer creates a new metrics HTTP server.
func NewServer(cfg config.MetricsConfig) *Server {
	mux := http.NewServeMux()
	mux.HandleFunc(cfg.Path, metricsHandler)
	mux.HandleFunc("/health", healthHandler)

	return &Server{
		cfg: cfg,
		server: &http.Server{
			Addr:    cfg.ListenAddr,
			Handler: mux,
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

// metricsHandler serves Prometheus-format metrics.
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	// Write all metrics in Prometheus exposition format
	writeMetric(w, "srmta_smtp_connections_total", "counter", ConnectionsTotal.value)
	writeMetric(w, "srmta_smtp_connections_active", "gauge", ConnectionsActive.value)
	writeMetric(w, "srmta_smtp_connections_rejected", "counter", ConnectionsRejected.value)
	writeMetric(w, "srmta_smtp_messages_accepted_total", "counter", MessagesAccepted.value)
	writeMetric(w, "srmta_auth_success_total", "counter", AuthSuccessTotal.value)
	writeMetric(w, "srmta_auth_failure_total", "counter", AuthFailureTotal.value)
	writeMetric(w, "srmta_tls_connections_total", "counter", TLSConnectionsTotal.value)
	writeMetric(w, "srmta_tls_handshake_errors_total", "counter", TLSHandshakeErrors.value)
	writeMetric(w, "srmta_queue_enqueued_total", "counter", QueueEnqueued.value)
	writeMetric(w, "srmta_queue_deferred_total", "counter", QueueDeferred.value)
	writeMetric(w, "srmta_queue_dead_letter_total", "counter", QueueDeadLetter.value)
	writeMetric(w, "srmta_queue_failed_total", "counter", QueueFailed.value)
	writeMetric(w, "srmta_queue_completed_total", "counter", QueueCompleted.value)
	writeMetric(w, "srmta_delivery_success_total", "counter", DeliveredTotal.value)
}

func writeMetric(w http.ResponseWriter, name, metricType string, value float64) {
	fmt.Fprintf(w, "# HELP %s SRMTA metric\n", name)
	fmt.Fprintf(w, "# TYPE %s %s\n", name, metricType)
	fmt.Fprintf(w, "%s %g\n", name, value)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy","service":"srmta"}`))
}
