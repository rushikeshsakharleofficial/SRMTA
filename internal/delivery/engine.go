// Package delivery implements the delivery engine — the core worker pool
// that takes messages from the active queue and delivers them via SMTP.
package delivery

import (
	"context"
	"sync"
	"time"

	"github.com/srmta/srmta/internal/bounce"
	"github.com/srmta/srmta/internal/config"
	"github.com/srmta/srmta/internal/dkim"
	"github.com/srmta/srmta/internal/dns"
	"github.com/srmta/srmta/internal/ip"
	"github.com/srmta/srmta/internal/logging"
	"github.com/srmta/srmta/internal/metrics"
	"github.com/srmta/srmta/internal/queue"
	"github.com/srmta/srmta/internal/smtp"
	"github.com/srmta/srmta/internal/store"
)

// Engine is the delivery worker pool that processes the active queue.
type Engine struct {
	cfg        config.DeliveryConfig
	hostname   string
	queue      *queue.Manager
	dns        *dns.Resolver
	ipPool     *ip.Pool
	dkimSigner *dkim.Signer
	bouncer    *bounce.Classifier
	db         store.Database
	logger     *logging.Logger
	client     *smtp.Client
	scheduler  *queue.Scheduler
	circuitBrk *CircuitBreakerManager
}

// NewEngine creates a new delivery engine.
func NewEngine(
	cfg config.DeliveryConfig,
	hostname string,
	q *queue.Manager,
	dnsResolver *dns.Resolver,
	ipPool *ip.Pool,
	dkimSigner *dkim.Signer,
	bouncer *bounce.Classifier,
	db store.Database,
	logger *logging.Logger,
) *Engine {
	return &Engine{
		cfg:        cfg,
		hostname:   hostname,
		queue:      q,
		dns:        dnsResolver,
		ipPool:     ipPool,
		dkimSigner: dkimSigner,
		bouncer:    bouncer,
		db:         db,
		logger:     logger,
		client:     smtp.NewClient(cfg, hostname, logger),
		scheduler:  queue.NewScheduler(cfg.PerDomainConcurrency, 0),
		circuitBrk: NewCircuitBreakerManager(5, 30*time.Second),
	}
}

// Start begins the delivery worker pool.
func (e *Engine) Start(ctx context.Context) {
	e.logger.Info("Delivery engine starting",
		"workers", e.cfg.MaxConcurrent,
		"per_domain_concurrency", e.cfg.PerDomainConcurrency,
	)

	var wg sync.WaitGroup

	// Start delivery workers
	for i := 0; i < e.cfg.MaxConcurrent; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			e.workerLoop(ctx, workerID)
		}(i)
	}

	// Start queue scanner that feeds the scheduler
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.scanLoop(ctx)
	}()

	<-ctx.Done()
	wg.Wait()
	e.client.Close()
	e.logger.Info("Delivery engine stopped")
}

// scanLoop periodically scans the active queue and feeds messages to the scheduler.
func (e *Engine) scanLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			messages, err := e.queue.GetActiveMessages("", 100)
			if err != nil {
				e.logger.Error("Queue scan error", "error", err)
				continue
			}
			for _, msg := range messages {
				e.scheduler.Schedule(msg)
			}
		}
	}
}

// workerLoop is the main delivery worker routine.
func (e *Engine) workerLoop(ctx context.Context, workerID int) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Get next message from scheduler
		msg := e.scheduler.Next()
		if msg == nil {
			time.Sleep(100 * time.Millisecond) // Back off if no messages
			continue
		}

		// Deliver the message
		e.deliver(ctx, workerID, msg)
	}
}

// deliver handles the full delivery pipeline for a single message.
func (e *Engine) deliver(ctx context.Context, workerID int, msg *queue.Message) {
	defer e.scheduler.Release(msg.Domain)

	start := time.Now()

	// Load message data from spool file
	data, err := e.loadMessageData(msg)
	if err != nil {
		e.logger.Error("Failed to load message data", "id", msg.ID, "error", err)
		e.queue.Fail(msg, "failed to load message data: "+err.Error())
		return
	}

	// Sign with DKIM
	if e.dkimSigner != nil {
		signedData, err := e.dkimSigner.Sign(data, msg.Sender)
		if err != nil {
			e.logger.Warn("DKIM signing failed", "id", msg.ID, "error", err)
			// Continue without DKIM if signing fails
		} else {
			data = signedData
		}
	}

	// Resolve MX for recipient domain
	mxRecords, err := e.dns.LookupMX(msg.Domain)
	if err != nil {
		e.logger.Error("MX resolution failed", "id", msg.ID, "domain", msg.Domain, "error", err)
		e.handleDeliveryFailure(msg, 0, "DNS resolution failed: "+err.Error())
		return
	}

	// Select sending IP
	selectedIP := e.ipPool.SelectIP()
	if selectedIP == nil {
		e.logger.Error("No healthy IPs available", "id", msg.ID)
		e.queue.Defer(msg, "no healthy IPs available")
		return
	}

	// Try MX hosts in priority order
	var lastErr error
	var lastResult *smtp.DeliveryResult

	for _, mx := range mxRecords {
		// Check circuit breaker for this MX host
		if !e.circuitBrk.AllowRequest(mx.Host) {
			e.logger.Debug("Circuit breaker open, skipping MX",
				"id", msg.ID, "mx", mx.Host,
				"state", e.circuitBrk.GetState(mx.Host).String())
			continue
		}

		for _, recipient := range msg.Recipients {
			result, err := e.client.Deliver(mx.Host, selectedIP.Address, msg.Sender, recipient, data)
			lastResult = result

			if err != nil {
				lastErr = err
				e.circuitBrk.RecordFailure(mx.Host)
				e.logger.Debug("Delivery attempt failed",
					"id", msg.ID,
					"mx", mx.Host,
					"recipient", recipient,
					"error", err,
				)
				continue
			}

			if result.Status == "delivered" {
				// Success!
				e.circuitBrk.RecordSuccess(mx.Host)
				duration := time.Since(start)
				e.logger.Info("Message delivered",
					"id", msg.ID,
					"recipient", recipient,
					"mx", mx.Host,
					"ip", selectedIP.Address,
					"tls", result.TLSUsed,
					"duration_ms", duration.Milliseconds(),
				)

				// Record delivery event
				e.recordEvent(msg, result, duration)

				// Update IP health
				e.ipPool.RecordResult(selectedIP.Address, true, result.ResponseCode, result.TLSUsed, false)

				metrics.DeliveredTotal.Inc()
				metrics.DeliveryDuration.Observe(duration.Seconds())

				e.queue.Complete(msg)
				return
			}
		}
	}

	// All MX hosts failed
	if lastResult != nil {
		e.ipPool.RecordResult(selectedIP.Address, false, lastResult.ResponseCode, lastResult.TLSUsed, false)
		e.handleDeliveryFailure(msg, lastResult.ResponseCode, lastResult.ResponseText)
	} else if lastErr != nil {
		e.ipPool.RecordResult(selectedIP.Address, false, 0, false, true)
		e.handleDeliveryFailure(msg, 0, lastErr.Error())
	}
}

// handleDeliveryFailure processes a failed delivery attempt.
func (e *Engine) handleDeliveryFailure(msg *queue.Message, responseCode int, responseText string) {
	retrySchedule := queue.DefaultRetrySchedule()
	decision := queue.EvaluateRetry(retrySchedule, msg.RetryCount, responseCode, responseText)

	switch decision.Action {
	case "retry":
		e.queue.Defer(msg, decision.Reason)
	case "dead-letter":
		e.queue.DeadLetter(msg, decision.Reason)
	case "fail":
		e.queue.Fail(msg, decision.Reason)
		// Classify bounce
		if e.bouncer != nil {
			e.bouncer.ClassifyAndRecord(msg.ID, msg.Sender, msg.Recipients[0], responseCode, responseText)
		}
	}

	metrics.DeliveryErrors.WithLabelValues(decision.Action).Inc()
}

// loadMessageData reads the message body from the spool file.
func (e *Engine) loadMessageData(msg *queue.Message) ([]byte, error) {
	if msg.Data != nil {
		return msg.Data, nil
	}
	return store.ReadFile(msg.DataPath)
}

// recordEvent logs a delivery event to PostgreSQL.
func (e *Engine) recordEvent(msg *queue.Message, result *smtp.DeliveryResult, duration time.Duration) {
	if e.db == nil {
		return
	}

	event := &store.DeliveryEvent{
		Timestamp:         time.Now(),
		MessageID:         msg.ID,
		Sender:            msg.Sender,
		Recipient:         result.Recipient,
		RemoteMX:          result.RemoteMX,
		ResponseCode:      result.ResponseCode,
		ResponseText:      result.ResponseText,
		IPUsed:            result.IPUsed,
		TLSStatus:         result.TLSUsed,
		RetryCount:        msg.RetryCount,
		ProcessingLatency: duration.Milliseconds(),
		Status:            result.Status,
	}

	e.db.RecordEvent(event)
}
