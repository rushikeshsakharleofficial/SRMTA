// Package delivery implements the delivery engine — the core worker pool
// that takes messages from the active queue and delivers them via SMTP.
package delivery

import (
	"context"
	"strings"
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
	"github.com/srmta/srmta/internal/routing"
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
	router     *routing.Router
	dkimSigner *dkim.Signer
	bouncer    *bounce.Classifier
	db         store.Database
	logger     *logging.Logger
	client     *smtp.Client
	scheduler  *queue.Scheduler
	circuitBrk *CircuitBreakerManager
	pendingMu  sync.Mutex
	pendingIDs map[string]struct{}
}

// EngineConfig bundles all dependencies required to construct an Engine.
type EngineConfig struct {
	Cfg          config.DeliveryConfig
	Hostname     string
	Queue        *queue.Manager
	DNSResolver  *dns.Resolver
	IPPool       *ip.Pool
	Router       *routing.Router
	DKIMSigner   *dkim.Signer
	Bouncer      *bounce.Classifier
	DB           store.Database
	OutboundPort int
	Logger       *logging.Logger
}

// NewEngine creates a new delivery engine.
func NewEngine(ecfg EngineConfig) *Engine {
	return &Engine{
		cfg:        ecfg.Cfg,
		hostname:   ecfg.Hostname,
		queue:      ecfg.Queue,
		dns:        ecfg.DNSResolver,
		ipPool:     ecfg.IPPool,
		router:     ecfg.Router,
		dkimSigner: ecfg.DKIMSigner,
		bouncer:    ecfg.Bouncer,
		db:         ecfg.DB,
		logger:     ecfg.Logger,
		client:     smtp.NewClient(ecfg.Cfg, ecfg.OutboundPort, ecfg.Hostname, ecfg.Logger),
		scheduler:  queue.NewScheduler(ecfg.Cfg.PerDomainConcurrency, 0),
		circuitBrk: NewCircuitBreakerManager(5, 30*time.Second),
		pendingIDs: make(map[string]struct{}),
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
				if !e.markPending(msg.ID) {
					continue
				}
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
	defer e.clearPending(msg.ID)
	defer e.scheduler.Release(msg.Domain)

	start := time.Now()

	data, err := e.prepareMessage(msg)
	if err != nil {
		return // prepareMessage already called queue.Fail / queue.Defer
	}

	mxRecords, err := e.dns.LookupMX(msg.Domain)
	if err != nil {
		e.logger.Error("MX resolution failed", "id", msg.ID, "domain", msg.Domain, "error", err)
		e.handleDeliveryFailure(msg, 0, "DNS resolution failed: "+err.Error())
		return
	}

	selectedIP := e.selectSendingIP(msg)
	if selectedIP == nil {
		e.logger.Error("No healthy IPs available", "id", msg.ID)
		e.queue.Defer(msg, "no healthy IPs available")
		return
	}

	successes, failedRecipients, responseCode, responseText := e.attemptMXDelivery(msg, mxRecords, selectedIP, data, start)
	if len(failedRecipients) == 0 {
		if err := e.queue.Complete(msg); err != nil {
			e.logger.Error("Failed to complete delivered message", "id", msg.ID, "error", err)
		}
		return
	}

	msg.Recipients = failedRecipients
	msg.Domain = extractDomain(failedRecipients[0])
	if successes == 0 {
		e.handleDeliveryFailure(msg, responseCode, responseText)
		return
	}

	e.logger.Warn("Partial delivery, retrying remaining recipients",
		"id", msg.ID,
		"delivered", successes,
		"remaining", len(failedRecipients),
	)
	e.handleDeliveryFailure(msg, responseCode, responseText)
}

// prepareMessage loads the raw message bytes and optionally DKIM-signs them.
// On hard failure it calls queue.Fail and returns a non-nil error.
func (e *Engine) prepareMessage(msg *queue.Message) ([]byte, error) {
	data, err := e.loadMessageData(msg)
	if err != nil {
		e.logger.Error("Failed to load message data", "id", msg.ID, "error", err)
		e.queue.Fail(msg, "failed to load message data: "+err.Error())
		return nil, err
	}

	if e.dkimSigner != nil {
		if signed, err := e.dkimSigner.Sign(data, msg.Sender); err != nil {
			e.logger.Warn("DKIM signing failed", "id", msg.ID, "error", err)
			// Continue without DKIM
		} else {
			data = signed
		}
	}
	return data, nil
}

// selectSendingIP picks the outbound IP for this message.
// Sender-domain binding takes priority; falls back to pool selection.
func (e *Engine) selectSendingIP(msg *queue.Message) *ip.PoolIP {
	if e.router != nil {
		senderDomain := extractDomain(msg.Sender)
		routeResult := e.router.ResolveFullPath(senderDomain, "", msg.Domain)
		if routeResult != nil && len(routeResult.PrimaryIPs) > 0 {
			if bestIP := routeResult.BestIP(); bestIP != "" {
				e.logger.Debug("Sender route applied",
					"id", msg.ID, "route", routeResult.ProviderName, "ip", bestIP)
				return &ip.PoolIP{Address: bestIP}
			}
		}
	}
	return e.ipPool.SelectIP()
}

// attemptMXDelivery tries each MX host (and each recipient) in priority order.
// On first successful delivery it records success and returns (nil, nil) — the
// message is already marked complete. On full failure it returns the last result
// or error so the caller can decide on retry/dead-letter.
func (e *Engine) attemptMXDelivery(
	msg *queue.Message,
	mxRecords []*dns.MXRecord,
	selectedIP *ip.PoolIP,
	data []byte,
	start time.Time,
) (successes int, failedRecipients []string, responseCode int, responseText string) {
	for _, recipient := range msg.Recipients {
		delivered := false
		for _, mx := range mxRecords {
			if !e.circuitBrk.AllowRequest(mx.Host) {
				e.logger.Debug("Circuit breaker open, skipping MX",
					"id", msg.ID, "mx", mx.Host,
					"state", e.circuitBrk.GetState(mx.Host).String())
				continue
			}

			result, err := e.client.Deliver(mx.Host, selectedIP.Address, msg.Sender, recipient, data)
			if err != nil {
				e.circuitBrk.RecordFailure(mx.Host)
				isTimeout := result == nil || result.ResponseCode == 0
				if result != nil {
					responseCode = result.ResponseCode
					responseText = result.ResponseText
					e.ipPool.RecordResult(selectedIP.Address, false, result.ResponseCode, result.TLSUsed, isTimeout)
				} else {
					responseCode = 0
					responseText = err.Error()
					e.ipPool.RecordResult(selectedIP.Address, false, 0, false, true)
				}
				e.logger.Debug("Delivery attempt failed",
					"id", msg.ID, "mx", mx.Host,
					"recipient", logging.MaskEmail(recipient), "error", err)
				continue
			}

			if result.Status != "delivered" {
				e.circuitBrk.RecordFailure(mx.Host)
				responseCode = result.ResponseCode
				responseText = result.ResponseText
				e.ipPool.RecordResult(selectedIP.Address, false, result.ResponseCode, result.TLSUsed, false)
				continue
			}

			e.circuitBrk.RecordSuccess(mx.Host)
			duration := time.Since(start)
			e.logger.Info("Message delivered",
				"id", msg.ID,
				"recipient", logging.MaskEmail(recipient),
				"mx", mx.Host,
				"ip", selectedIP.Address,
				"tls", result.TLSUsed,
				"duration_ms", duration.Milliseconds(),
			)
			e.recordEvent(msg, result, duration)
			e.ipPool.RecordResult(selectedIP.Address, true, result.ResponseCode, result.TLSUsed, false)
			metrics.DeliveredTotal.Inc()
			metrics.DeliveryDuration.Observe(duration.Seconds())
			successes++
			delivered = true
			break
		}

		if !delivered {
			failedRecipients = append(failedRecipients, recipient)
		}
	}

	return successes, failedRecipients, responseCode, responseText
}

// handleDeliveryFailure processes a failed delivery attempt.
func (e *Engine) handleDeliveryFailure(msg *queue.Message, responseCode int, responseText string) {
	if e.bouncer != nil && responseCode > 0 && len(msg.Recipients) > 0 {
		record := e.bouncer.ClassifyAndRecord(msg.ID, msg.Sender, msg.Recipients[0], responseCode, responseText)
		if record != nil && record.Type == bounce.BounceHard {
			if err := e.queue.Fail(msg, "hard bounce: "+responseText); err != nil {
				e.logger.Error("Failed to mark message failed", "id", msg.ID, "error", err)
			}
			metrics.DeliveryErrors.WithLabelValues("fail").Inc()
			return
		}
	}

	retrySchedule := queue.DefaultRetrySchedule()
	decision := queue.EvaluateRetry(retrySchedule, msg.RetryCount, responseCode, responseText)

	switch decision.Action {
	case "retry":
		if err := e.queue.Defer(msg, decision.Reason); err != nil {
			e.logger.Error("Failed to defer message", "id", msg.ID, "error", err)
		}
	case "dead-letter":
		if err := e.queue.DeadLetter(msg, decision.Reason); err != nil {
			e.logger.Error("Failed to dead-letter message", "id", msg.ID, "error", err)
		}
	case "fail":
		if err := e.queue.Fail(msg, decision.Reason); err != nil {
			e.logger.Error("Failed to mark message failed", "id", msg.ID, "error", err)
		}
		if e.bouncer != nil && responseCode == 0 && len(msg.Recipients) > 0 {
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

// extractDomain returns the domain part of an email address.
func extractDomain(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(parts[1])
}

// recordEvent logs a delivery event to the database and transaction log.
func (e *Engine) recordEvent(msg *queue.Message, result *smtp.DeliveryResult, duration time.Duration) {
	now := time.Now()

	// Write to database
	if e.db != nil {
		event := &store.DeliveryEvent{
			Timestamp:         now,
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

	// Write to transaction CSV log
	e.logger.Transaction(&logging.DeliveryEvent{
		Timestamp:         now,
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
	})
}

func (e *Engine) markPending(messageID string) bool {
	e.pendingMu.Lock()
	defer e.pendingMu.Unlock()
	if _, exists := e.pendingIDs[messageID]; exists {
		return false
	}
	e.pendingIDs[messageID] = struct{}{}
	return true
}

func (e *Engine) clearPending(messageID string) {
	e.pendingMu.Lock()
	delete(e.pendingIDs, messageID)
	e.pendingMu.Unlock()
}
