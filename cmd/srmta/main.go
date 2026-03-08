// SRMTA — Production-Grade Mail Transfer Agent
// Main entry point: initializes all subsystems, handles signals, and orchestrates graceful shutdown.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/srmta/srmta/internal/bounce"
	"github.com/srmta/srmta/internal/config"
	"github.com/srmta/srmta/internal/delivery"
	"github.com/srmta/srmta/internal/dkim"
	"github.com/srmta/srmta/internal/dns"
	"github.com/srmta/srmta/internal/ip"
	"github.com/srmta/srmta/internal/logging"
	"github.com/srmta/srmta/internal/metrics"
	"github.com/srmta/srmta/internal/queue"
	"github.com/srmta/srmta/internal/smtp"
	"github.com/srmta/srmta/internal/store"
)

var (
	version   = "1.0.0"
	buildTime = "unknown"
)

func main() {
	configPath := flag.String("config", "/etc/srmta/config.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	if *showVersion {
		fmt.Printf("SRMTA v%s (built %s)\n", version, buildTime)
		os.Exit(0)
	}

	// ── Load Configuration ──────────────────────────────────────────────
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// ── Initialize Logger ───────────────────────────────────────────────
	logger := logging.NewLogger(cfg.Logging)
	logger.Info("SRMTA starting", "version", version, "hostname", cfg.Server.Hostname)

	// ── Context with cancellation for graceful shutdown ─────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── Initialize Prometheus Metrics ───────────────────────────────────
	metricsServer := metrics.NewServer(cfg.Metrics)
	metrics.Register()

	// ── Initialize Data Stores ──────────────────────────────────────────
	dbStore, err := store.NewDatabase(cfg.Database)
	if err != nil {
		logger.Warn("Database not available — event logging disabled",
			"driver", cfg.Database.Driver, "error", err)
	}
	if dbStore != nil {
		logger.Info("Database initialized", "driver", dbStore.Driver())
		defer dbStore.Close()
	}

	redisStore, err := store.NewRedisStore(cfg.Redis)
	if err != nil {
		logger.Warn("Redis not available — queue state caching disabled", "error", err)
	}
	if redisStore != nil {
		defer redisStore.Close()
	}

	// ── Initialize DNS Resolver ─────────────────────────────────────────
	dnsResolver := dns.NewResolver(cfg.DNS, redisStore, logger)

	// ── Initialize IP Pool Manager ──────────────────────────────────────
	ipPool := ip.NewPool(cfg.IPPool, logger)

	// ── Initialize DKIM Signer ──────────────────────────────────────────
	dkimSigner, err := dkim.NewSigner(cfg.DKIM)
	if err != nil {
		logger.Warn("DKIM signer not available — signing disabled", "error", err)
	}

	// ── Initialize Bounce Classifier ────────────────────────────────────
	bounceClassifier := bounce.NewClassifier(cfg.Bounce, dbStore, logger)

	// ── Initialize Queue Manager ────────────────────────────────────────
	queueManager, err := queue.NewManager(cfg.Queue, redisStore, dbStore, logger)
	if err != nil {
		logger.Error("Failed to initialize queue manager", "error", err)
		os.Exit(1)
	}

	// ── Initialize Delivery Engine ──────────────────────────────────────
	deliveryEngine := delivery.NewEngine(
		cfg.Delivery,
		cfg.Server.Hostname,
		queueManager,
		dnsResolver,
		ipPool,
		dkimSigner,
		bounceClassifier,
		dbStore,
		logger,
	)

	// ── Initialize SMTP Server ──────────────────────────────────────────
	smtpServer := smtp.NewServer(cfg.SMTP, cfg.TLS, queueManager, logger)

	// ── Start all subsystems ────────────────────────────────────────────
	var wg sync.WaitGroup

	// Start metrics server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := metricsServer.Start(ctx); err != nil {
			logger.Error("Metrics server error", "error", err)
		}
	}()

	// Start queue processor
	wg.Add(1)
	go func() {
		defer wg.Done()
		queueManager.Start(ctx)
	}()

	// Start delivery engine
	wg.Add(1)
	go func() {
		defer wg.Done()
		deliveryEngine.Start(ctx)
	}()

	// Start IP pool health monitor
	wg.Add(1)
	go func() {
		defer wg.Done()
		ipPool.StartHealthMonitor(ctx)
	}()

	// Start SMTP server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := smtpServer.Start(ctx); err != nil {
			logger.Error("SMTP server error", "error", err)
			cancel()
		}
	}()

	smtpAddr := cfg.SMTP.InboundAddr
	if smtpAddr == "" {
		smtpAddr = cfg.SMTP.ListenAddr
	}
	if smtpAddr == "" {
		smtpAddr = ":25"
	}
	logger.Info("SRMTA fully initialized and accepting connections",
		"smtp_addr", smtpAddr,
		"metrics_addr", cfg.Metrics.ListenAddr,
	)

	// ── Signal Handling & Graceful Shutdown ──────────────────────────────
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-sigChan
		switch sig {
		case syscall.SIGHUP:
			logger.Info("Received SIGHUP, reloading configuration")
			newCfg, err := config.Load(*configPath)
			if err != nil {
				logger.Error("Failed to reload config", "error", err)
				continue
			}
			// Hot-reload supported subsystems
			ipPool.Reload(newCfg.IPPool)
			logger.Info("Configuration reloaded successfully")

		case syscall.SIGINT, syscall.SIGTERM:
			logger.Info("Received shutdown signal, initiating graceful shutdown",
				"signal", sig.String(),
				"grace_period", cfg.Server.ShutdownGrace,
			)

			// Create shutdown context with grace period
			shutdownCtx, shutdownCancel := context.WithTimeout(
				context.Background(), cfg.Server.ShutdownGrace,
			)

			// Stop accepting new connections
			smtpServer.Stop()

			// Cancel main context to signal all goroutines
			cancel()

			// Wait for all goroutines or timeout
			done := make(chan struct{})
			go func() {
				wg.Wait()
				close(done)
			}()

			select {
			case <-done:
				logger.Info("Graceful shutdown completed")
			case <-shutdownCtx.Done():
				logger.Warn("Shutdown grace period exceeded, forcing exit")
			}

			shutdownCancel()
			logger.Info("SRMTA stopped")
			os.Exit(0)
		}
	}
}
