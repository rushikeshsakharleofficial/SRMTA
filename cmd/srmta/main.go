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

	"github.com/srmta/srmta/internal/access"
	"github.com/srmta/srmta/internal/bounce"
	"github.com/srmta/srmta/internal/config"
	"github.com/srmta/srmta/internal/delivery"
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

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	logger := logging.NewLogger(cfg.Logging)
	defer logger.Close()
	logger.Info("SRMTA starting", "version", version, "hostname", cfg.Server.Hostname)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	metricsServer := metrics.NewServer(cfg.Metrics)
	metrics.Register()

	dbStore := initStore(cfg, logger)
	if dbStore != nil {
		defer dbStore.Close()
	}

	dnsResolver := dns.NewResolver(cfg.DNS, logger)
	ipPool := ip.NewPool(cfg.IPPool, logger)

	dkimSigner, err := dkim.NewSigner(cfg.DKIM)
	if err != nil {
		logger.Warn("DKIM signer not available — signing disabled", "error", err)
	}

	bounceClassifier := bounce.NewClassifier(cfg.Bounce, dbStore, logger)

	queueManager, err := queue.NewManager(cfg.Queue, dbStore, logger)
	if err != nil {
		logger.Error("Failed to initialize queue manager", "error", err)
		os.Exit(1)
	}

	router := buildRouter(cfg, ipPool)

	deliveryEngine := delivery.NewEngine(delivery.EngineConfig{
		Cfg:          cfg.Delivery,
		Hostname:     cfg.Server.Hostname,
		Queue:        queueManager,
		DNSResolver:  dnsResolver,
		IPPool:       ipPool,
		Router:       router,
		DKIMSigner:   dkimSigner,
		Bouncer:      bounceClassifier,
		DB:           dbStore,
		OutboundPort: cfg.SMTP.OutboundPort,
		Logger:       logger,
	})

	// Load IP and domain access control lists from configured INI files.
	var ipACL *access.AccessList
	if cfg.SMTP.AllowedIPsFile != "" {
		acl, err := access.LoadIPsINI(cfg.SMTP.AllowedIPsFile)
		if err != nil {
			logger.Warn("Failed to load allowed IPs file — IP ACL disabled", "file", cfg.SMTP.AllowedIPsFile, "error", err)
		} else {
			ipACL = acl
			logger.Info("Loaded IP ACL", "file", cfg.SMTP.AllowedIPsFile)
		}
	}
	if cfg.SMTP.AllowedDomainsFile != "" {
		domains, err := access.LoadDomainsINI(cfg.SMTP.AllowedDomainsFile)
		if err != nil {
			logger.Warn("Failed to load allowed domains file", "file", cfg.SMTP.AllowedDomainsFile, "error", err)
		} else {
			cfg.SMTP.AllowedDomains = append(cfg.SMTP.AllowedDomains, domains...)
			logger.Info("Loaded domain ACL", "file", cfg.SMTP.AllowedDomainsFile, "count", len(domains))
		}
	}

	smtpServer := smtp.NewServer(cfg.SMTP, cfg.TLS, queueManager, logger, ipACL)

	svc := subsystems{
		metrics:  metricsServer,
		queue:    queueManager,
		delivery: deliveryEngine,
		ipPool:   ipPool,
		smtp:     smtpServer,
	}
	var wg sync.WaitGroup
	startSubsystems(ctx, &wg, svc, logger, cancel)

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

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-sigChan
		switch sig {
		case syscall.SIGHUP:
			reloadConfig(*configPath, ipPool, logger)
		case syscall.SIGINT, syscall.SIGTERM:
			gracefulShutdown(cfg, smtpServer, cancel, &wg, logger)
		}
	}
}

func initStore(cfg *config.Config, logger *logging.Logger) store.Database {
	dbStore, err := store.NewDatabase(cfg.Database)
	if err != nil {
		logger.Warn("Database not available — event logging disabled", "error", err)
		return nil
	}
	if dbStore != nil {
		logger.Info("Database initialized", "driver", dbStore.Driver())
	}
	return dbStore
}

func buildRouter(cfg *config.Config, ipPool *ip.Pool) *routing.Router {
	routerCfg := routing.RouterConfig{
		FallbackIPs: cfg.Routing.FallbackIPs,
	}
	for _, r := range cfg.Routing.Routes {
		routerCfg.Routes = append(routerCfg.Routes, routing.ProviderRoute{
			Name:           r.Name,
			MXPatterns:     r.MXPatterns,
			DomainPatterns: r.DomainPatterns,
			PrimaryIPs:     r.PrimaryIPs,
			BackupIPs:      r.BackupIPs,
		})
	}
	for _, sr := range cfg.Routing.SenderRoutes {
		routerCfg.SenderRoutes = append(routerCfg.SenderRoutes, routing.SenderRoute{
			Domain:    sr.Domain,
			IPs:       sr.IPs,
			SubnetStr: sr.Subnets,
			BackupIPs: sr.BackupIPs,
		})
	}
	router := routing.NewRouter(routerCfg, nil)

	poolStats := ipPool.Stats()
	poolIPs := make([]string, len(poolStats))
	for i, s := range poolStats {
		poolIPs[i] = s.Address
	}
	router.SetPoolIPs(poolIPs)
	return router
}

// subsystems groups the long-lived service instances started by main.
type subsystems struct {
	metrics  *metrics.Server
	queue    *queue.Manager
	delivery *delivery.Engine
	ipPool   *ip.Pool
	smtp     *smtp.Server
}

func startSubsystems(ctx context.Context, wg *sync.WaitGroup, svc subsystems, logger *logging.Logger, cancel context.CancelFunc) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := svc.metrics.Start(ctx); err != nil {
			logger.Error("Metrics server error", "error", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		svc.queue.Start(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		svc.delivery.Start(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		svc.ipPool.StartHealthMonitor(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := svc.smtp.Start(ctx); err != nil {
			logger.Error("SMTP server error", "error", err)
			cancel()
		}
	}()
}

func reloadConfig(configPath string, ipPool *ip.Pool, logger *logging.Logger) {
	logger.Info("Received SIGHUP, reloading configuration")
	newCfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("Failed to reload config", "error", err)
		return
	}
	ipPool.Reload(newCfg.IPPool)
	logger.Info("Configuration reloaded successfully")
}

func gracefulShutdown(cfg *config.Config, smtpServer *smtp.Server, cancel context.CancelFunc, wg *sync.WaitGroup, logger *logging.Logger) {
	logger.Info("Received shutdown signal, initiating graceful shutdown",
		"grace_period", cfg.Server.ShutdownGrace,
	)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownGrace)
	defer shutdownCancel()

	smtpServer.Stop()
	cancel()

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

	logger.Info("SRMTA stopped")
	os.Exit(0)
}
