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

	dbStore, redisStore := initStores(cfg, logger)
	if dbStore != nil {
		defer dbStore.Close()
	}
	if redisStore != nil {
		defer redisStore.Close()
	}

	dnsResolver := dns.NewResolver(cfg.DNS, redisStore, logger)
	ipPool := ip.NewPool(cfg.IPPool, logger)

	dkimSigner, err := dkim.NewSigner(cfg.DKIM)
	if err != nil {
		logger.Warn("DKIM signer not available — signing disabled", "error", err)
	}

	bounceClassifier := bounce.NewClassifier(cfg.Bounce, dbStore, logger)

	queueManager, err := queue.NewManager(cfg.Queue, redisStore, dbStore, logger)
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

	smtpServer := smtp.NewServer(cfg.SMTP, cfg.TLS, queueManager, logger)

	var wg sync.WaitGroup
	startSubsystems(ctx, &wg, metricsServer, queueManager, deliveryEngine, ipPool, smtpServer, logger, cancel)

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

func initStores(cfg *config.Config, logger *logging.Logger) (*store.Database, *store.RedisStore) {
	dbStore, err := store.NewDatabase(cfg.Database)
	if err != nil {
		logger.Warn("Database not available — event logging disabled",
			"driver", cfg.Database.Driver, "error", err)
	}
	if dbStore != nil {
		logger.Info("Database initialized", "driver", dbStore.Driver())
	}

	redisStore, err := store.NewRedisStore(cfg.Redis)
	if err != nil {
		logger.Warn("Redis not available — queue state caching disabled", "error", err)
	}

	return dbStore, redisStore
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

func startSubsystems(ctx context.Context, wg *sync.WaitGroup,
	metricsServer *metrics.Server,
	queueManager *queue.Manager,
	deliveryEngine *delivery.Engine,
	ipPool *ip.Pool,
	smtpServer *smtp.Server,
	logger *logging.Logger,
	cancel context.CancelFunc,
) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := metricsServer.Start(ctx); err != nil {
			logger.Error("Metrics server error", "error", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		queueManager.Start(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		deliveryEngine.Start(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		ipPool.StartHealthMonitor(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := smtpServer.Start(ctx); err != nil {
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
