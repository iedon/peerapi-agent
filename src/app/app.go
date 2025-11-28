package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/iedon/peerapi-agent/api"
	"github.com/iedon/peerapi-agent/bird"
	"github.com/iedon/peerapi-agent/config"
	"github.com/iedon/peerapi-agent/httpserver"
	"github.com/iedon/peerapi-agent/logger"
	"github.com/iedon/peerapi-agent/metrics"
	"github.com/iedon/peerapi-agent/network"
	"github.com/iedon/peerapi-agent/session"
	"github.com/iedon/peerapi-agent/tasks"
	"github.com/iedon/peerapi-agent/version"
	"github.com/oschwald/geoip2-golang"
)

// App represents the main application
type App struct {
	cfg *config.Config
	log *logger.Logger

	// Managers
	sessionMgr     *session.Manager
	rttManager     *metrics.RTTManager
	trafficMonitor *network.TrafficMonitor

	// External dependencies
	birdPool  *bird.BirdPool
	apiClient *api.Client

	// HTTP server
	httpServer *httpserver.Server

	// Background tasks
	heartbeatTask    *tasks.HeartbeatTask
	trafficTask      *tasks.TrafficMonitorTask
	rttTask          *tasks.RTTTask
	sessionSyncTask  *tasks.SessionSyncTask
	metricsTask      *tasks.MetricsTask
	filterParamsTask *tasks.FilterParamsUpdaterTask
	wireguardDNSTask *tasks.WireGuardDNSTask
	geoIPTask        *tasks.GeoIPCheckTask
	peerProbeTask    *tasks.PeerProbeTask

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a new application instance
func New(configFile string) (*App, error) {
	// Load configuration
	cfg, err := config.Load(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Validate configuration
	if err := config.Validate(cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Create logger
	loggerCfg := &logger.Config{
		File:           cfg.Logger.File,
		MaxSize:        cfg.Logger.MaxSize,
		MaxBackups:     cfg.Logger.MaxBackups,
		MaxAge:         cfg.Logger.MaxAge,
		Compress:       cfg.Logger.Compress,
		ConsoleLogging: cfg.Logger.ConsoleLogging,
		Level:          logger.ParseLevel(cfg.Logger.Level),
	}
	log, err := logger.New(loggerCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	log.Info("%s v%s starting...", version.SERVER_NAME, version.SERVER_VERSION)
	log.Info("Configuration loaded from: %s", configFile)

	// Create BIRD pool
	birdPool, err := bird.NewBirdPool(
		cfg.Bird.ControlSocket,
		cfg.Bird.PoolSize,
		cfg.Bird.PoolSizeMax,
		cfg.Bird.ConnectionMaxRetries,
		cfg.Bird.ConnectionRetryDelayMs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create BIRD pool: %w", err)
	}
	log.Info("BIRD pool initialized with %d connections", cfg.Bird.PoolSize)

	// Create managers
	sessionMgr := session.NewManager(cfg, log)
	rttManager := metrics.NewRTTManager(cfg, log)
	trafficMonitor := network.NewTrafficMonitor(log)

	// Create API client
	apiClient := api.NewClient(cfg, log)

	// Create HTTP handlers
	handlers := httpserver.NewHandlers(cfg, log)

	// Set up handler callbacks (these will be set after task creation)
	var syncTask *tasks.SessionSyncTask
	handlers.GetStatusData = func() (sessions, metricsData any) {
		// Gather session and metrics data for center server
		return sessionMgr.List(), map[string]any{
			"activeSessions": sessionMgr.Count(),
		}
	}
	handlers.TriggerSync = func() {
		// Manual sync triggered via HTTP API
		log.Debug("Manual sync triggered via HTTP API")
		if syncTask != nil {
			ctx := context.Background()
			syncTask.TriggerSync(ctx)
		}
	}

	// Create HTTP server
	httpServer := httpserver.NewServer(cfg, log, handlers)

	// Load GeoIP database if configured
	var geoDB *geoip2.Reader
	if cfg.Metric.MaxMindGeoLiteCountryMmdbPath != "" {
		var err error
		geoDB, err = geoip2.Open(cfg.Metric.MaxMindGeoLiteCountryMmdbPath)
		if err != nil {
			log.Warn("Failed to load GeoIP database from %s: %v", cfg.Metric.MaxMindGeoLiteCountryMmdbPath, err)
		} else {
			log.Info("GeoIP database loaded successfully from %s", cfg.Metric.MaxMindGeoLiteCountryMmdbPath)
		}
	}

	// Create and initialize background tasks, make it available to be run via app.Run() later
	heartbeatTask := tasks.NewHeartbeatTask(cfg, log, apiClient, birdPool)
	trafficTask := tasks.NewTrafficMonitorTask(log, trafficMonitor)
	rttTask := tasks.NewRTTTask(cfg, log, rttManager, sessionMgr)
	sessionSyncTask := tasks.NewSessionSyncTask(cfg, log, apiClient, sessionMgr)
	metricsTask := tasks.NewMetricsTask(cfg, log, apiClient, sessionMgr, rttManager, trafficMonitor, birdPool)
	filterParamsTask := tasks.NewFilterParamsUpdaterTask(cfg, log, sessionMgr, rttManager, birdPool)
	wireguardDNSTask := tasks.NewWireGuardDNSTask(cfg, log, sessionMgr)
	geoIPTask := tasks.NewGeoIPCheckTask(cfg, log, sessionMgr, apiClient, geoDB)
	peerProbeTask := tasks.NewPeerProbeTask(cfg, log, sessionMgr, apiClient)

	// Link probe task to filter params task so it can get probe status
	filterParamsTask.SetProbeStatusProvider(peerProbeTask)

	// Set the sync task reference for HTTP handlers
	syncTask = sessionSyncTask

	// Create context for lifecycle management
	ctx, cancel := context.WithCancel(context.Background())

	app := &App{
		cfg:              cfg,
		log:              log,
		sessionMgr:       sessionMgr,
		rttManager:       rttManager,
		trafficMonitor:   trafficMonitor,
		birdPool:         birdPool,
		apiClient:        apiClient,
		httpServer:       httpServer,
		heartbeatTask:    heartbeatTask,
		trafficTask:      trafficTask,
		rttTask:          rttTask,
		sessionSyncTask:  sessionSyncTask,
		metricsTask:      metricsTask,
		filterParamsTask: filterParamsTask,
		wireguardDNSTask: wireguardDNSTask,
		geoIPTask:        geoIPTask,
		peerProbeTask:    peerProbeTask,
		ctx:              ctx,
		cancel:           cancel,
	}

	return app, nil
}

// Run starts the application
func (a *App) Run() error {
	a.log.Info("Starting application components...")

	// Start HTTP server
	if err := a.httpServer.Start(); err != nil {
		return fmt.Errorf("failed to start HTTP server: %w", err)
	}

	// Start background tasks
	taskCount := 9
	a.wg.Add(taskCount)

	go func() {
		defer a.wg.Done()
		a.heartbeatTask.Run(a.ctx)
	}()

	go func() {
		defer a.wg.Done()
		a.trafficTask.Run(a.ctx)
	}()

	go func() {
		defer a.wg.Done()
		a.rttTask.Run(a.ctx)
	}()

	go func() {
		defer a.wg.Done()
		a.sessionSyncTask.Run(a.ctx)
	}()

	go func() {
		defer a.wg.Done()
		a.metricsTask.Run(a.ctx)
	}()

	go func() {
		defer a.wg.Done()
		a.filterParamsTask.Run(a.ctx)
	}()

	go func() {
		defer a.wg.Done()
		a.wireguardDNSTask.Run(a.ctx)
	}()

	go func() {
		defer a.wg.Done()
		a.geoIPTask.Run(a.ctx)
	}()

	go func() {
		defer a.wg.Done()
		a.peerProbeTask.Run(a.ctx)
	}()

	a.log.Info("Started %d background tasks:", taskCount)
	a.log.Info("  - Heartbeat task (PeerAPI.HeartbeatInterval: %ds)", a.cfg.PeerAPI.HeartbeatInterval)
	a.log.Info("  - Traffic monitor task (Managed Interval: %ds)", 1)
	a.log.Info("  - RTT measurement task (PeerAPI.MetricInterval: %ds)", max(60, a.cfg.PeerAPI.MetricInterval))
	a.log.Info("  - Session sync task (PeerAPI.SyncInterval: %ds)", a.cfg.PeerAPI.SyncInterval)
	a.log.Info("  - Metrics collection task (PeerAPI.MetricInterval: %ds)", a.cfg.PeerAPI.MetricInterval)
	a.log.Info("  - Filter params updater task (Metric.FilterParamsUpdateInterval: %ds)", a.cfg.Metric.FilterParamsUpdateInterval)
	a.log.Info("  - WireGuard DNS updater task (WireGuard.DNSUpdateInterval: %ds)", a.cfg.WireGuard.DNSUpdateInterval)
	a.log.Info("  - GeoIP check task (Metric.GeoCheckInterval: %ds)", a.cfg.Metric.GeoCheckInterval)
	a.log.Info("  - Peer probe task (PeerProbe.IntervalSeconds: %ds)", a.cfg.PeerProbe.IntervalSeconds)

	// Set up probe server route
	if err := network.EnsureProbeServerIPv6Route(
		a.ctx,
		a.cfg.Bird.IPCommandPath,
		a.cfg.PeerProbe.Enabled,
		a.cfg.PeerAPI.ProbeServerIPv6,
		a.cfg.PeerAPI.ProbeServerIPv6Prefix,
		a.cfg.PeerAPI.ProbeServerIPv6Interface,
	); err != nil {
		a.log.Warn("Failed to install probe server route: %v", err)
	}

	a.log.Info("All components started successfully")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		a.log.Info("Received signal: %v", sig)
	case <-a.ctx.Done():
		a.log.Info("Context cancelled")
	}

	return a.Shutdown()
}

// Shutdown gracefully shuts down the application
func (a *App) Shutdown() error {
	a.log.Info("Initiating graceful shutdown...")
	shutdownStart := time.Now()

	// Cancel context to stop all tasks
	a.cancel()

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Remove probe server route
	if err := network.RemoveProbeServerIPv6Route(
		shutdownCtx,
		a.cfg.Bird.IPCommandPath,
		a.cfg.PeerProbe.Enabled,
		a.cfg.PeerAPI.ProbeServerIPv6,
		a.cfg.PeerAPI.ProbeServerIPv6Prefix,
		a.cfg.PeerAPI.ProbeServerIPv6Interface,
	); err != nil {
		a.log.Warn("Failed to remove probe server route: %v", err)
	}

	// Stop HTTP server
	if err := a.httpServer.Stop(shutdownCtx); err != nil {
		a.log.Warn("HTTP server shutdown error: %v", err)
	}

	// Wait for background tasks to finish
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		a.log.Info("All background tasks stopped")
	case <-shutdownCtx.Done():
		a.log.Warn("Shutdown timeout exceeded, forcing exit")
	}

	// Close BIRD pool
	if a.birdPool != nil {
		a.birdPool.Close()
		a.log.Info("BIRD pool closed")
	}

	shutdownDuration := time.Since(shutdownStart)
	a.log.Info("Graceful shutdown completed in %v", shutdownDuration)

	return nil
}
