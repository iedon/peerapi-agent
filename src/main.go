package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/iedon/peerapi-agent/bird"
	"github.com/oschwald/geoip2-golang"
)

const (
	SERVER_NAME    = "iEdon-PeerAPI-Agent"
	SERVER_VERSION = "1.0.5"
)

var SERVER_SIGNATURE = fmt.Sprintf("%s (%s; %s; %s)", SERVER_NAME+"/"+SERVER_VERSION, runtime.GOOS, runtime.GOARCH, runtime.Version())

var (
	cfg      *config
	birdPool *bird.BirdPool
	geoDB    *geoip2.Reader // Global GeoIP database reader
)

// Global state variables for session management task/metric task/monitoring task
var localSessions = make(map[string]BgpSession)
var localMetrics = make(map[string]SessionMetric)
var localTrafficRate = make(map[string]TrafficRate)

// Dedicated mutexes for different data structures to reduce contention
var sessionMutex sync.RWMutex // Protects localSessions
var metricMutex sync.RWMutex  // Protects localMetrics
var trafficMutex sync.RWMutex // Protects localTrafficRate

// Global map to track RTT measurement information for sessions
var rttTrackers = make(map[string]*RTTTracker) // Key is session.UUID
var rttMutex sync.RWMutex                      // Dedicated mutex for RTT-related operations

func initBirdConnectionPool() error {
	var err error
	birdPool, err = bird.NewBirdPool(cfg.Bird.ControlSocket, cfg.Bird.PoolSize, cfg.Bird.PoolSizeMax)
	if err != nil {
		return fmt.Errorf("failed to initialize bird manager: %v", err)
	}

	return nil
}

func main() {
	configFile := flag.String("c", "config.json", "Path to the JSON configuration file")
	help := flag.Bool("h", false, "Print this message")
	flag.Parse()

	if *help {
		fmt.Fprintln(os.Stderr, "Usage:", os.Args[0], "[-c config_file]")
		flag.PrintDefaults()
		return
	}

	// Create a root context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var err error
	cfg, err = loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v\n", err)
	}

	if cfg.PeerAPI.MetricInterval < 60 {
		log.Fatalf("Invalid configuration: MetricInterval must be at least 60 seconds, got %d", cfg.PeerAPI.MetricInterval)
		return
	}

	// Initialize the custom logger
	initLogger(&cfg.Logger)
	// Close the logger when the application exits
	defer func() {
		if logger != nil {
			logger.Close()
		}
	}()

	if cfg.Metric.MaxMindGeoLiteCountryMmdbPath != "" {
		db, err := geoip2.Open(cfg.Metric.MaxMindGeoLiteCountryMmdbPath)
		if err != nil {
			log.Fatalf("Failed to load MaxMind GeoLiteCountry MMDB: %v\n", err)
		}
		geoDB = db
		// Ensure cleanup of the database
		defer geoDB.Close()
	}

	// Initialize managers
	if err := initBirdConnectionPool(); err != nil {
		log.Fatalf("Failed to initialize bird connection pool: %v\n", err)
	}
	defer birdPool.Close() // Ensure bird pool is closed on exit

	app := fiber.New(fiber.Config{
		AppName:            SERVER_NAME,
		ServerHeader:       SERVER_SIGNATURE,
		EnableIPValidation: true,
		TrustProxyConfig:   fiber.TrustProxyConfig{Proxies: cfg.Server.TrustedProxies},
		ReadTimeout:        time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout:       time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:        time.Duration(cfg.Server.IdleTimeout) * time.Second,
		ReadBufferSize:     cfg.Server.ReadBufferSize,
		WriteBufferSize:    cfg.Server.WriteBufferSize,
		BodyLimit:          cfg.Server.BodyLimit,
	})

	initRouter(app)

	// Create a WaitGroup to track all running background tasks
	var wg sync.WaitGroup

	// Start background tasks with context and waitgroup
	wg.Add(6) // 6 is the number of background tasks
	go heartbeatTask(ctx, &wg)
	go mainSessionTask(ctx, &wg)
	go metricTask(ctx, &wg)
	go bandwidthMonitorTask(ctx, &wg)
	go dn42BGPCommunityTask(ctx, &wg)
	go geoCheckTask(ctx, &wg)

	// Set up signal handling for graceful shutdown
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	// Start the HTTP server in a goroutine
	serverShutdown := make(chan error, 1)
	go func() {
		if err := app.Listen(cfg.Server.Listen); err != nil {
			serverShutdown <- err
		}
	}()

	// Wait for shutdown signal or server error
	select {
	case sig := <-shutdownChan:
		log.Printf("Shutdown signal received: %v", sig)
	case err := <-serverShutdown:
		log.Printf("HTTP server error: %v", err)
	}

	// Initiate graceful shutdown
	log.Println("Initiating graceful shutdown sequence...")

	// Set a timeout for graceful shutdown
	shutdownTimeout := 30 * time.Second
	log.Printf("Using shutdown timeout of %v", shutdownTimeout)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	// First, cancel the context to notify all background tasks
	log.Println("Signaling all background tasks to stop...")
	cancel()

	// Then shut down the HTTP server
	log.Println("Shutting down HTTP server...")
	serverShutdownStart := time.Now()

	if err := app.ShutdownWithContext(shutdownCtx); err != nil {
		log.Printf("Error shutting down HTTP server: %v", err)
	} else {
		log.Printf("HTTP server shut down successfully in %v", time.Since(serverShutdownStart))
	}

	// Wait for all background tasks to complete with timeout
	log.Printf("Waiting for %d background tasks to complete...", 6) // 6 is the number of background tasks
	taskShutdownStart := time.Now()

	waitChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitChan)
	}()

	select {
	case <-waitChan:
		log.Printf("All background tasks completed gracefully in %v", time.Since(taskShutdownStart))
	case <-shutdownCtx.Done():
		log.Printf("Shutdown timeout of %v reached, some tasks may not have completed", shutdownTimeout)
	}

	// Perform final resource cleanup
	cleanupResources()

	log.Println("Server gracefully stopped")
}

// cleanupResources handles the cleanup of all application resources
func cleanupResources() {
	log.Println("Performing final resource cleanup...")

	// Close the GeoIP database if it was opened
	if geoDB != nil {
		log.Println("Closing GeoIP database...")
		geoDB.Close()
	}

	// Close the Bird connection pool
	if birdPool != nil {
		log.Println("Closing Bird connection pool...")
		birdPool.Close()
	}

	// Clear global data structures
	log.Println("Clearing global data structures...")

	sessionMutex.Lock()
	for k := range localSessions {
		delete(localSessions, k)
	}
	sessionMutex.Unlock()

	metricMutex.Lock()
	for k := range localMetrics {
		delete(localMetrics, k)
	}
	metricMutex.Unlock()

	trafficMutex.Lock()
	for k := range localTrafficRate {
		delete(localTrafficRate, k)
	}
	trafficMutex.Unlock()

	rttMutex.Lock()
	for k := range rttTrackers {
		delete(rttTrackers, k)
	}
	rttMutex.Unlock()

	log.Println("Resource cleanup completed")
}
