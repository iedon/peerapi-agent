package httpserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/iedon/peerapi-agent/config"
	"github.com/iedon/peerapi-agent/logger"
	"github.com/iedon/peerapi-agent/version"
)

// Server manages the HTTP server
type Server struct {
	cfg      *config.Config
	logger   *logger.Logger
	handlers *Handlers
	server   *http.Server
	listener net.Listener
}

// NewServer creates a new HTTP server
func NewServer(cfg *config.Config, log *logger.Logger, handlers *Handlers) *Server {
	return &Server{
		cfg:      cfg,
		logger:   log,
		handlers: handlers,
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	// Create router
	mux := http.NewServeMux()

	// Create auth middleware
	withAuth := AuthMiddleware(s.cfg)

	// Register routes
	mux.HandleFunc("/status", withAuth(s.handlers.StatusHandler))
	mux.HandleFunc("/sync", withAuth(s.handlers.SyncHandler))
	mux.HandleFunc("/info", withAuth(s.handlers.InfoHandler))

	// Apply middleware in reverse order (last applied = first executed)
	var handler http.Handler = mux

	// Apply body limit middleware
	if s.cfg.Server.BodyLimit > 0 {
		handler = BodyLimitMiddleware(int64(s.cfg.Server.BodyLimit))(handler)
	}

	// Apply trusted proxy middleware
	if len(s.cfg.Server.TrustedProxies) > 0 {
		handler = TrustedProxyMiddleware(s.cfg.Server.TrustedProxies)(handler)
	}

	// Apply server header middleware
	handler = ServerHeaderMiddleware(version.SERVER_SIGNATURE)(handler)

	// Apply debug logging middleware
	handler = DebugLoggingMiddleware(s.logger, s.cfg.Server.Debug)(handler)

	// Create listener
	var err error

	if s.cfg.Server.ListenerType == "unix" {
		// Unix socket listener
		s.listener, err = net.Listen("unix", s.cfg.Server.Listen)
		if err != nil {
			return fmt.Errorf("failed to listen on unix socket %s: %w", s.cfg.Server.Listen, err)
		}
		s.logger.Info("HTTP server listening on unix socket: %s", s.cfg.Server.Listen)
	} else {
		// TCP listener
		s.listener, err = net.Listen("tcp", s.cfg.Server.Listen)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", s.cfg.Server.Listen, err)
		}
		s.logger.Info("HTTP server listening on: %s", s.cfg.Server.Listen)
	}

	// Create HTTP server
	s.server = &http.Server{
		Handler:      handler,
		ReadTimeout:  time.Duration(s.cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(s.cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(s.cfg.Server.IdleTimeout) * time.Second,
	}

	// Start server in goroutine
	go func() {
		if err := s.server.Serve(s.listener); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTP server error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully stops the HTTP server
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("Shutting down HTTP server...")

	if s.server != nil {
		if err := s.server.Shutdown(ctx); err != nil {
			s.logger.Warn("HTTP server shutdown error: %v", err)
			return err
		}
	}

	if s.listener != nil {
		s.listener.Close()
	}

	s.logger.Info("HTTP server stopped")
	return nil
}
