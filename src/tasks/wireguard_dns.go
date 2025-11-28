package tasks

import (
	"context"
	"time"

	"github.com/iedon/peerapi-agent/config"
	"github.com/iedon/peerapi-agent/logger"
	"github.com/iedon/peerapi-agent/network"
	"github.com/iedon/peerapi-agent/session"
)

// WireGuardDNSTask updates WireGuard endpoints based on DNS resolution
type WireGuardDNSTask struct {
	cfg        *config.Config
	logger     *logger.Logger
	sessionMgr *session.Manager
}

// NewWireGuardDNSTask creates a new WireGuard DNS update task
func NewWireGuardDNSTask(cfg *config.Config, log *logger.Logger, sessionMgr *session.Manager) *WireGuardDNSTask {
	return &WireGuardDNSTask{
		cfg:        cfg,
		logger:     log,
		sessionMgr: sessionMgr,
	}
}

// Run runs the WireGuard DNS update task
func (t *WireGuardDNSTask) Run(ctx context.Context) {
	// Use configured interval, default to 300 seconds (5 minutes) if not set
	intervalSeconds := 300
	if t.cfg.WireGuard.DNSUpdateInterval > 0 {
		intervalSeconds = t.cfg.WireGuard.DNSUpdateInterval
	}

	t.logger.Info("WireGuard DNS update task running with interval of %d seconds", intervalSeconds)
	interval := time.Duration(intervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.logger.Info("WireGuard DNS update task shutting down...")
			return
		case <-ticker.C:
			t.performUpdate()
		}
	}
}

// performUpdate checks all active WireGuard sessions and updates endpoints if needed
func (t *WireGuardDNSTask) performUpdate() {
	// Get all active WireGuard sessions
	sessions := t.sessionMgr.GetActive()
	wireguardSessions := make([]*session.Session, 0)

	for _, sess := range sessions {
		if sess.Type == "wireguard" && sess.Interface != "" && sess.Credential != "" {
			wireguardSessions = append(wireguardSessions, sess)
		}
	}

	if len(wireguardSessions) == 0 {
		return
	}

	// Check each WireGuard session
	for _, sess := range wireguardSessions {
		t.checkAndUpdateEndpoint(sess)
	}
}

// checkAndUpdateEndpoint checks if a WireGuard session needs endpoint update
func (t *WireGuardDNSTask) checkAndUpdateEndpoint(sess *session.Session) {
	if sess.Endpoint == "" {
		return
	}

	// Get latest handshake information for this interface
	handshakeTime, err := network.GetWireGuardLastHandshake(t.cfg.WireGuard.WGCommandPath, sess.Interface, sess.Credential)
	if err != nil {
		t.logger.Warn("Failed to get handshake info for session %s interface %s: %v",
			sess.UUID, sess.Interface, err)
		return
	}

	// Check if handshake is older than 135 seconds
	currentTime := time.Now().Unix()
	if (currentTime - handshakeTime) > 135 {
		if err := network.UpdateWireGuardEndpoint(t.cfg.WireGuard.WGCommandPath, sess.Interface, sess.Credential, sess.Endpoint); err != nil {
			t.logger.Error("Failed to update endpoint for session %s interface %s: %v",
				sess.UUID, sess.Interface, err)
		}
	}
}
