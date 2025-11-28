package tasks

import (
	"context"
	"time"

	"github.com/iedon/peerapi-agent/config"
	"github.com/iedon/peerapi-agent/logger"
	"github.com/iedon/peerapi-agent/metrics"
	"github.com/iedon/peerapi-agent/session"
)

// RTTTask manages periodic RTT measurements and cache cleanup
type RTTTask struct {
	cfg        *config.Config
	logger     *logger.Logger
	rttManager *metrics.RTTManager
	sessionMgr *session.Manager
}

// NewRTTTask creates a new RTT task
func NewRTTTask(cfg *config.Config, log *logger.Logger, rttMgr *metrics.RTTManager, sessMgr *session.Manager) *RTTTask {
	return &RTTTask{
		cfg:        cfg,
		logger:     log,
		rttManager: rttMgr,
		sessionMgr: sessMgr,
	}
}

// Run runs the RTT measurement task
func (t *RTTTask) Run(ctx context.Context) {
	// Calculate RTT interval (at least 60 seconds)
	rttInterval := time.Duration(t.cfg.PeerAPI.MetricInterval) * time.Second
	rttInterval = max(rttInterval, 60*time.Second)

	ticker := time.NewTicker(rttInterval)
	defer ticker.Stop()

	// Start cache cleanup routine
	cleanupCtx, cleanupCancel := context.WithCancel(ctx)
	defer cleanupCancel()
	go t.runCacheCleanup(cleanupCtx)

	t.logger.Info("Starting RTT measurement task with interval %v", rttInterval)

	// Perform initial RTT measurement
	t.measureRTT(ctx)

	for {
		select {
		case <-ctx.Done():
			t.logger.Info("RTT measurement task shutting down...")
			return
		case <-ticker.C:
			t.measureRTT(ctx)
		}
	}
}

func (t *RTTTask) measureRTT(ctx context.Context) {
	sessions := t.sessionMgr.GetActive()
	t.rttManager.BatchMeasureRTT(ctx, sessions)
}

func (t *RTTTask) runCacheCleanup(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.logger.Debug("RTT cache cleanup shutting down...")
			// Perform one final cleanup
			t.performCacheCleanup()
			return
		case <-ticker.C:
			t.performCacheCleanup()
		}
	}
}

func (t *RTTTask) performCacheCleanup() {
	// Get active session UUIDs
	activeUUIDs := make(map[string]bool)
	for _, s := range t.sessionMgr.List() {
		activeUUIDs[s.UUID] = true
	}

	// Cleanup RTT caches
	t.rttManager.CleanupCache(activeUUIDs)
}
