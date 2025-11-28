package tasks

import (
	"context"
	"sync"
	"time"

	"github.com/iedon/peerapi-agent/api"
	"github.com/iedon/peerapi-agent/config"
	"github.com/iedon/peerapi-agent/logger"
	"github.com/iedon/peerapi-agent/session"
)

// PeerProbeTask sends active probes to peer sessions
type PeerProbeTask struct {
	cfg        *config.Config
	logger     *logger.Logger
	sessionMgr *session.Manager
	apiClient  *api.Client

	// Probe summary data (fetched from PeerAPI)
	summaryMu   sync.RWMutex
	summaryData map[string]api.ProbeSummarySnapshot
}

// ProbeFamily represents the IP address family for probing
type ProbeFamily int

const (
	ProbeFamilyIPv4 ProbeFamily = iota
	ProbeFamilyIPv6
	ProbeFamilyAny
)

const defaultProbeSummaryCooldownSeconds = 30

// NewPeerProbeTask creates a new peer probe task
func NewPeerProbeTask(
	cfg *config.Config,
	log *logger.Logger,
	sessionMgr *session.Manager,
	apiClient *api.Client,
) *PeerProbeTask {
	return &PeerProbeTask{
		cfg:         cfg,
		logger:      log,
		sessionMgr:  sessionMgr,
		apiClient:   apiClient,
		summaryData: make(map[string]api.ProbeSummarySnapshot),
	}
}

// Run runs the peer probe task
func (t *PeerProbeTask) Run(ctx context.Context) {
	if !t.cfg.PeerProbe.Enabled {
		t.logger.Debug("Peer probe task disabled via configuration, skipping start")
		return
	}

	// Platform-specific initialization
	if err := t.initialize(); err != nil {
		t.logger.Error("Failed to initialize peer probe task: %v", err)
		return
	}

	interval := time.Duration(t.cfg.PeerProbe.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	t.logger.Info("Peer probe task running with interval of %v", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run immediately on startup
	t.runPeerProbe(ctx)

	for {
		select {
		case <-ctx.Done():
			t.logger.Info("Peer probe task shutting down...")
			return
		case <-ticker.C:
			t.runPeerProbe(ctx)
		}
	}
}

// runPeerProbe executes a single probe run
func (t *PeerProbeTask) runPeerProbe(ctx context.Context) {
	// Get active sessions eligible for probing
	sessions := t.collectProbeCandidateSessions()
	if len(sessions) == 0 {
		t.logger.Debug("No active sessions eligible for probing")
		return
	}

	// Platform-specific probe execution
	t.executeProbes(ctx, sessions)

	// Finalize probe run (fetch summaries)
	t.finalizePeerProbeRun(ctx)
}

// collectProbeCandidateSessions gets all active sessions eligible for probing
func (t *PeerProbeTask) collectProbeCandidateSessions() []*session.Session {
	sessions := t.sessionMgr.GetActive()
	return sessions
}

// finalizePeerProbeRun fetches probe summaries from PeerAPI after probing
func (t *PeerProbeTask) finalizePeerProbeRun(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	count, err := t.refreshProbeSummariesWithCooldown(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		t.logger.Error("Failed to refresh probe summaries: %v", err)
		return
	}

	t.logger.Debug("Refreshed %d probe summaries", count)
}

// refreshProbeSummariesWithCooldown fetches probe summaries with a cooldown delay
func (t *PeerProbeTask) refreshProbeSummariesWithCooldown(ctx context.Context) (int, error) {
	cooldown := t.cfg.PeerProbe.ProbeSummaryCooldownSeconds
	if cooldown <= 0 {
		cooldown = defaultProbeSummaryCooldownSeconds
	}

	timer := time.NewTimer(time.Duration(cooldown) * time.Second)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-timer.C:
	}

	summaries, err := t.fetchProbeSummaries(ctx)
	if err != nil {
		return 0, err
	}

	t.storeProbeSummaries(summaries)
	return len(summaries), nil
}

// fetchProbeSummaries fetches probe summaries from PeerAPI
func (t *PeerProbeTask) fetchProbeSummaries(ctx context.Context) ([]api.ProbeSummarySnapshot, error) {
	return t.apiClient.GetProbeSummaries(ctx)
}

// storeProbeSummaries stores probe summaries in memory
func (t *PeerProbeTask) storeProbeSummaries(summaries []api.ProbeSummarySnapshot) {
	t.summaryMu.Lock()
	defer t.summaryMu.Unlock()

	updated := make(map[string]api.ProbeSummarySnapshot, len(summaries))
	for _, summary := range summaries {
		updated[summary.UUID] = summary
	}
	t.summaryData = updated
}

// GetProbeStatusFlag returns probe status flag for a session
// Returns 1 if probe is problematic, 0 if healthy
func (t *PeerProbeTask) GetProbeStatusFlag(uuid string, family ProbeFamily) int {
	t.summaryMu.RLock()
	snapshot, ok := t.summaryData[uuid]
	t.summaryMu.RUnlock()
	if !ok {
		return 0
	}

	switch family {
	case ProbeFamilyIPv4:
		return evaluateProbeEndpoint(snapshot.IPv4)
	case ProbeFamilyIPv6:
		return evaluateProbeEndpoint(snapshot.IPv6)
	case ProbeFamilyAny:
		if evaluateProbeEndpoint(snapshot.IPv4) == 1 || evaluateProbeEndpoint(snapshot.IPv6) == 1 {
			return 1
		}
	}

	return 0
}

// evaluateProbeEndpoint evaluates a probe endpoint snapshot
// Returns 1 if problematic, 0 if fully healthy
// Logic: ok->0, norouting->1, nat->1, notavailable->0, error->0
func evaluateProbeEndpoint(endpoint api.ProbeEndpointSnapshot) int {
	// If NAT is true, return 1 (problematic)
	if endpoint.NAT != nil && *endpoint.NAT {
		return 1
	}

	// Based on status value
	switch *endpoint.Status {
	case api.ProbeHealthStatusHealthy:
		return 0 // healthy
	case api.ProbeHealthStatusUnhealthy:
		return 1 // problematic, no routing
	case api.ProbeHealthStatusNotAvailable:
		return 0 // not available, treat as non-problematic
	default:
		return 0 // unknown status, treat as non-problematic
	}
}
