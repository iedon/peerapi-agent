package tasks

import (
	"context"
	"fmt"
	"math"
	"os"
	"path"
	"slices"
	"time"

	"github.com/iedon/peerapi-agent/bird"
	"github.com/iedon/peerapi-agent/config"
	"github.com/iedon/peerapi-agent/logger"
	"github.com/iedon/peerapi-agent/metrics"
	"github.com/iedon/peerapi-agent/session"
)

// FilterParamsUpdaterTask updates BIRD filter parameters based on RTT metrics
type FilterParamsUpdaterTask struct {
	cfg        *config.Config
	logger     *logger.Logger
	sessionMgr *session.Manager
	rttManager *metrics.RTTManager
	birdPool   *bird.BirdPool
	probeTask  ProbeStatusProvider // Interface for getting probe status
}

// ProbeStatusProvider provides probe status flags
type ProbeStatusProvider interface {
	GetProbeStatusFlag(sessionUUID string, family ProbeFamily) int
}

// NewFilterParamsUpdaterTask creates a new filter params updater task
func NewFilterParamsUpdaterTask(
	cfg *config.Config,
	log *logger.Logger,
	sessionMgr *session.Manager,
	rttManager *metrics.RTTManager,
	birdPool *bird.BirdPool,
) *FilterParamsUpdaterTask {
	return &FilterParamsUpdaterTask{
		cfg:        cfg,
		logger:     log,
		sessionMgr: sessionMgr,
		rttManager: rttManager,
		birdPool:   birdPool,
	}
}

// SetProbeStatusProvider sets the probe status provider
func (t *FilterParamsUpdaterTask) SetProbeStatusProvider(provider ProbeStatusProvider) {
	t.probeTask = provider
}

// Run runs the filter params updater task
func (t *FilterParamsUpdaterTask) Run(ctx context.Context) {
	// Wait 120 seconds before the first run to allow RTT measurements to be collected
	select {
	case <-ctx.Done():
		t.logger.Info("Filter params updater task shutting down before initial run")
		return
	case <-time.After(120 * time.Second):
		// Continue with execution
	}

	// Use configured interval, default to 3600 seconds (60 minutes) if not set
	interval := 3600
	if t.cfg.Metric.FilterParamsUpdateInterval > 0 {
		interval = t.cfg.Metric.FilterParamsUpdateInterval
	}

	t.logger.Info("Filter params updater running with interval of %d seconds", interval)
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	// Run an initial update
	t.updateFilterParams()

	for {
		select {
		case <-ctx.Done():
			t.logger.Info("Filter params updater task shutting down...")
			return
		case <-ticker.C:
			t.updateFilterParams()
		}
	}
}

// updateFilterParams updates the filter parameters for all active BGP sessions
func (t *FilterParamsUpdaterTask) updateFilterParams() {
	t.logger.Debug("Updating filter parameters...")

	// Get all active sessions
	sessions := t.sessionMgr.GetActive()
	if len(sessions) == 0 {
		t.logger.Debug("No active sessions to update")
		return
	}

	// Update each session's BIRD configuration
	updatedCount := 0
	failedCount := 0

	for _, sess := range sessions {
		// Get the effective RTT value for this session
		rtt, lossRate := t.rttManager.GetRTTValue(sess.UUID)
		effectiveRTT := t.calculateEffectiveRTT(rtt, lossRate)

		// Calculate the latency community value
		latencyCommunityValue := t.getLatencyCommunityValue(effectiveRTT)

		// Get bandwidth and security community values based on session type
		ifBwCommunity, ifSecCommunity := session.GetCommunityValues(sess.Type, t.cfg)

		// Update the BIRD configuration
		if err := t.updateBirdConfig(sess, latencyCommunityValue, ifBwCommunity, ifSecCommunity); err != nil {
			t.logger.Error("Failed to update BIRD config for session %s: %v", sess.UUID, err)
			failedCount++
		} else {
			updatedCount++
		}
	}

	t.logger.Info("Filter updated for %d sessions, %d failed", updatedCount, failedCount)

	// Reload BIRD configuration
	t.reloadBirdConfig()
}

// calculateEffectiveRTT calculates an effective RTT value considering loss penalty
func (t *FilterParamsUpdaterTask) calculateEffectiveRTT(rtt int, lossRate float64) int {
	if rtt <= 0 {
		return -1
	}

	// Apply loss penalty: increase effective RTT based on packet loss rate
	lossPenaltyFactor := 2.0
	effectiveRTT := float64(rtt) * (1.0 + lossRate*lossPenaltyFactor)

	return int(effectiveRTT)
}

// getLatencyCommunityValue calculates the appropriate latency community value
// DN42 latency community values based on latency ranges (in milliseconds):
// (64511, 1) :: latency ∈ (0, 2.7ms]
// (64511, 2) :: latency ∈ (2.7ms, 7.3ms]
// (64511, 3) :: latency ∈ (7.3ms, 20ms]
// (64511, 4) :: latency ∈ (20ms, 55ms]
// (64511, 5) :: latency ∈ (55ms, 148ms]
// (64511, 6) :: latency ∈ (148ms, 403ms]
// (64511, 7) :: latency ∈ (403ms, 1097ms]
// (64511, 8) :: latency ∈ (1097ms, 2981ms]
// (64511, 9) :: latency > 2981ms
func (t *FilterParamsUpdaterTask) getLatencyCommunityValue(rtt int) int {
	if rtt == -1 {
		return 0 // No community if ping failed
	}

	if rtt == 0 {
		return 1 // Very low latency
	}

	latencyMs := float64(rtt)

	// Handle the special case for value 9 (latency > 2981ms)
	if latencyMs > 2981 {
		return 9
	}

	// For values 1-8, use the logarithmic formula
	// If latency is in [exp(x-1), exp(x)] ms, then community value is x
	communityValue := int(math.Log(latencyMs)) + 1

	// Ensure the value is in valid range
	if communityValue < 1 {
		communityValue = 1
	} else if communityValue > 9 {
		communityValue = 9
	}

	return communityValue
}

// updateBirdConfig updates the BIRD configuration for a specific session
func (t *FilterParamsUpdaterTask) updateBirdConfig(sess *session.Session, latencyCommunity, ifBwCommunity, ifSecCommunity int) error {
	confPath := path.Join(t.cfg.Bird.BGPPeerConfDir, sess.Interface+".conf")

	// Ensure the template is loaded
	if t.cfg.Bird.BGPPeerConfTemplate == nil {
		return fmt.Errorf("BIRD peer configuration template is not initialized")
	}

	// Remove existing config file if it exists
	if err := os.Remove(confPath); err != nil && !os.IsNotExist(err) {
		t.logger.Warn("Failed to remove existing BIRD config at %s: %v", confPath, err)
	}

	// Create output file
	outFile, err := os.Create(confPath)
	if err != nil {
		return fmt.Errorf("failed to create BIRD config file %s: %w", confPath, err)
	}
	defer outFile.Close()

	// Generate base session name
	sessionName := fmt.Sprintf("DN42_%d_%s", sess.ASN, sess.Interface)

	// Check if MP-BGP or extended nexthop is enabled
	mpBGP := slices.Contains(sess.Extensions, "mp-bgp")
	extendedNexthop := slices.Contains(sess.Extensions, "extended-nexthop")

	// Get probe status flags
	probeFlagIPv4 := 0
	probeFlagIPv6 := 0
	if t.probeTask != nil {
		probeFlagIPv4 = t.probeTask.GetProbeStatusFlag(sess.UUID, ProbeFamilyIPv4)
		probeFlagIPv6 = t.probeTask.GetProbeStatusFlag(sess.UUID, ProbeFamilyIPv6)
	}

	// Generate the configuration based on BGP type
	if mpBGP {
		// For MP-BGP, generate a single protocol
		interfaceAddr, err := session.GetNeighborAddress(sess)
		if err != nil {
			return err
		}

		filterParamsIPv4 := composeFilterParams(latencyCommunity, ifBwCommunity, ifSecCommunity, sess.Policy, probeFlagIPv4)
		filterParamsIPv6 := composeFilterParams(latencyCommunity, ifBwCommunity, ifSecCommunity, sess.Policy, probeFlagIPv6)

		templateData := session.BirdTemplateData{
			SessionName:       sessionName,
			InterfaceAddr:     interfaceAddr,
			ASN:               sess.ASN,
			IPv4ShouldImport:  true,
			IPv4ShouldExport:  true,
			IPv6ShouldImport:  true,
			IPv6ShouldExport:  true,
			ExtendedNextHopOn: extendedNexthop,
			FilterParamsIPv4:  filterParamsIPv4,
			FilterParamsIPv6:  filterParamsIPv6,
		}

		if err := t.cfg.Bird.BGPPeerConfTemplate.Execute(outFile, templateData); err != nil {
			return fmt.Errorf("failed to generate MP-BGP config: %w", err)
		}
	} else {
		// For traditional BGP, generate separate protocols for IPv4 and IPv6
		if sess.IPv6LinkLocal != "" || sess.IPv6 != "" {
			var interfaceAddr string
			if sess.IPv6LinkLocal != "" {
				interfaceAddr = fmt.Sprintf("%s%%'%s'", sess.IPv6LinkLocal, sess.Interface)
			} else {
				interfaceAddr = sess.IPv6
			}

			filterParamsIPv4 := composeFilterParams(latencyCommunity, ifBwCommunity, ifSecCommunity, sess.Policy, probeFlagIPv4)
			filterParamsIPv6 := composeFilterParams(latencyCommunity, ifBwCommunity, ifSecCommunity, sess.Policy, probeFlagIPv6)

			templateData := session.BirdTemplateData{
				SessionName:       sessionName + "_v6",
				InterfaceAddr:     interfaceAddr,
				ASN:               sess.ASN,
				IPv4ShouldImport:  false,
				IPv4ShouldExport:  false,
				IPv6ShouldImport:  true,
				IPv6ShouldExport:  true,
				ExtendedNextHopOn: extendedNexthop,
				FilterParamsIPv4:  filterParamsIPv4,
				FilterParamsIPv6:  filterParamsIPv6,
			}

			if err := t.cfg.Bird.BGPPeerConfTemplate.Execute(outFile, templateData); err != nil {
				return fmt.Errorf("failed to generate IPv6 BGP config: %w", err)
			}
		}

		if sess.IPv4 != "" {
			filterParamsIPv4 := composeFilterParams(latencyCommunity, ifBwCommunity, ifSecCommunity, sess.Policy, probeFlagIPv4)
			filterParamsIPv6 := composeFilterParams(latencyCommunity, ifBwCommunity, ifSecCommunity, sess.Policy, probeFlagIPv6)

			templateData := session.BirdTemplateData{
				SessionName:       sessionName + "_v4",
				InterfaceAddr:     sess.IPv4,
				ASN:               sess.ASN,
				IPv4ShouldImport:  true,
				IPv4ShouldExport:  true,
				IPv6ShouldImport:  false,
				IPv6ShouldExport:  false,
				ExtendedNextHopOn: extendedNexthop,
				FilterParamsIPv4:  filterParamsIPv4,
				FilterParamsIPv6:  filterParamsIPv6,
			}

			if err := t.cfg.Bird.BGPPeerConfTemplate.Execute(outFile, templateData); err != nil {
				return fmt.Errorf("failed to generate IPv4 BGP config: %w", err)
			}
		}
	}

	return nil
}

// reloadBirdConfig reloads the BIRD configuration
func (t *FilterParamsUpdaterTask) reloadBirdConfig() {
	if ok, err := t.birdPool.Configure(); err != nil {
		t.logger.Error("Failed to reload BIRD configuration: %v", err)
	} else if !ok {
		t.logger.Warn("BIRD configuration reload failed")
	} else {
		t.logger.Debug("BIRD configuration reloaded successfully")
	}
}

// Helper functions

func composeFilterParams(latencyCommunity, ifBwCommunity, ifSecCommunity, policy, probeFlag int) string {
	return fmt.Sprintf("%d,%d,%d,%d,%d", latencyCommunity, ifBwCommunity, ifSecCommunity, policy, probeFlag)
}
