// Package main implements the peerapi agent functionality
// This file focuses on DN42 BGP Community management based on RTT metrics,
// and updating BIRD filter parameters accordingly

package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"os"
	"path"
	"slices"
	"sync"
	"time"
)

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
// (64511, x) :: latency ∈ [exp(x-1), exp(x)] ms (for x < 10)

// calculateEffectiveRTT calculates an effective RTT value from the metric array
// considering loss penalty and historical measurements
func calculateEffectiveRTT(tracker *RTTTracker) int {
	if len(tracker.Metric) == 0 {
		return tracker.LastRTT
	}

	// Calculate average RTT from successful measurements only
	var validRTTs []int
	for _, rtt := range tracker.Metric {
		if rtt > 0 { // Only include successful pings (positive RTT values)
			validRTTs = append(validRTTs, rtt)
		}
	}

	if len(validRTTs) == 0 {
		return -1 // No successful measurements
	}

	// Calculate average RTT from valid measurements
	var sum int
	for _, rtt := range validRTTs {
		sum += rtt
	}
	avgRTT := float64(sum) / float64(len(validRTTs))

	// Apply loss penalty: increase effective RTT based on packet loss rate
	// Loss penalty formula: effective_RTT = avg_RTT * (1 + loss_rate * penalty_factor)
	// Higher loss rates result in higher effective RTT values
	lossPenaltyFactor := 2.0 // Adjustable penalty factor
	lossRate := tracker.AvgLoss
	effectiveRTT := avgRTT * (1.0 + lossRate*lossPenaltyFactor)

	return int(effectiveRTT)
}

// getLatencyCommunityValue calculates the appropriate latency community value
// based on the RTT in milliseconds
func getLatencyCommunityValue(rtt int) int {
	if rtt == -1 {
		// If ping failed or timed out, default to 0 (no community)
		return 0
	}

	if rtt == 0 {
		// If RTT is 0, it is likely directly connected or nearby network path,
		// which is considered very low latency
		// Treat as community value 1
		return 1
	}

	// For values 1-9, we use the exponential formula
	// latency ∈ [exp(x-1), exp(x)] ms (for x < 10)
	latencyMs := float64(rtt)

	// Handle the special case for value 9 (latency > 2981ms)
	if latencyMs > 2981 {
		return 9
	}

	// For values 1-8, use the logarithmic formula
	// If latency is in [exp(x-1), exp(x)] ms, then community value is x
	// Solving for x: x = ln(latency) + 1
	communityValue := int(math.Log(latencyMs)) + 1

	// Ensure the value is in valid range
	if communityValue < 1 {
		communityValue = 1
	} else if communityValue > 9 {
		communityValue = 9
	}

	return communityValue
}

func composeFilterParams(latencyCommunity, ifBwCommunity, ifSecCommunity, policy, probeFlag int) string {
	return fmt.Sprintf("%d,%d,%d,%d,%d", latencyCommunity, ifBwCommunity, ifSecCommunity, policy, probeFlag)
}

// updateFilterParams updates the filter parameters for all active BGP sessions
func updateFilterParams() {
	log.Println("[FilterParamsUpdater] Updating filter parameters...")

	// Get all active sessions
	sessionMutex.RLock()
	sessions := make([]BgpSession, 0, len(localSessions))
	for _, session := range localSessions {
		if session.Status == PEERING_STATUS_ENABLED || session.Status == PEERING_STATUS_PROBLEM {
			sessions = append(sessions, session)
		}
	}
	sessionMutex.RUnlock()

	if len(sessions) == 0 {
		log.Println("[FilterParamsUpdater] No active sessions to update")
		return
	}

	// Calculate effective RTT values for all sessions using RTTTracker.Metric array
	rttMutex.RLock()
	effectiveRTTValues := make(map[string]int)
	for uuid, tracker := range rttTrackers {
		effectiveRTTValues[uuid] = calculateEffectiveRTT(tracker)
	}
	rttMutex.RUnlock()

	// Update each session's BIRD configuration
	updatedCount := 0
	failedCount := 0

	for _, session := range sessions {
		// Get the effective RTT value for this session from the tracker
		rtt, exists := effectiveRTTValues[session.UUID]
		if !exists {
			// Fallback to current metric if no tracker exists
			metricMutex.RLock()
			if metric, metricExists := localMetrics[session.UUID]; metricExists {
				rtt = metric.RTT.Current
			} else {
				rtt = -1 // Default to -1 if no RTT data exists
			}
			metricMutex.RUnlock()
		}

		// Calculate the latency community value
		latencyCommunityValue := getLatencyCommunityValue(rtt)

		// Log effective RTT value, loss rate, and corresponding community for debugging
		// rttMutex.RLock()
		// if tracker, trackerExists := rttTrackers[session.UUID]; trackerExists {
		// 	log.Printf("[FilterParamsUpdater] Session %s: effective RTT %d ms (loss rate: %.2f%%), mapped to community value %d",
		// 		session.UUID, rtt, tracker.AvgLoss*100, latencyCommunityValue)
		// } else {
		// 	log.Printf("[FilterParamsUpdater] Session %s: RTT %d ms (no tracker), mapped to community value %d",
		// 		session.UUID, rtt, latencyCommunityValue)
		// }
		// rttMutex.RUnlock()

		// Get bandwidth and security community values based on session type
		ifBwCommunity, ifSecCommunity := getCommunityValues(session.Type)

		// Update the BIRD configuration
		if err := updateBirdConfig(&session, latencyCommunityValue, ifBwCommunity, ifSecCommunity); err != nil {
			log.Printf("[FilterParamsUpdater] Failed to update BIRD config for session %s: %v", session.UUID, err)
			failedCount++
		} else {
			updatedCount++
		}
	}

	log.Printf("[FilterParamsUpdater] Updated %d sessions, %d failed", updatedCount, failedCount)

	// Reload BIRD configuration
	reloadBirdConfig()
}

// updateBirdConfig updates the BIRD configuration for a specific session
// with latency community values
func updateBirdConfig(session *BgpSession, latencyCommunity, ifBwCommunity, ifSecCommunity int) error {
	confPath := path.Join(cfg.Bird.BGPPeerConfDir, session.Interface+".conf")
	// log.Printf("[FilterParamsUpdater] Updating BIRD config for session %s (interface: %s) with latency community value %d",
	//	session.UUID, session.Interface, latencyCommunity)

	birdConfMutex.Lock()
	defer birdConfMutex.Unlock()

	// Ensure the template is loaded
	if cfg.Bird.BGPPeerConfTemplate == nil {
		return fmt.Errorf("BIRD peer configuration template is not initialized")
	}

	// Remove existing config file if it exists
	if err := os.Remove(confPath); err != nil && !os.IsNotExist(err) {
		log.Printf("[FilterParamsUpdater] Warning: Failed to remove existing BIRD config at %s: %v", confPath, err)
		// Continue anyway
	}

	// Create output file
	outFile, err := os.Create(confPath)
	if err != nil {
		return fmt.Errorf("failed to create BIRD config file %s: %v", confPath, err)
	}
	defer outFile.Close()

	// Generate base session name
	sessionName := fmt.Sprintf("DN42_%d_%s", session.ASN, session.Interface)

	// Check if MP-BGP or extended nexthop is enabled
	mpBGP := slices.Contains(session.Extensions, "mp-bgp")
	extendedNexthop := slices.Contains(session.Extensions, "extended-nexthop")

	// Generate the configuration based on BGP type
	if mpBGP {
		// For MP-BGP, generate a single protocol that handles both IPv4 and IPv6
		interfaceAddr, err := getNeighborAddress(session)
		if err != nil {
			return err
		}

		filterParamsIPv4 := composeFilterParams(latencyCommunity, ifBwCommunity, ifSecCommunity, session.Policy, probeStatusFlag(session.UUID, probeFamilyIPv4))
		filterParamsIPv6 := composeFilterParams(latencyCommunity, ifBwCommunity, ifSecCommunity, session.Policy, probeStatusFlag(session.UUID, probeFamilyIPv6))

		templateData := BirdTemplateData{
			SessionName:       sessionName,
			InterfaceAddr:     interfaceAddr,
			ASN:               session.ASN,
			IPv4ShouldImport:  true,
			IPv4ShouldExport:  true,
			IPv6ShouldImport:  true,
			IPv6ShouldExport:  true,
			ExtendedNextHopOn: extendedNexthop,
			FilterParamsIPv4:  filterParamsIPv4,
			FilterParamsIPv6:  filterParamsIPv6,
		}

		if err := cfg.Bird.BGPPeerConfTemplate.Execute(outFile, templateData); err != nil {
			return fmt.Errorf("failed to generate MP-BGP config: %v", err)
		}
	} else {
		// For traditional BGP, generate separate protocols for IPv4 and IPv6
		// Generate IPv6 config if IPv6 addresses are available
		if session.IPv6LinkLocal != "" || session.IPv6 != "" {
			filterParamsIPv4 := composeFilterParams(latencyCommunity, ifBwCommunity, ifSecCommunity, session.Policy, probeStatusFlag(session.UUID, probeFamilyIPv4))
			filterParamsIPv6 := composeFilterParams(latencyCommunity, ifBwCommunity, ifSecCommunity, session.Policy, probeStatusFlag(session.UUID, probeFamilyIPv6))
			var interfaceAddr string
			if session.IPv6LinkLocal != "" {
				interfaceAddr = fmt.Sprintf("%s%%'%s'", session.IPv6LinkLocal, session.Interface)
			} else if session.IPv6 != "" {
				interfaceAddr = session.IPv6
			}

			templateData := BirdTemplateData{
				SessionName:       sessionName + "_v6",
				InterfaceAddr:     interfaceAddr,
				ASN:               session.ASN,
				IPv4ShouldImport:  false,
				IPv4ShouldExport:  false,
				IPv6ShouldImport:  true,
				IPv6ShouldExport:  true,
				ExtendedNextHopOn: extendedNexthop,
				FilterParamsIPv4:  filterParamsIPv4,
				FilterParamsIPv6:  filterParamsIPv6,
			}

			if err := cfg.Bird.BGPPeerConfTemplate.Execute(outFile, templateData); err != nil {
				return fmt.Errorf("failed to generate IPv6 BGP config: %v", err)
			}
		}

		// Generate IPv4 config if an IPv4 address is available
		if session.IPv4 != "" {
			filterParamsIPv4 := composeFilterParams(latencyCommunity, ifBwCommunity, ifSecCommunity, session.Policy, probeStatusFlag(session.UUID, probeFamilyIPv4))
			filterParamsIPv6 := composeFilterParams(latencyCommunity, ifBwCommunity, ifSecCommunity, session.Policy, probeStatusFlag(session.UUID, probeFamilyIPv6))
			templateData := BirdTemplateData{
				SessionName:       sessionName + "_v4",
				InterfaceAddr:     session.IPv4,
				ASN:               session.ASN,
				IPv4ShouldImport:  true,
				IPv4ShouldExport:  true,
				IPv6ShouldImport:  false,
				IPv6ShouldExport:  false,
				ExtendedNextHopOn: extendedNexthop,
				FilterParamsIPv4:  filterParamsIPv4,
				FilterParamsIPv6:  filterParamsIPv6,
			}

			if err := cfg.Bird.BGPPeerConfTemplate.Execute(outFile, templateData); err != nil {
				return fmt.Errorf("failed to generate IPv4 BGP config: %v", err)
			}
		}
	}

	// log.Printf("[FilterParamsUpdater] Successfully updated BIRD config for session %s with latency community %d",
	//	session.UUID, latencyCommunity)
	return nil
}

// reloadBirdConfig reloads the BIRD configuration
func reloadBirdConfig() {
	if ok, err := birdPool.Configure(); err != nil {
		log.Printf("[FilterParamsUpdater] Failed to reload BIRD configuration: %v", err)
	} else if !ok {
		log.Printf("[FilterParamsUpdater] BIRD configuration reload failed")
	} else {
		log.Printf("[FilterParamsUpdater] BIRD configuration reloaded successfully")
	}
}

// filterParamsUpdaterTask periodically updates the BGP communities based on RTT metrics
func filterParamsUpdaterTask(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	// Wait 120 seconds before the first run to allow RTT measurements to be collected
	select {
	case <-ctx.Done():
		shutdownStart := time.Now()
		log.Println("[FilterParamsUpdater] Shutting down DN42 BGP Community update task before initial run")
		log.Printf("[FilterParamsUpdater] Task shutdown completed in %v", time.Since(shutdownStart))
		return
	case <-time.After(120 * time.Second):
		// Continue with execution
	}

	// Use configured interval, default to 60 minutes (3600 seconds) if not set
	interval := 3600
	if cfg.Metric.FilterParamsUpdateInterval > 0 {
		interval = cfg.Metric.FilterParamsUpdateInterval
	}

	log.Printf("[FilterParamsUpdater] Running with update interval of %d seconds", interval)
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	// Run an initial update
	updateFilterParams()

	for {
		select {
		case <-ctx.Done():
			shutdownStart := time.Now()
			log.Println("[FilterParamsUpdater] Shutting down DN42 BGP Community update task...")

			// Perform any DN42 BGP Community-specific cleanup
			log.Println("[FilterParamsUpdater] Ensuring Bird filter parameters are in a consistent state")

			log.Printf("[FilterParamsUpdater] Task shutdown completed in %v", time.Since(shutdownStart))
			return
		case <-ticker.C:
			updateFilterParams()
		}
	}
}
