package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// removeDuplicateEndpoints removes duplicate endpoints from a slice while preserving order
func removeDuplicateEndpoints(endpoints []string) []string {
	if len(endpoints) <= 1 {
		return endpoints
	}

	seen := make(map[string]bool)
	result := make([]string, 0, len(endpoints))

	for _, endpoint := range endpoints {
		if !seen[endpoint] {
			seen[endpoint] = true
			result = append(result, endpoint)
		}
	}
	return result
}

// checkSessionGeoLocation checks if a session's endpoint location is allowed
// Returns true if the session should be torn down
func checkSessionGeoLocation(session *BgpSession) (bool, error) {
	// Skip checking if:
	// - Auto teardown is not enabled
	// - GeoIP database is not initialized
	if !cfg.Metric.AutoTeardown || geoDB == nil {
		return false, nil
	}

	var endpointsToCheck []string

	// Always check the configured session endpoint if available
	if session.Endpoint != "" {
		// Extract just the IP/hostname portion for geo checking
		sessionHost := extractHostFromEndpoint(session.Endpoint)
		if sessionHost != "" {
			endpointsToCheck = append(endpointsToCheck, sessionHost)
		}
	}

	// For WireGuard sessions, also check the actual WireGuard connected endpoint
	if session.Type == "wireguard" && session.Interface != "" && session.Credential != "" {
		wgEndpoint := getWireGuardEndpoint(session.Interface, session.Credential)
		if wgEndpoint != "" && wgEndpoint != "(none)" {
			// WireGuard endpoint is already processed to be host-only
			endpointsToCheck = append(endpointsToCheck, wgEndpoint)
		}
	}

	// If no endpoints to check, don't teardown
	if len(endpointsToCheck) == 0 {
		return false, nil
	}

	// Remove duplicates to avoid redundant checks
	endpointsToCheck = removeDuplicateEndpoints(endpointsToCheck)

	// Check each unique endpoint - if ANY endpoint violates geo rules, teardown the session
	for _, endpoint := range endpointsToCheck {
		if shouldTeardown, err := shouldTeardownForEndpoint(session, endpoint); shouldTeardown {
			return shouldTeardown, err
		}
	}

	return false, nil
}

// getWireGuardEndpoint gets the actual endpoint for a WireGuard interface/peer combination
// Returns only the IP/hostname portion (without port) for geo checking
func getWireGuardEndpoint(interfaceName, publicKey string) string {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Run 'wg show <interface> endpoints'
	cmd := exec.CommandContext(ctx, cfg.WireGuard.WGCommandPath, "show", interfaceName, "endpoints")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[GeoCheck] Failed to get WireGuard endpoints for interface %s: %v", interfaceName, err)
		return ""
	}

	// Parse the output to find the endpoint for our public key
	// Output format: <public_key>\t<endpoint>
	lines := strings.SplitSeq(string(output), "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			continue
		}

		if strings.TrimSpace(parts[0]) == publicKey {
			endpoint := strings.TrimSpace(parts[1])
			// Extract only the IP/hostname portion for geo checking
			if host, _, err := net.SplitHostPort(endpoint); err == nil {
				return host
			}
			// If no port present, return the endpoint as is
			return endpoint
		}
	}

	// If we don't find the public key, return empty
	return ""
}

// shouldTeardownForEndpoint checks if a specific endpoint should cause session teardown
func shouldTeardownForEndpoint(session *BgpSession, endpoint string) (bool, error) {
	// Get country code from the endpoint
	countryCode, err := geoIPCountryCode(geoDB, endpoint)
	if err != nil {
		log.Printf("<%s> Failed to get country code for %s: %v", session.UUID, endpoint, err)
		return false, nil // On error, don't teardown
	}

	// If country code is empty, don't teardown
	if countryCode == "" {
		return false, nil
	}

	// Check whitelist/blacklist based on configuration
	switch strings.ToLower(cfg.Metric.GeoIPCountryMode) {
	case "whitelist":
		return checkWhitelistModeForEndpoint(session, endpoint, countryCode)
	case "blacklist":
		return checkBlacklistModeForEndpoint(session, endpoint, countryCode)
	default:
		// For any other mode, don't teardown
		return false, nil
	}
}

// checkWhitelistModeForEndpoint checks if a country is on the whitelist for a specific endpoint
// Returns true if the session should be torn down
func checkWhitelistModeForEndpoint(session *BgpSession, endpoint, countryCode string) (bool, error) {
	// In whitelist mode, tear down if country is NOT on the whitelist
	for _, allowedCountry := range cfg.Metric.WhitelistGeoCountries {
		if strings.EqualFold(countryCode, allowedCountry) {
			// Country is in whitelist, so don't teardown
			return false, nil
		}
	}

	// Country not found in whitelist - should be torn down
	log.Printf("<%s> Endpoint %s, Country %s is not on the whitelist, session will be torn down",
		session.UUID, endpoint, countryCode)
	return true, fmt.Errorf("country `%s` of your endpoint `%s` is not on the whitelist", countryCode, endpoint)
}

// checkBlacklistModeForEndpoint checks if a country is on the blacklist for a specific endpoint
// Returns true if the session should be torn down
func checkBlacklistModeForEndpoint(session *BgpSession, endpoint, countryCode string) (bool, error) {
	// In blacklist mode, tear down if country IS on the blacklist
	for _, blockedCountry := range cfg.Metric.BlacklistGeoCountries {
		if strings.EqualFold(countryCode, blockedCountry) {
			// Country is in blacklist, so teardown
			log.Printf("<%s> Endpoint %s, Country %s is on the blacklist, session will be torn down",
				session.UUID, endpoint, countryCode)
			return true, fmt.Errorf("country `%s` of your endpoint `%s` is on the blacklist", countryCode, endpoint)
		}
	}

	// Country not found in blacklist - should not be torn down
	return false, nil
}

// geoCheckTask runs periodically to check all active sessions against geo rules
func geoCheckTask(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	// Skip if geoDB is not initialized
	if geoDB == nil {
		log.Println("[GeoCheck] GeoIP database not initialized, geo checking disabled")
		return
	}

	// Use configured interval, default to 15 minutes (900 seconds) if not set
	intervalSeconds := 900
	if cfg.Metric.GeoCheckInterval > 0 {
		intervalSeconds = cfg.Metric.GeoCheckInterval
	}

	log.Printf("[GeoCheck] Running with check interval of %d seconds", intervalSeconds)
	interval := time.Duration(intervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run an initial check on startup
	performGeoCheck()

	for {
		select {
		case <-ctx.Done():
			shutdownStart := time.Now()
			log.Println("[GeoCheck] Shutting down geo check task...")

			// Perform any geo-specific cleanup
			if geoDB != nil {
				log.Println("[GeoCheck] Ensuring GeoIP database is ready for cleanup")
			}

			log.Printf("[GeoCheck] Geo check task shutdown completed in %v", time.Since(shutdownStart))
			return
		case <-ticker.C:
			performGeoCheck()
		}
	}
}

// performGeoCheck checks all active sessions against geo rules
func performGeoCheck() {
	// Get all active sessions
	sessionMutex.RLock()
	sessionsToCheck := make([]BgpSession, 0, len(localSessions))
	for _, session := range localSessions {
		// Only check active sessions
		if session.Status == PEERING_STATUS_ENABLED || session.Status == PEERING_STATUS_PROBLEM {
			sessionsToCheck = append(sessionsToCheck, session)
		}
	}
	sessionMutex.RUnlock()

	if len(sessionsToCheck) == 0 {
		log.Println("[GeoCheck] No active sessions to check")
		return
	}

	// Check each session against geo rules
	for _, session := range sessionsToCheck {
		if shouldTeardown, err := checkSessionGeoLocation(&session); shouldTeardown {
			teardownViolatingSession(&session, err.Error())
		}
	}
}

// teardownViolatingSession tears down a session that violates geo rules
func teardownViolatingSession(session *BgpSession, reason string) {
	log.Printf("[GeoCheck] <%s> Session violates geo rules, tearing down", session.UUID)

	// Report teardown status to PeerAPI
	err := reportNewStatusToCenter(session.UUID, PEERING_STATUS_TEARDOWN, reason)
	if err != nil {
		log.Printf("<%s> Failed to report teardown status: %v", session.UUID, err)
	}
}
