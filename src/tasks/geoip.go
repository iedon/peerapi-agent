package tasks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/iedon/peerapi-agent/api"
	"github.com/iedon/peerapi-agent/config"
	"github.com/iedon/peerapi-agent/logger"
	"github.com/iedon/peerapi-agent/network"
	"github.com/iedon/peerapi-agent/session"
	"github.com/oschwald/geoip2-golang"
)

// GeoIPCheckTask periodically checks session endpoints against geo rules
type GeoIPCheckTask struct {
	cfg        *config.Config
	logger     *logger.Logger
	sessionMgr *session.Manager
	apiClient  *api.Client
	geoDB      *geoip2.Reader
}

// NewGeoIPCheckTask creates a new GeoIP check task
func NewGeoIPCheckTask(
	cfg *config.Config,
	log *logger.Logger,
	sessionMgr *session.Manager,
	apiClient *api.Client,
	geoDB *geoip2.Reader,
) *GeoIPCheckTask {
	return &GeoIPCheckTask{
		cfg:        cfg,
		logger:     log,
		sessionMgr: sessionMgr,
		apiClient:  apiClient,
		geoDB:      geoDB,
	}
}

// Run runs the GeoIP check task
func (t *GeoIPCheckTask) Run(ctx context.Context) {
	// Skip if GeoIP database is not initialized
	if t.geoDB == nil {
		t.logger.Info("GeoIP database not initialized, geo checking disabled")
		return
	}

	// Use configured interval, default to 15 minutes (900 seconds) if not set
	intervalSeconds := 900
	if t.cfg.Metric.GeoCheckInterval > 0 {
		intervalSeconds = t.cfg.Metric.GeoCheckInterval
	}

	t.logger.Info("GeoIP check task running with interval of %d seconds", intervalSeconds)
	interval := time.Duration(intervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run an initial check on startup
	t.performGeoCheck(ctx)

	for {
		select {
		case <-ctx.Done():
			shutdownStart := time.Now()
			t.logger.Info("GeoIP check task shutting down...")
			t.logger.Info("GeoIP check task shutdown completed in %v", time.Since(shutdownStart))
			return
		case <-ticker.C:
			t.performGeoCheck(ctx)
		}
	}
}

// performGeoCheck checks all active sessions against geo rules
func (t *GeoIPCheckTask) performGeoCheck(ctx context.Context) {
	// Get all active sessions
	activeSessions := t.sessionMgr.GetActive()
	if len(activeSessions) == 0 {
		t.logger.Debug("No active sessions to check")
		return
	}

	// Check each session against geo rules
	for _, sess := range activeSessions {
		if ctx.Err() != nil {
			return
		}
		if shouldTeardown, err := t.checkSessionGeoLocation(sess); shouldTeardown {
			t.teardownViolatingSession(ctx, sess, err.Error())
		}
	}
}

// checkSessionGeoLocation checks if a session's endpoint location is allowed
// Returns true if the session should be torn down
func (t *GeoIPCheckTask) checkSessionGeoLocation(sess *session.Session) (bool, error) {
	// Skip checking if auto teardown is not enabled
	if !t.cfg.Metric.AutoTeardown {
		return false, nil
	}

	var endpointsToCheck []string

	// Always check the configured session endpoint if available
	if sess.Endpoint != "" {
		sessionHost := network.ExtractHost(sess.Endpoint)
		if sessionHost != "" {
			endpointsToCheck = append(endpointsToCheck, sessionHost)
		}
	}

	// For WireGuard sessions, also check the actual WireGuard connected endpoint
	if sess.Type == "wireguard" && sess.Interface != "" && sess.Credential != "" {
		wgEndpoint, err := t.getWireGuardEndpoint(sess.Interface, sess.Credential)
		if err != nil {
			t.logger.Debug("<%s> Failed to get WireGuard endpoint: %v", sess.UUID, err)
		} else if wgEndpoint != "" && wgEndpoint != "(none)" {
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
		if shouldTeardown, err := t.shouldTeardownForEndpoint(sess, endpoint); shouldTeardown {
			return shouldTeardown, err
		}
	}

	return false, nil
}

// getWireGuardEndpoint gets the actual endpoint for a WireGuard interface/peer combination
// Returns only the IP/hostname portion (without port) for geo checking
func (t *GeoIPCheckTask) getWireGuardEndpoint(interfaceName, publicKey string) (string, error) {
	// Use the network package's WireGuard functions
	endpoint, err := network.GetWireGuardPeerEndpoint(t.cfg.WireGuard.WGCommandPath, interfaceName, publicKey)
	if err != nil {
		return "", err
	}

	// Extract host from endpoint (remove port)
	host := network.ExtractHost(endpoint)
	return host, nil
}

// shouldTeardownForEndpoint checks if a specific endpoint should cause session teardown
func (t *GeoIPCheckTask) shouldTeardownForEndpoint(sess *session.Session, endpoint string) (bool, error) {
	// Get country code from the endpoint
	countryCode, err := network.GeoIPCountryCode(t.geoDB, endpoint)
	if err != nil {
		t.logger.Debug("<%s> Failed to get country code for %s: %v", sess.UUID, endpoint, err)
		return false, nil // On error, don't teardown
	}

	// If country code is empty, don't teardown
	if countryCode == "" {
		return false, nil
	}

	// Check whitelist/blacklist based on configuration
	switch strings.ToLower(t.cfg.Metric.GeoIPCountryMode) {
	case "whitelist":
		return t.checkWhitelistMode(sess, endpoint, countryCode)
	case "blacklist":
		return t.checkBlacklistMode(sess, endpoint, countryCode)
	default:
		// For any other mode, don't teardown
		return false, nil
	}
}

// checkWhitelistMode checks if a country is on the whitelist
// Returns true if the session should be torn down
func (t *GeoIPCheckTask) checkWhitelistMode(sess *session.Session, endpoint, countryCode string) (bool, error) {
	// In whitelist mode, tear down if country is NOT on the whitelist
	for _, allowedCountry := range t.cfg.Metric.WhitelistGeoCountries {
		if strings.EqualFold(countryCode, allowedCountry) {
			// Country is in whitelist, so don't teardown
			return false, nil
		}
	}

	// Country not found in whitelist - should be torn down
	t.logger.Warn("<%s> Endpoint %s, Country %s is not on the whitelist, session will be torn down",
		sess.UUID, endpoint, countryCode)
	return true, fmt.Errorf("country `%s` of your endpoint `%s` is not on the whitelist", countryCode, endpoint)
}

// checkBlacklistMode checks if a country is on the blacklist
// Returns true if the session should be torn down
func (t *GeoIPCheckTask) checkBlacklistMode(sess *session.Session, endpoint, countryCode string) (bool, error) {
	// In blacklist mode, tear down if country IS on the blacklist
	for _, blockedCountry := range t.cfg.Metric.BlacklistGeoCountries {
		if strings.EqualFold(countryCode, blockedCountry) {
			// Country is in blacklist, so teardown
			t.logger.Warn("<%s> Endpoint %s, Country %s is on the blacklist, session will be torn down",
				sess.UUID, endpoint, countryCode)
			return true, fmt.Errorf("country `%s` of your endpoint `%s` is on the blacklist", countryCode, endpoint)
		}
	}

	// Country not found in blacklist - should not be torn down
	return false, nil
}

// teardownViolatingSession tears down a session that violates geo rules
func (t *GeoIPCheckTask) teardownViolatingSession(ctx context.Context, sess *session.Session, reason string) {
	t.logger.Warn("<%s> Session violates geo rules, tearing down", sess.UUID)

	// Report teardown status to PeerAPI
	err := t.apiClient.ReportSessionStatus(ctx, sess.UUID, session.StatusTeardown, reason)
	if err != nil {
		t.logger.Error("<%s> Failed to report teardown status: %v", sess.UUID, err)
	}
}

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
