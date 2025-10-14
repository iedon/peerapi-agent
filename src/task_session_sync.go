// Package main implements the peerapi agent functionality
// This file focuses on session management tasks
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	PEERING_STATUS_DELETED = iota
	PEERING_STATUS_DISABLED
	PEERING_STATUS_ENABLED
	PEERING_STATUS_PENDING_APPROVAL
	PEERING_STATUS_QUEUED_FOR_SETUP
	PEERING_STATUS_QUEUED_FOR_DELETE
	PEERING_STATUS_PROBLEM
	PEERING_STATUS_TEARDOWN
)

var (
	// WireGuard public key: base64 encoded
	base64Regex = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)

	// Interface name: alphanumeric, underscore, hyphen, dot (Linux interface naming)
	interfaceNameRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,15}$`)

	// Hostname: RFC 1123 compliant
	hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
)

const (
	// ASN_MAX is the maximum valid ASN value
	ASN_MAX = 4294967295 // Maximum ASN value (32-bit unsigned integer)

	// Allowed MTU range (common network interface MTU values)
	MIN_MTU = 1280
	MAX_MTU = 9999
)

// getBgpSessions fetches BGP session information from the PeerAPI server
func getBgpSessions() ([]BgpSession, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: time.Duration(cfg.PeerAPI.RequestTimeout) * time.Second,
	}

	// Build request URL
	url := fmt.Sprintf("%s/agent/%s/sessions", cfg.PeerAPI.URL, cfg.PeerAPI.RouterUUID)

	// Generate authentication token
	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("[GetBGPSessions] failed to generate token: %v", err)
	}

	// Create request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("[GetBGPSessions] failed to create request: %v", err)
	}

	// Set headers
	setHTTPClientHeader(req, token, false)

	// Send request to PeerAPI
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("[GetBGPSessions] failed to get sessions: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("[GetBGPSessions] failed to get sessions, status code: %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("[GetBGPSessions] failed to read response body: %v", err)
	}

	// Parse response
	var response PeerApiResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("[GetBGPSessions] failed to parse response: %v", err)
	}

	if response.Code != 0 {
		return nil, fmt.Errorf("[GetBGPSessions] got an error response from PeerAPI: %s", response.Message)
	}

	// Parse BGP sessions data
	var data BgpSessionsResponse
	err = json.Unmarshal(response.Data, &data)
	if err != nil {
		return nil, fmt.Errorf("[GetBGPSessions] failed to parse BGP sessions data: %v", err)
	}

	return data.BgpSessions, nil
}

// reportNewStatusToCenter reports a session status change to the PeerAPI server
func reportNewStatusToCenter(sessionUUID string, status int) error {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: time.Duration(cfg.PeerAPI.RequestTimeout) * time.Second,
	}

	// Build request URL
	url := fmt.Sprintf("%s/agent/%s/modify", cfg.PeerAPI.URL, cfg.PeerAPI.RouterUUID)

	// Generate authentication token
	token, err := generateToken()
	if err != nil {
		return fmt.Errorf("<%s> failed to generate token: %v", sessionUUID, err)
	}

	// Prepare request body
	requestBody := map[string]any{
		"status":  status,
		"session": sessionUUID,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("<%s> failed to marshal request body: %v", sessionUUID, err)
	}

	// Create request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("<%s> failed to create request: %v", sessionUUID, err)
	}

	// Set headers
	setHTTPClientHeader(req, token, true)

	// Send request to PeerAPI
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("<%s> failed to notify: %v", sessionUUID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("<%s> failed to notify, status code: %d", sessionUUID, resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("<%s> failed to read response body: %v", sessionUUID, err)
	}

	// Parse response
	var response PeerApiResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("<%s> failed to parse response: %v", sessionUUID, err)
	}

	if response.Code != 0 {
		return fmt.Errorf("<%s> got an error response from PeerAPI: %s", sessionUUID, response.Message)
	}

	return nil
}

// processNewSession handles a newly discovered session
func processNewSession(session *BgpSession, nextLocal map[string]BgpSession) {
	// Validate session inputs if not torndown
	checkAndValidateSession(session)

	switch session.Status {
	case PEERING_STATUS_QUEUED_FOR_SETUP:
		err := configureSession(session)
		if err != nil {
			session.Status = PEERING_STATUS_PROBLEM
			log.Printf("[processNewSession] Failed to configure session %s: %v", session.UUID, err)
		} else {
			session.Status = PEERING_STATUS_ENABLED
			log.Printf("[processNewSession] Session %s is enabled and has been set up", session.UUID)
		}
		err = reportNewStatusToCenter(session.UUID, session.Status)
		if err != nil {
			log.Printf("[processNewSession] Session %s status update failed: %v",
				session.UUID, err)
		}

	case PEERING_STATUS_ENABLED:
		err1 := configureSession(session)
		if err1 != nil {
			session.Status = PEERING_STATUS_PROBLEM
			err2 := reportNewStatusToCenter(session.UUID, session.Status)
			if err2 != nil {
				log.Printf("[processNewSession] Session %s status update failed: %v",
					session.UUID, err2)
			} else {
				log.Printf("[processNewSession] Failed to configure session %s: %v", session.UUID, err1)
			}
		} else {
			log.Printf("[processNewSession] Session %s is enabled and has been set up", session.UUID)
		}

	case PEERING_STATUS_PROBLEM:
		err1 := configureSession(session)
		if err1 == nil {
			session.Status = PEERING_STATUS_ENABLED
			err2 := reportNewStatusToCenter(session.UUID, session.Status)
			if err2 != nil {
				log.Printf("[processNewSession] Session %s status update failed: %v",
					session.UUID, err2)
			} else {
				log.Printf("[processNewSession] Session %s changed from PROBLEM to ENABLED and has been set up", session.UUID)
			}
		} else {
			log.Printf("[processNewSession] Failed to configure session %s: %v", session.UUID, err1)
		}

	case PEERING_STATUS_QUEUED_FOR_DELETE:
		err := reportNewStatusToCenter(session.UUID, PEERING_STATUS_DELETED)
		if err == nil {
			session.Status = PEERING_STATUS_DELETED
			log.Printf("[processNewSession] Session %s is not locally synced but queued for deletion in PeerAPI DB, notifying and skipping", session.UUID)
		}

	default:
		log.Printf("[processNewSession] Skipping and adding session %s with status %d", session.UUID, session.Status)
	}

	nextLocal[session.UUID] = *session
}

// processChangedSession handles a session that has changed configuration
func processChangedSession(newSession *BgpSession, oldSession *BgpSession, nextLocal map[string]BgpSession) {
	if reflect.DeepEqual(*newSession, *oldSession) {
		// No changes, just copy to the new map
		nextLocal[newSession.UUID] = *newSession
		return
	}

	// special case: delete torndown session,
	// so that already torndown sessions changed to delete status will not be torndown again
	var isDeletingTorndownSession bool = (oldSession.Status == PEERING_STATUS_TEARDOWN &&
		(newSession.Status == PEERING_STATUS_QUEUED_FOR_DELETE ||
			newSession.Status == PEERING_STATUS_DELETED))

	if !isDeletingTorndownSession {
		checkAndValidateSession(newSession)
	}

	// Handle session based on its new status
	switch newSession.Status {
	case PEERING_STATUS_DISABLED, PEERING_STATUS_DELETED, PEERING_STATUS_TEARDOWN:
		deleteSession(oldSession)
		log.Printf("[processChangedSession] Session %s has been deleted due to status change to %d",
			newSession.UUID, newSession.Status)

	case PEERING_STATUS_QUEUED_FOR_DELETE:
		deleteSession(oldSession)
		newSession.Status = PEERING_STATUS_DELETED
		err := reportNewStatusToCenter(newSession.UUID, PEERING_STATUS_DELETED)
		if err != nil {
			log.Printf("[processChangedSession] Session %s has been deleted but status update failed: %v",
				newSession.UUID, err)
		} else {
			log.Printf("[processChangedSession] Session %s has been deleted and status updated", newSession.UUID)
		}

	case PEERING_STATUS_QUEUED_FOR_SETUP:
		err := configureSession(newSession)
		if err != nil {
			newSession.Status = PEERING_STATUS_PROBLEM
			log.Printf("[processChangedSession] Failed to reconfigure session %s: %v", newSession.UUID, err)
		} else {
			newSession.Status = PEERING_STATUS_ENABLED
			log.Printf("[processChangedSession] Session %s is enabled and has been set up", newSession.UUID)
		}
		err = reportNewStatusToCenter(newSession.UUID, newSession.Status)
		if err != nil {
			log.Printf("[processChangedSession] Session %s status update failed: %v",
				newSession.UUID, err)
		}

	case PEERING_STATUS_ENABLED:
		err1 := configureSession(newSession)
		if err1 != nil {
			newSession.Status = PEERING_STATUS_PROBLEM
			err2 := reportNewStatusToCenter(newSession.UUID, newSession.Status)
			if err2 != nil {
				log.Printf("[processChangedSession] Session %s status update failed: %v",
					newSession.UUID, err2)
			} else {
				log.Printf("[processChangedSession] Failed to configure session %s: %v", newSession.UUID, err1)
			}
		} else {
			log.Printf("[processChangedSession] Session %s is enabled and has been set up", newSession.UUID)
		}

	case PEERING_STATUS_PROBLEM:
		err1 := configureSession(newSession)
		if err1 == nil {
			newSession.Status = PEERING_STATUS_ENABLED
			err2 := reportNewStatusToCenter(newSession.UUID, newSession.Status)
			if err2 != nil {
				log.Printf("[processChangedSession] Session %s status update failed: %v",
					newSession.UUID, err2)
			} else {
				log.Printf("[processChangedSession] Session %s changed from PROBLEM to ENABLED and has been set up", newSession.UUID)
			}
		} else {
			log.Printf("[processChangedSession] Failed to configure session %s: %v", newSession.UUID, err1)
		}
	}

	// Update the session in the new map
	nextLocal[newSession.UUID] = *newSession
}

// processDeletedSession handles a session that has been removed from the PeerAPI
func processDeletedSession(session *BgpSession) {
	err := deleteSession(session)
	if err != nil {
		log.Printf("[SyncSessions] Session %s has been removed from PeerAPI, but failed to remove locally: %v", session.UUID, err)
		return
	}
	log.Printf("[SyncSessions] Session %s has been removed from PeerAPI", session.UUID)
}

// mainSessionTask is the main function for session management
func mainSessionTask(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(time.Duration(cfg.PeerAPI.SyncInterval) * time.Second)
	defer ticker.Stop()

	// Sync sessions immediately on startup
	syncSessions()

	for {
		select {
		case <-ctx.Done():
			shutdownStart := time.Now()
			log.Println("[SessionSync] Shutting down session synchronization task...")

			// Perform any session-specific cleanup
			sessionMutex.RLock()
			sessionCount := len(localSessions)
			sessionMutex.RUnlock()
			log.Printf("[SessionSync] Cleaning up %d managed BGP sessions", sessionCount)

			log.Printf("[SessionSync] Session synchronization task shutdown completed in %v", time.Since(shutdownStart))
			return
		case <-ticker.C:
			syncSessions()
		}
	}
}

// syncSessions synchronizes local sessions with the PeerAPI server
func syncSessions() {
	remoteSessions, err := getBgpSessions()
	if err != nil {
		log.Printf("[SyncSessions] Failed to get remote sessions: %v", err)
		return
	}

	sessionMutex.RLock()
	log.Printf("[SyncSessions] Syncing %d sessions with local %d sessions", len(remoteSessions), len(localSessions))
	sessionMutex.RUnlock()

	nextLocal := make(map[string]BgpSession)
	remoteSessionUUIDs := make(map[string]struct{})

	// Process remote sessions
	for i := range remoteSessions {
		session := &remoteSessions[i]
		remoteSessionUUIDs[session.UUID] = struct{}{}
		sessionMutex.RLock()
		oldSession, exists := localSessions[session.UUID]
		sessionMutex.RUnlock()

		if !exists {
			// New session
			processNewSession(session, nextLocal)
		} else {
			// Existing session that may have changed
			processChangedSession(session, &oldSession, nextLocal)
		}
	}
	// Handle sessions that were deleted from the remote side
	sessionMutex.RLock()
	for uuid, session := range localSessions {
		if _, exists := remoteSessionUUIDs[uuid]; !exists {
			processDeletedSession(&session)
		}
	}
	sessionMutex.RUnlock()
	// Update local sessions map
	sessionMutex.Lock()
	localSessions = nextLocal
	sessionMutex.Unlock()
}

// validateInterfaceName validates network interface names
func validateInterfaceName(name string) error {
	if name == "" {
		return fmt.Errorf("interface name cannot be empty")
	}

	if len(name) > 15 {
		return fmt.Errorf("interface name too long (max 15 characters)")
	}

	if !interfaceNameRegex.MatchString(name) {
		return fmt.Errorf("invalid characters in interface name")
	}

	return nil
}

// validateIPAddress validates IPv4 and IPv6 addresses
func validateIPAddressIfGiven(ipStr string) error {
	if ipStr == "" {
		return nil // Empty IP is allowed in some contexts
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address format")
	}

	return nil
}

// validateWireGuardPublicKey validates WireGuard public keys
func validateWireGuardPublicKey(key string) error {
	if key == "" {
		return fmt.Errorf("WireGuard public key cannot be empty")
	}

	if !base64Regex.MatchString(key) {
		return fmt.Errorf("invalid WireGuard public key format, expected base64 encoded string")
	}

	return nil
}

// validateEndpoint validates endpoint addresses (IP:port or hostname:port)
func validateEndpoint(endpoint, sessionType string) error {
	if endpoint == "" {
		if sessionType == "wireguard" {
			return nil // WireGuard can work without endpoint for incoming connections
		}
		return fmt.Errorf("endpoint is required for this session type")
	}

	// Parse endpoint to separate host and port
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		// For GRE tunnels, endpoint is just an IP without port
		// "missing port in address" error is expected if no port is given
		// so we dismiss it and handle IP check for GRE/IP6GRE sessions
		if sessionType == "gre" || sessionType == "ip6gre" {
			if validateIPAddressIfGiven(endpoint) != nil {
				return fmt.Errorf("invalid endpoint format (expected valid IP)")
			}
			return nil
		}
		return fmt.Errorf("invalid endpoint format (expected host:port)")
	}

	// Validate port
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid endpoint port number")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("endpoint port number out of valid range (1-65535)")
	}

	// Validate host (can be IP or hostname)
	if ip := net.ParseIP(host); ip == nil {
		// It's a hostname
		if len(host) > 253 {
			return fmt.Errorf("endpoint hostname too long (max 253 characters)")
		}
		if !hostnameRegex.MatchString(host) {
			return fmt.Errorf("invalid endpoint hostname format")
		}
	}

	return nil
}

// validateMTU validates MTU values
func validateMTU(mtu int) error {
	if mtu < MIN_MTU || mtu > MAX_MTU {
		return fmt.Errorf("MTU <%d> must be between %d and %d", mtu, MIN_MTU, MAX_MTU)
	}
	return nil
}

// validateSessionInputs performs comprehensive validation of all session inputs
func validateSessionInputs(session *BgpSession) error {
	// Validate interface name
	if err := validateInterfaceName(session.Interface); err != nil {
		return err
	}

	// Validate IP addresses
	if err := validateIPAddressIfGiven(session.IPv4); err != nil {
		return err
	}
	if err := validateIPAddressIfGiven(session.IPv6); err != nil {
		return err
	}
	if session.IPv6 != "" && strings.HasPrefix(strings.ToLower(session.IPv6), "fe80:") {
		return fmt.Errorf("IPv6 ULA cannot be a link-local address")
	}
	if err := validateIPAddressIfGiven(session.IPv6LinkLocal); err != nil {
		return err
	}
	if session.IPv6LinkLocal != "" && !strings.HasPrefix(strings.ToLower(session.IPv6LinkLocal), "fe80:") {
		return fmt.Errorf("IPv6 link-local address must start with fe80")
	}

	// Validate endpoint
	if err := validateEndpoint(session.Endpoint, session.Type); err != nil {
		return err
	}

	// Validate credentials based on session type
	switch session.Type {
	case "wireguard":
		if err := validateWireGuardPublicKey(session.Credential); err != nil {
			return err
		}
	case "gre", "ip6gre":
		// GRE/IP6GRE sessions do not require credentials, so we skip validation
	default:
		return fmt.Errorf("unsupported session type")
	}

	// Validate MTU
	if err := validateMTU(session.MTU); err != nil {
		return err
	}

	// Validate ASN (basic range check)
	if session.ASN == 0 || session.ASN > ASN_MAX {
		return fmt.Errorf("invalid ASN value: %s", strconv.FormatUint(uint64(session.ASN), 10))
	}

	return nil
}

func checkAndValidateSession(session *BgpSession) {
	// Validate session inputs if not torndown
	if session.Status != PEERING_STATUS_TEARDOWN {
		err := validateSessionInputs(session)
		if err != nil {
			log.Printf("[SyncSessions] Session %s has invalid configuration, tearing down: %v", session.UUID, err)
			session.Status = PEERING_STATUS_TEARDOWN
			err = reportNewStatusToCenter(session.UUID, PEERING_STATUS_TEARDOWN)
			if err != nil {
				log.Printf("[SyncSessions] Failed to report problem status for session %s: %v", session.UUID, err)
			}
		}
	}
}
