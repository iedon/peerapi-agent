package session

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/iedon/peerapi-agent/config"
	"github.com/iedon/peerapi-agent/logger"
)

// Manager manages BGP sessions in a thread-safe manner
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	cfg      *config.Config
	logger   *logger.Logger
}

// NewManager creates a new session manager
func NewManager(cfg *config.Config, log *logger.Logger) *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
		cfg:      cfg,
		logger:   log,
	}
}

// Get retrieves a session by UUID
func (m *Manager) Get(uuid string) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[uuid]
}

// Exists checks if a session exists
func (m *Manager) Exists(uuid string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.sessions[uuid]
	return exists
}

// List returns all sessions
func (m *Manager) List() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

// Add adds or updates a session
func (m *Manager) Add(session *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[session.UUID] = session
}

// Delete removes a session
func (m *Manager) Delete(uuid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, uuid)
}

// Count returns the number of sessions
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// Replace replaces all sessions atomically
func (m *Manager) Replace(sessions map[string]*Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions = sessions
}

// GetActive returns all active sessions
func (m *Manager) GetActive() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	active := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		if s.Status == PEERING_STATUS_ENABLED || s.Status == PEERING_STATUS_PROBLEM {
			active = append(active, s)
		}
	}
	return active
}

// ConfigureSession configures the network interface and BIRD for a session
func (m *Manager) ConfigureSession(session *Session) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	m.logger.Info("Configuring session %s (asn: %d, type: %s, interface: %s)",
		session.UUID, session.ASN, session.Type, session.Interface)

	// Configure interface
	if err := configureInterface(ctx, session, m.cfg); err != nil {
		return fmt.Errorf("interface configuration failed: %w", err)
	}

	// Ensure peer probe route if needed
	if err := ensurePeerProbeIPv6Route(session, m.cfg); err != nil {
		m.logger.Warn("Failed to install peer probe route for session %s: %v", session.UUID, err)
	}

	// Apply sysctl settings after interface is up
	applySysctlSettings(ctx, session.Interface, m.cfg, m.logger)

	// Configure BIRD
	if err := m.configureBirdForSession(session); err != nil {
		return fmt.Errorf("BIRD configuration failed: %w", err)
	}

	m.logger.Info("Successfully configured session %s", session.UUID)
	return nil
}

// generateMPBGPConfig generates MP-BGP configuration
func (m *Manager) generateMPBGPConfig(outFile *os.File, session *Session, sessionName string, extendedNexthop bool, ifBwCommunity, ifSecCommunity int) error {
	interfaceAddr, err := GetNeighborAddress(session)
	if err != nil {
		return err
	}

	filterParamsIPv4 := fmt.Sprintf("%d,%d,%d,%d,%d", 0, ifBwCommunity, ifSecCommunity, session.Policy, 0)
	filterParamsIPv6 := fmt.Sprintf("%d,%d,%d,%d,%d", 0, ifBwCommunity, ifSecCommunity, session.Policy, 0)

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

	if err := m.cfg.Bird.BGPPeerConfTemplate.Execute(outFile, templateData); err != nil {
		return fmt.Errorf("failed to generate MP-BGP config: %w", err)
	}

	return nil
}

// generateTraditionalBGPConfig generates traditional BGP configuration (separate v4/v6)
func (m *Manager) generateTraditionalBGPConfig(outFile *os.File, session *Session, sessionName string, extendedNexthop bool, ifBwCommunity, ifSecCommunity int) error {
	if session.IPv6LinkLocal != "" || session.IPv6 != "" {
		var interfaceAddr string
		if session.IPv6LinkLocal != "" {
			interfaceAddr = fmt.Sprintf("%s%%'%s'", session.IPv6LinkLocal, session.Interface)
		} else {
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
			FilterParamsIPv4:  fmt.Sprintf("%d,%d,%d,%d,%d", 0, ifBwCommunity, ifSecCommunity, session.Policy, 0),
			FilterParamsIPv6:  fmt.Sprintf("%d,%d,%d,%d,%d", 0, ifBwCommunity, ifSecCommunity, session.Policy, 0),
		}

		if err := m.cfg.Bird.BGPPeerConfTemplate.Execute(outFile, templateData); err != nil {
			return fmt.Errorf("failed to generate IPv6 BGP config: %w", err)
		}
	}

	if session.IPv4 != "" {
		templateData := BirdTemplateData{
			SessionName:       sessionName + "_v4",
			InterfaceAddr:     session.IPv4,
			ASN:               session.ASN,
			IPv4ShouldImport:  true,
			IPv4ShouldExport:  true,
			IPv6ShouldImport:  false,
			IPv6ShouldExport:  false,
			ExtendedNextHopOn: extendedNexthop,
			FilterParamsIPv4:  fmt.Sprintf("%d,%d,%d,%d,%d", 0, ifBwCommunity, ifSecCommunity, session.Policy, 0),
			FilterParamsIPv6:  fmt.Sprintf("%d,%d,%d,%d,%d", 0, ifBwCommunity, ifSecCommunity, session.Policy, 0),
		}

		if err := m.cfg.Bird.BGPPeerConfTemplate.Execute(outFile, templateData); err != nil {
			return fmt.Errorf("failed to generate IPv4 BGP config: %w", err)
		}
	}

	return nil
}

// DeleteSession tears down a session
func (m *Manager) DeleteSession(session *Session) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	m.logger.Info("Deleting session %s (interface: %s)", session.UUID, session.Interface)

	// Remove peer probe route if needed
	if err := removePeerProbeIPv6Route(session, m.cfg); err != nil {
		m.logger.Warn("Failed to remove peer probe route for session %s: %v", session.UUID, err)
	}

	// Delete BIRD configuration
	if err := deleteBird(session, m.cfg); err != nil {
		m.logger.Warn("Failed to delete BIRD config for session %s: %v", session.UUID, err)
	}

	// Delete interface
	if err := deleteInterface(ctx, session.Interface, m.cfg); err != nil {
		m.logger.Warn("Failed to delete interface %s: %v", session.Interface, err)
		return err
	}

	m.logger.Info("Successfully deleted session %s", session.UUID)
	return nil
}
