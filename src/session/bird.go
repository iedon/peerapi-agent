package session

import (
	"fmt"
	"os"
	"path"
	"sync"

	"github.com/iedon/peerapi-agent/config"
)

var birdConfMutex sync.Mutex

// LockBirdConfig locks the BIRD configuration mutex
func LockBirdConfig() {
	birdConfMutex.Lock()
}

// UnlockBirdConfig unlocks the BIRD configuration mutex
func UnlockBirdConfig() {
	birdConfMutex.Unlock()
}

// GetCommunityValues returns the bandwidth and security community values based on session type
func GetCommunityValues(sessionType string, cfg *config.Config) (ifBwCommunity, ifSecCommunity int) {
	switch sessionType {
	case "wireguard":
		return cfg.WireGuard.DN42BandwidthCommunity, cfg.WireGuard.DN42InterfaceSecurityCommunity
	case "gre", "ip6gre":
		return cfg.GRE.DN42BandwidthCommunity, cfg.GRE.DN42InterfaceSecurityCommunity
	default:
		return 0, 0
	}
}

// GetNeighborAddress returns the appropriate neighbor address for a BGP session
func GetNeighborAddress(session *Session) (string, error) {
	if session.IPv6LinkLocal != "" {
		return fmt.Sprintf("%s%%'%s'", session.IPv6LinkLocal, session.Interface), nil
	}
	if session.IPv6 != "" {
		return session.IPv6, nil
	}
	if session.IPv4 != "" {
		return session.IPv4, nil
	}

	return "", fmt.Errorf("no valid interface addresses for peering session %s", session.UUID)
}

// configureBirdForSession generates BIRD configuration using templates
func (m *Manager) configureBirdForSession(session *Session) error {
	confPath := fmt.Sprintf("%s/%s.conf", m.cfg.Bird.BGPPeerConfDir, session.Interface)

	birdConfMutex.Lock()
	defer birdConfMutex.Unlock()

	if err := os.Remove(confPath); err != nil && !os.IsNotExist(err) {
		m.logger.Warn("Failed to remove existing BIRD config at %s: %v", confPath, err)
	}

	if m.cfg.Bird.BGPPeerConfTemplate == nil {
		return fmt.Errorf("BIRD peer configuration template is not initialized")
	}

	ifBwCommunity, ifSecCommunity := GetCommunityValues(session.Type, m.cfg)
	mpBGP := false
	extendedNexthop := false
	for _, ext := range session.Extensions {
		if ext == "mp-bgp" {
			mpBGP = true
		}
		if ext == "extended-nexthop" {
			extendedNexthop = true
		}
	}

	outFile, err := os.Create(confPath)
	if err != nil {
		return fmt.Errorf("failed to create BIRD config file %s: %w", confPath, err)
	}
	defer outFile.Close()

	sessionName := fmt.Sprintf("DN42_%d_%s", session.ASN, session.Interface)

	if mpBGP {
		if err := m.generateMPBGPConfig(outFile, session, sessionName, extendedNexthop, ifBwCommunity, ifSecCommunity); err != nil {
			return err
		}
	} else {
		if err := m.generateTraditionalBGPConfig(outFile, session, sessionName, extendedNexthop, ifBwCommunity, ifSecCommunity); err != nil {
			return err
		}
	}

	return nil
}

// deleteBird removes the BIRD configuration file for a session
func deleteBird(session *Session, cfg *config.Config) error {
	confPath := path.Join(cfg.Bird.BGPPeerConfDir, session.Interface+".conf")

	birdConfMutex.Lock()
	defer birdConfMutex.Unlock()

	if err := os.Remove(confPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to remove BIRD configuration file %s: %w", confPath, err)
	}

	return nil
}
