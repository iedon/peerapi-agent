package config

import (
	"fmt"
)

// Validate validates the configuration
func Validate(cfg *Config) error {
	// Validate metric interval
	if cfg.PeerAPI.MetricInterval < 60 {
		return fmt.Errorf("MetricInterval must be at least 60 seconds, got %d", cfg.PeerAPI.MetricInterval)
	}

	// Validate required fields
	if cfg.PeerAPI.APIURL == "" {
		return fmt.Errorf("peerApiCenter.apiUrl is required")
	}

	if cfg.PeerAPI.RouterUUID == "" {
		return fmt.Errorf("peerApiCenter.routerUuid is required")
	}

	if cfg.PeerAPI.AgentSecret == "" {
		return fmt.Errorf("peerApiCenter.agentSecret is required")
	}

	if cfg.Bird.ControlSocket == "" {
		return fmt.Errorf("bird.controlSocket is required")
	}

	if cfg.Bird.BGPPeerConfDir == "" {
		return fmt.Errorf("bird.bgpPeerConfDir is required")
	}

	// Set defaults if not specified
	if cfg.Server.ListenerType == "" {
		cfg.Server.ListenerType = "tcp"
	}

	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":8080"
	}

	return nil
}
