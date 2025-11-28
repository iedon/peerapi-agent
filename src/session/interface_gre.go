package session

import (
	"context"
	"fmt"

	"github.com/iedon/peerapi-agent/config"
)

func configureGreInterface(ctx context.Context, session *Session, cfg *config.Config) error {
	if err := deleteInterface(ctx, session.Interface, cfg); err != nil {
		return fmt.Errorf("failed to delete existing interface: %w", err)
	}

	isIPv6 := session.Type == "ip6gre"

	if err := createGRETunnel(ctx, session, isIPv6, cfg); err != nil {
		return err
	}

	if err := configureIPAddresses(ctx, session, cfg); err != nil {
		return err
	}

	if err := setInterfaceMTU(ctx, session.Interface, session.MTU, cfg); err != nil {
		return err
	}

	if err := bringUpInterface(ctx, session, cfg); err != nil {
		return fmt.Errorf("failed to bring up %s interface: %w", session.Type, err)
	}

	return nil
}

func createGRETunnel(ctx context.Context, session *Session, ipv6 bool, cfg *config.Config) error {
	var args []string
	if ipv6 {
		args = []string{"-6", "tunnel", "add", session.Interface,
			"mode", "ip6gre",
			"local", cfg.GRE.LocalEndpointHost6,
			"remote", session.Endpoint,
			"ttl", "255",
			"encaplimit", "none"}
	} else {
		args = []string{"tunnel", "add", session.Interface,
			"mode", "gre",
			"local", cfg.GRE.LocalEndpointHost4,
			"remote", session.Endpoint,
			"ttl", "255"}
	}

	if output, err := runIP(ctx, cfg, args...); err != nil {
		return fmt.Errorf("failed to create %s tunnel: %v (output: %q)", session.Type, err, output)
	}

	return nil
}
