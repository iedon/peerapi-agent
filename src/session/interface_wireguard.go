package session

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
	"github.com/iedon/peerapi-agent/cmd"
	"github.com/iedon/peerapi-agent/config"
)

func configureWireguardInterface(ctx context.Context, session *Session, cfg *config.Config) error {
	if session.Credential == "" {
		return fmt.Errorf("empty credential (used as publickey) specified")
	}

	if err := deleteInterface(ctx, session.Interface, cfg); err != nil {
		return fmt.Errorf("failed to delete existing interface: %w", err)
	}

	if output, err := runIP(ctx, cfg, "link", "add", "dev", session.Interface, "type", "wireguard"); err != nil {
		return fmt.Errorf("failed to create wireguard interface: %v (output: %q)", err, output)
	}

	port, err := parseWireguardListenPort(session, cfg)
	if err != nil {
		return err
	}

	if err := programWireguardPeer(ctx, session, port, cfg); err != nil {
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

func programWireguardPeer(ctx context.Context, session *Session, port int, cfg *config.Config) error {
	args := []string{"set", session.Interface, "private-key", cfg.WireGuard.PrivateKeyPath}
	if port != 0 {
		args = append(args, "listen-port", strconv.Itoa(port))
	}

	args = append(args,
		"peer", session.Credential,
		"persistent-keepalive", strconv.Itoa(cfg.WireGuard.PersistentKeepaliveInterval),
		"allowed-ips", cfg.WireGuard.AllowedIPs,
	)

	if session.Endpoint != "" {
		if _, _, err := net.SplitHostPort(session.Endpoint); err != nil {
			return fmt.Errorf("failed to parse wireguard endpoint %q: %w", session.Endpoint, err)
		}
		args = append(args, "endpoint", session.Endpoint)
	}

	if output, err := cmd.RunCommand(ctx, cfg.WireGuard.WGCommandPath, args...); err != nil {
		return fmt.Errorf("failed to configure wireguard: %v (output: %q)", err, output)
	}

	return nil
}

func parseWireguardListenPort(session *Session, cfg *config.Config) (int, error) {
	if len(session.Data) == 0 {
		return 0, nil
	}

	var sessionData SessionData
	if err := json.Unmarshal(session.Data, &sessionData); err != nil {
		return 0, nil
	}

	if sessionData.Passthrough == "" {
		return 0, nil
	}

	token, err := jwt.Parse(sessionData.Passthrough, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(cfg.PeerAPI.SessionPassthroughJwtSecert), nil
	})
	if err != nil {
		return 0, fmt.Errorf("failed to decode session passthrough data: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return 0, nil
	}

	portValue, exists := claims["port"]
	if !exists {
		return 0, nil
	}

	switch v := portValue.(type) {
	case float64:
		return int(v), nil
	case int:
		return v, nil
	case json.Number:
		if p, err := v.Int64(); err == nil {
			return int(p), nil
		} else {
			return 0, fmt.Errorf("failed to decode port for wireguard: %w", err)
		}
	default:
		return 0, fmt.Errorf("unexpected port value type for wireguard")
	}
}
