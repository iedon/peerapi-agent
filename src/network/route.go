package network

import (
	"context"
	"fmt"
	"strings"

	"github.com/iedon/peerapi-agent/cmd"
)

// stripCIDRSuffix removes CIDR prefix notation from an address
func StripCIDRSuffix(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if idx := strings.Index(addr, "/"); idx >= 0 {
		return addr[:idx]
	}
	return addr
}

// IsIgnorableRouteError checks if a route error can be safely ignored
func IsIgnorableRouteError(output string) bool {
	switch {
	case strings.Contains(output, "No such process"),
		strings.Contains(output, "Cannot find device"),
		strings.Contains(output, "No such file or directory"):
		return true
	default:
		return false
	}
}

// runIP executes the ip command with the given arguments
func runIP(ctx context.Context, ipCommandPath string, args ...string) (string, error) {
	return cmd.RunCommand(ctx, ipCommandPath, args...)
}

// getRoute6Nexthop gets the IPv6 gateway for a given interface
func getRoute6Nexthop(ctx context.Context, ipCommandPath, ipv6, iface string) (string, error) {
	target := StripCIDRSuffix(ipv6)
	if target == "" {
		return "", fmt.Errorf("input ipv6 is not invalid")
	}

	output, err := runIP(ctx, ipCommandPath, "-6", "route", "get", target, "oif", iface)
	if err != nil {
		return "", err
	}

	// Parse output like: "fd42:4242:2189:ac:6::1 from :: via fe80::1 dev eth0 src fd42:4242:2189:118::1 metric 0"
	fields := strings.Fields(output)
	for i, field := range fields {
		if field == "via" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}

	return "", fmt.Errorf("no nexthop found for %s via interface %s", target, iface)
}

// EnsureProbeServerIPv6Route installs the probe server IPv6 route if configured
func EnsureProbeServerIPv6Route(ctx context.Context, ipCommandPath string, peerProbeEnabled bool, probeServerIPv6, probeServerIPv6Prefix, probeServerIPv6Interface string) error {
	if !peerProbeEnabled {
		return nil
	}

	prefix := probeServerIPv6Prefix
	iface := probeServerIPv6Interface

	if prefix == "" || iface == "" {
		return nil
	}

	nextHop, err := getRoute6Nexthop(ctx, ipCommandPath, probeServerIPv6, iface)
	if err != nil || nextHop == "" {
		return fmt.Errorf("failed to get IPv6 gateway for interface %s: %v", iface, err)
	}

	args := []string{"-6", "route", "replace", prefix, "via", nextHop, "dev", iface}
	if output, err := runIP(ctx, ipCommandPath, args...); err != nil {
		return fmt.Errorf("failed to install probe server route: %v (output: \"%s\")", err, output)
	}

	return nil
}

// RemoveProbeServerIPv6Route removes the probe server IPv6 route if configured
func RemoveProbeServerIPv6Route(ctx context.Context, ipCommandPath string, peerProbeEnabled bool, probeServerIPv6, probeServerIPv6Prefix, probeServerIPv6Interface string) error {
	if !peerProbeEnabled {
		return nil
	}

	prefix := probeServerIPv6Prefix
	iface := probeServerIPv6Interface

	if prefix == "" || iface == "" {
		return nil
	}

	nextHop, err := getRoute6Nexthop(ctx, ipCommandPath, probeServerIPv6, iface)
	if err != nil || nextHop == "" {
		return nil
	}

	args := []string{"-6", "route", "del", prefix, "via", nextHop, "dev", iface}
	if output, err := runIP(ctx, ipCommandPath, args...); err != nil {
		if IsIgnorableRouteError(output) {
			return nil
		}
		return fmt.Errorf("failed to remove probe server route: %v (output: \"%s\")", err, output)
	}

	return nil
}
