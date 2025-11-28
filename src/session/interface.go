package session

import (
	"context"
	"fmt"
	"hash/crc32"
	"os/exec"
	"strconv"
	"strings"

	"github.com/iedon/peerapi-agent/cmd"
	"github.com/iedon/peerapi-agent/config"
	"github.com/iedon/peerapi-agent/logger"
	"github.com/iedon/peerapi-agent/network"
)

// configureInterface sets up network interfaces based on the BGP session parameters
func configureInterface(ctx context.Context, session *Session, cfg *config.Config) error {
	switch session.Type {
	case "wireguard":
		return configureWireguardInterface(ctx, session, cfg)
	case "gre", "ip6gre":
		return configureGreInterface(ctx, session, cfg)
	default:
		return fmt.Errorf("unsupported session type: %s", session.Type)
	}
}

func configureIPAddresses(ctx context.Context, session *Session, cfg *config.Config) error {
	ipAddresses := []struct {
		value string
		label string
	}{
		{session.IPv4, "IPv4"},
		{session.IPv6, "IPv6"},
		{session.IPv6LinkLocal, "IPv6 Link Local"},
	}

	for _, ipAddr := range ipAddresses {
		if allowed, err := network.ValidateInterfaceIP(ipAddr.value, cfg.PeerAPI.InterfaceIpAllowPublic, cfg.PeerAPI.InterfaceIpBlacklist); !allowed {
			return fmt.Errorf("%s address %s validation failed: %w", ipAddr.label, ipAddr.value, err)
		}
	}

	if err := addInterfaceAddress(ctx, session.Interface, cfg.IP.IPv4, session.IPv4, 32, "IPv4", cfg); err != nil {
		return err
	}

	if err := addInterfaceAddress(ctx, session.Interface, cfg.IP.IPv6LinkLocal, session.IPv6LinkLocal, 64, "IPv6 link-local", cfg); err != nil {
		return err
	}

	if err := addInterfaceAddress(ctx, session.Interface, cfg.IP.IPv6, session.IPv6, 128, "IPv6", cfg); err != nil {
		return err
	}

	return nil
}

func setIPv6InterfaceRoute(ctx context.Context, session *Session, cfg *config.Config) error {
	dest := ensureCIDR(session.IPv6, 128)
	if dest == "" {
		return fmt.Errorf("invalid IPv6 address for session %s", session.UUID)
	}

	if output, err := runIP(ctx, cfg, "-6", "route", "add", dest, "dev", session.Interface); err != nil {
		return fmt.Errorf("failed to add IPv6 route: %v (output: %q)", err, output)
	}

	return nil
}

func applySysctlSettings(ctx context.Context, interfaceName string, cfg *config.Config, log *logger.Logger) {
	boolToStr := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}

	sysctlParams := map[string]struct {
		value string
		desc  string
	}{
		fmt.Sprintf("net.ipv4.conf.%s.forwarding", interfaceName):   {boolToStr(cfg.Sysctl.IfaceIPForwarding), "IPv4 forwarding"},
		fmt.Sprintf("net.ipv6.conf.%s.forwarding", interfaceName):   {boolToStr(cfg.Sysctl.IfaceIP6Forwarding), "IPv6 forwarding"},
		fmt.Sprintf("net.ipv6.conf.%s.accept_ra", interfaceName):    {boolToStr(cfg.Sysctl.IfaceIP6AcceptRA), "IPv6 Router Advertisement acceptance"},
		fmt.Sprintf("net.ipv6.conf.%s.autoconf", interfaceName):     {boolToStr(cfg.Sysctl.IfaceIP6AutoConfig), "IPv6 autoconfiguration"},
		fmt.Sprintf("net.ipv4.conf.%s.rp_filter", interfaceName):    {strconv.Itoa(cfg.Sysctl.IfaceRPFilter), "Reverse Path Filter"},
		fmt.Sprintf("net.ipv4.conf.%s.accept_local", interfaceName): {boolToStr(cfg.Sysctl.IfaceAcceptLocal), "Accept local traffic"},
	}

	for param, config := range sysctlParams {
		cmd := exec.CommandContext(ctx, cfg.Sysctl.CommandPath, "-w", fmt.Sprintf("%s=%s", param, config.value))
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Warn("Failed to set %s for interface %s: %v (output: %q)",
				config.desc, interfaceName, err, strings.TrimSpace(string(output)))
		}
	}
}

func bringUpInterface(ctx context.Context, session *Session, cfg *config.Config) error {
	if output, err := runIP(ctx, cfg, "link", "set", "up", "dev", session.Interface); err != nil {
		return fmt.Errorf("failed to bring up interface %s: %v (output: %q)", session.Interface, err, output)
	}

	if session.IPv6 != "" {
		// Set IPv6 dev route for the interface if IPv6 is configured
		// IPv6 link-local does not require this route
		if err := setIPv6InterfaceRoute(ctx, session, cfg); err != nil {
			return fmt.Errorf("failed to set IPv6 dev route for interface: %w", err)
		}
	}

	// Note: applySysctlSettings needs logger, but we don't have it here
	// This will be called from Manager which has access to logger
	return nil
}

func deleteInterface(ctx context.Context, iface string, cfg *config.Config) error {
	exist, err := network.InterfaceExists(iface)
	if err != nil {
		return fmt.Errorf("failed to check if interface %s exists: %w", iface, err)
	}
	if !exist {
		return nil
	}

	if output, err := runIP(ctx, cfg, "link", "set", "down", "dev", iface); err != nil {
		return fmt.Errorf("failed to bring down interface %s: %v (output: %q)", iface, err, output)
	}

	if output, err := runIP(ctx, cfg, "link", "del", "dev", iface); err != nil {
		return fmt.Errorf("failed to delete interface %s: %v (output: %q)", iface, err, output)
	}

	return nil
}

func addInterfaceAddress(ctx context.Context, iface, local, peer string, prefixLen int, label string, cfg *config.Config) error {
	if local == "" {
		return nil
	}

	args := []string{"addr", "add", "dev", iface, ensureCIDR(local, prefixLen)}
	if peer != "" {
		args = append(args, "peer", ensureCIDR(peer, prefixLen))
	}

	if output, err := runIP(ctx, cfg, args...); err != nil {
		return fmt.Errorf("failed to add %s: %v (output: %q)", label, err, output)
	}
	return nil
}

func setInterfaceMTU(ctx context.Context, iface string, mtu int, cfg *config.Config) error {
	if output, err := runIP(ctx, cfg, "link", "set", "mtu", strconv.Itoa(mtu), "dev", iface); err != nil {
		return fmt.Errorf("failed to set MTU: %v (output: %q)", err, output)
	}
	return nil
}

// runIP executes the ip command with the given arguments
func runIP(ctx context.Context, cfg *config.Config, args ...string) (string, error) {
	return cmd.RunCommand(ctx, cfg.Bird.IPCommandPath, args...)
}

// ensureCIDR adds CIDR prefix notation if not already present
func ensureCIDR(addr string, prefixLen int) string {
	addr = strings.TrimSpace(addr)
	if addr == "" || strings.Contains(addr, "/") {
		return addr
	}
	return fmt.Sprintf("%s/%d", addr, prefixLen)
}

// ensurePeerProbeIPv6Route installs an IPv6 route for peer probing
func ensurePeerProbeIPv6Route(session *Session, cfg *config.Config) error {
	if !shouldManagePeerProbeRoute(session, cfg) {
		return nil
	}

	nextHop := sessionIPv6NextHop(session)
	if nextHop == "" {
		return fmt.Errorf("session %s has no IPv6 next hop for probe route", session.UUID)
	}

	localIPv6 := network.StripCIDRSuffix(cfg.IP.IPv6)
	if localIPv6 == "" {
		return fmt.Errorf("ipConfig.ipv6 is required for probe route setup")
	}

	dest := cfg.PeerAPI.ProbeServerIPv6Prefix
	if dest == "" || !strings.Contains(dest, "/") {
		return fmt.Errorf("probeServerIPv6Prefix is required for probe route setup")
	}

	const maxAttempts = 100
	baseMetric := peerProbeRouteMetric(session)
	ctx := context.Background()
	for attempt := range maxAttempts {
		metric := baseMetric + uint32(attempt)
		metricStr := strconv.FormatUint(uint64(metric), 10)
		args := []string{"-6", "route", "add", dest, "via", nextHop, "src", localIPv6, "dev", session.Interface, "metric", metricStr}
		if output, err := runIP(ctx, cfg, args...); err != nil {
			if !strings.Contains(output, "File exists") {
				return fmt.Errorf("failed to install peer probe route for session %s (metric %s): %v (output: %q)", session.UUID, metricStr, err, output)
			}
			continue
		}

		return nil
	}

	return fmt.Errorf("failed to install peer probe route for session %s: exhausted metric retries", session.UUID)
}

// removePeerProbeIPv6Route removes an IPv6 route for peer probing
func removePeerProbeIPv6Route(session *Session, cfg *config.Config) error {
	if !shouldManagePeerProbeRoute(session, cfg) {
		return nil
	}

	nextHop := sessionIPv6NextHop(session)
	if nextHop == "" {
		return nil
	}

	localIPv6 := network.StripCIDRSuffix(cfg.IP.IPv6)
	dest := cfg.PeerAPI.ProbeServerIPv6Prefix
	if localIPv6 == "" || dest == "" || !strings.Contains(dest, "/") {
		return nil
	}

	ctx := context.Background()
	if output, err := runIP(ctx, cfg, "-6", "route", "del", dest, "via", nextHop, "src", localIPv6, "dev", session.Interface); err != nil {
		if network.IsIgnorableRouteError(output) {
			return nil
		}
		return fmt.Errorf("failed to remove peer probe route for session %s: %v (output: %q)", session.UUID, err, output)
	}

	return nil
}

func shouldManagePeerProbeRoute(session *Session, cfg *config.Config) bool {
	if session == nil || !cfg.PeerProbe.Enabled {
		return false
	}
	if cfg.PeerAPI.ProbeServerIPv6 == "" || cfg.IP.IPv6 == "" {
		return false
	}
	if session.Interface == "" {
		return false
	}
	return sessionIPv6NextHop(session) != ""
}

// SessionIPv6NextHop returns the IPv6 next hop for a session
func sessionIPv6NextHop(session *Session) string {
	if session == nil {
		return ""
	}
	if nh := network.StripCIDRSuffix(session.IPv6LinkLocal); nh != "" {
		return nh
	}
	return network.StripCIDRSuffix(session.IPv6)
}

func peerProbeRouteMetric(session *Session) uint32 {
	data := session.UUID
	hash := crc32.ChecksumIEEE([]byte(data))
	if hash == 0 || hash < 10000 {
		// max uint32 - 10000 + hash
		hash = 0xFFFFFFFF - 10000 + hash
	}
	return hash
}
