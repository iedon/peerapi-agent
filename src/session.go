package main

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SessionData holds the parsed JSON from the session.Data field
type SessionData struct {
	Passthrough string `json:"passthrough"`
	Info        string `json:"info"`
}

// BirdTemplateData holds the data needed to render a BIRD configuration template
type BirdTemplateData struct {
	SessionName       string
	InterfaceAddr     string
	ASN               uint
	IPv4ShouldImport  bool
	IPv4ShouldExport  bool
	IPv6ShouldImport  bool
	IPv6ShouldExport  bool
	ExtendedNextHopOn bool
	FilterParamsIPv4  string
	FilterParamsIPv6  string
}

var birdConfMutex sync.Mutex

// configureSession sets up both the network interface and BIRD configuration for a BGP session.
func configureSession(session *BgpSession) error {
	if err := configureInterface(session); err != nil {
		return fmt.Errorf("interface configuration failed: %w", err)
	}

	if err := ensurePeerProbeIPv6Route(session); err != nil {
		return fmt.Errorf("peer probe route installation failed: %w", err)
	}

	if err := configureBird(session); err != nil {
		return fmt.Errorf("BIRD configuration failed: %w", err)
	}

	return nil
}

// deleteSession tears down a BGP session by removing both the interface and BIRD configuration.
func deleteSession(session *BgpSession) error {
	if err := removePeerProbeIPv6Route(session); err != nil {
		log.Printf("Warning: failed to remove peer probe route for session %s: %v", session.UUID, err)
	}

	var interfaceErr error
	if err := deleteInterface(session.Interface); err != nil {
		log.Printf("Warning: Failed to delete interface %s: %v", session.Interface, err)
		interfaceErr = err
	}

	birdErr := deleteBird(session)

	if interfaceErr != nil {
		return interfaceErr
	}
	if birdErr != nil {
		return birdErr
	}

	return nil
}

// configureInterface sets up network interfaces based on the BGP session parameters.
func configureInterface(session *BgpSession) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	log.Printf("Configuring interface for session %s (asn: %d, type: %s, interface: %s)",
		session.UUID, session.ASN, session.Type, session.Interface)

	switch session.Type {
	case "wireguard":
		return configureWireguardInterface(ctx, session)
	case "gre", "ip6gre":
		return configureGreInterface(ctx, session)
	default:
		return fmt.Errorf("unsupported session type: %s", session.Type)
	}
}

func configureWireguardInterface(ctx context.Context, session *BgpSession) error {
	if session.Credential == "" {
		return fmt.Errorf("empty credential (used as publickey) specified")
	}

	if err := deleteInterface(session.Interface); err != nil {
		log.Printf("Warning: Failed to delete existing interface %s: %v", session.Interface, err)
	}

	if output, err := runIPWithCtx(ctx, "link", "add", "dev", session.Interface, "type", "wireguard"); err != nil {
		return fmt.Errorf("failed to create wireguard interface: %v (output: \"%s\")", err, output)
	}

	port, err := parseWireguardListenPort(session)
	if err != nil {
		return err
	}

	if err := programWireguardPeer(ctx, session, port); err != nil {
		return err
	}

	if err := configureIPAddresses(ctx, session); err != nil {
		return err
	}

	if err := setInterfaceMTU(ctx, session.Interface, session.MTU, "MTU"); err != nil {
		return err
	}

	if err := bringUpInterface(ctx, session); err != nil {
		return fmt.Errorf("failed to bring up %s interface: %v", session.Type, err)
	}

	log.Printf("Successfully configured WireGuard interface %s for session %s",
		session.Interface, session.UUID)
	return nil
}

func programWireguardPeer(ctx context.Context, session *BgpSession, port int) error {
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
			return fmt.Errorf("failed to parse wireguard endpoint \"%s\" : %v", session.Endpoint, err)
		}
		args = append(args, "endpoint", session.Endpoint)
	}

	if output, err := runCommandWithOutput(ctx, cfg.WireGuard.WGCommandPath, args...); err != nil {
		return fmt.Errorf("failed to configure wireguard: %v (output: \"%s\")", err, output)
	}

	return nil
}

func configureGreInterface(ctx context.Context, session *BgpSession) error {
	if err := deleteInterface(session.Interface); err != nil {
		log.Printf("Warning: Failed to delete existing interface %s: %v", session.Interface, err)
	}

	isIPv6 := session.Type == "ip6gre"
	if isIPv6 {
		log.Printf("Creating IPv6 GRE tunnel: %s with local: %s remote: %s",
			session.Interface, cfg.GRE.LocalEndpointHost6, session.Endpoint)
	} else {
		log.Printf("Creating IPv4 GRE tunnel: %s with local: %s remote: %s",
			session.Interface, cfg.GRE.LocalEndpointHost4, session.Endpoint)
	}

	if err := createGRETunnel(ctx, session, isIPv6); err != nil {
		return err
	}

	if err := configureIPAddresses(ctx, session); err != nil {
		return err
	}

	if err := setInterfaceMTU(ctx, session.Interface, session.MTU, "GRE MTU"); err != nil {
		return err
	}

	if err := bringUpInterface(ctx, session); err != nil {
		return fmt.Errorf("failed to bring up %s interface: %v", session.Type, err)
	}

	log.Printf("Successfully configured %s interface %s for session %s",
		session.Type, session.Interface, session.UUID)
	return nil
}

func createGRETunnel(ctx context.Context, session *BgpSession, ipv6 bool) error {
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

	if output, err := runIPWithCtx(ctx, args...); err != nil {
		return fmt.Errorf("failed to create %s tunnel: %v (output: \"%s\")", session.Type, err, output)
	}

	return nil
}

func configureIPAddresses(ctx context.Context, session *BgpSession) error {
	ipAddresses := []struct {
		value string
		label string
	}{
		{session.IPv4, "IPv4"},
		{session.IPv6, "IPv6"},
		{session.IPv6LinkLocal, "IPv6 Link Local"},
	}

	for _, ipAddr := range ipAddresses {
		if allowed, err := validateInterfaceIP(ipAddr.value); !allowed {
			return fmt.Errorf("%s address %s validation failed: %v", ipAddr.label, ipAddr.value, err)
		}
	}

	if err := addInterfaceAddress(ctx, session.Interface, cfg.IP.IPv4, session.IPv4, 32, "IPv4"); err != nil {
		return err
	}

	if err := addInterfaceAddress(ctx, session.Interface, cfg.IP.IPv6LinkLocal, session.IPv6LinkLocal, 64, "IPv6 link-local"); err != nil {
		return err
	}

	if err := addInterfaceAddress(ctx, session.Interface, cfg.IP.IPv6, session.IPv6, 128, "IPv6"); err != nil {
		return err
	}

	return nil
}

func setIPv6InterfaceRoute(ctx context.Context, session *BgpSession) error {
	dest := ensureCIDR(session.IPv6, 128)
	if dest == "" {
		return fmt.Errorf("invalid IPv6 address for session %s", session.UUID)
	}

	if output, err := runIPWithCtx(ctx, "-6", "route", "add", dest, "dev", session.Interface); err != nil {
		return fmt.Errorf("failed to add IPv6 route: %v (output: \"%s\")", err, output)
	}

	return nil
}

func applySysctlSettings(ctx context.Context, interfaceName string) {
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
			log.Printf("[applySysctlSettings] Warning: Failed to set %s for interface %s: %v (output: \"%s\")",
				config.desc, interfaceName, err, strings.TrimSpace(string(output)))
		}
	}
}

func bringUpInterface(ctx context.Context, session *BgpSession) error {
	if output, err := runIPWithCtx(ctx, "link", "set", "up", "dev", session.Interface); err != nil {
		return fmt.Errorf("failed to bring up interface %s: %v (output: \"%s\")", session.Interface, err, output)
	}

	if session.IPv6 != "" {
		if err := setIPv6InterfaceRoute(ctx, session); err != nil {
			return fmt.Errorf("failed to set IPv6 dev route for interface: %v", err)
		}
	}

	applySysctlSettings(ctx, session.Interface)
	return nil
}

func deleteInterface(iface string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	exist, err := interfaceExists(iface)
	if err != nil {
		log.Printf("Warning: Failed to check if interface %s exists: %v", iface, err)
	}
	if err == nil && !exist {
		return nil
	}

	if output, err := runIPWithCtx(ctx, "link", "set", "down", "dev", iface); err != nil {
		log.Printf("Warning: Failed to bring down interface %s: %v (output: \"%s\")", iface, err, output)
	}

	if output, err := runIPWithCtx(ctx, "link", "del", "dev", iface); err != nil {
		return fmt.Errorf("failed to delete interface %s: %v (output: \"%s\")", iface, err, output)
	}

	log.Printf("Successfully deleted interface %s", iface)
	return nil
}

func configureBird(session *BgpSession) error {
	confPath := path.Join(cfg.Bird.BGPPeerConfDir, session.Interface+".conf")
	log.Printf("Configuring BIRD for session %s (interface: %s)", session.UUID, session.Interface)

	birdConfMutex.Lock()
	defer birdConfMutex.Unlock()

	if err := os.Remove(confPath); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: Failed to remove existing BIRD config at %s: %v", confPath, err)
	}

	if cfg.Bird.BGPPeerConfTemplate == nil {
		return fmt.Errorf("BIRD peer configuration template is not initialized")
	}

	ifBwCommunity, ifSecCommunity := getCommunityValues(session.Type)
	mpBGP := slices.Contains(session.Extensions, "mp-bgp")
	extendedNexthop := slices.Contains(session.Extensions, "extended-nexthop")

	outFile, err := os.Create(confPath)
	if err != nil {
		return fmt.Errorf("failed to create BIRD config file %s: %v", confPath, err)
	}
	defer outFile.Close()

	sessionName := fmt.Sprintf("DN42_%d_%s", session.ASN, session.Interface)

	if mpBGP {
		if err := generateMPBGPConfig(outFile, session, sessionName, extendedNexthop, ifBwCommunity, ifSecCommunity); err != nil {
			return err
		}
	} else {
		if err := generateTraditionalBGPConfig(outFile, session, sessionName, extendedNexthop, ifBwCommunity, ifSecCommunity); err != nil {
			return err
		}
	}

	if ok, err := birdPool.Configure(); err != nil {
		log.Printf("failed to configure BIRD: %v", err)
	} else if !ok {
		log.Printf("BIRD configuration failed")
	}

	log.Printf("Configured BIRD for session %s", session.UUID)
	return nil
}

func getCommunityValues(sessionType string) (int, int) {
	ifBwCommunity := 0
	ifSecCommunity := 0

	switch sessionType {
	case "wireguard":
		ifBwCommunity = cfg.WireGuard.DN42BandwidthCommunity
		ifSecCommunity = cfg.WireGuard.DN42InterfaceSecurityCommunity
	case "gre", "ip6gre":
		ifBwCommunity = cfg.GRE.DN42BandwidthCommunity
		ifSecCommunity = cfg.GRE.DN42InterfaceSecurityCommunity
	}

	return ifBwCommunity, ifSecCommunity
}

func generateMPBGPConfig(outFile *os.File, session *BgpSession, sessionName string, extendedNexthop bool, ifBwCommunity, ifSecCommunity int) error {
	interfaceAddr, err := getNeighborAddress(session)
	if err != nil {
		return err
	}

	filterParamsIPv4 := fmt.Sprintf("%d,%d,%d,%d,%d", 0, ifBwCommunity, ifSecCommunity, session.Policy, probeStatusFlag(session.UUID, probeFamilyIPv4))
	filterParamsIPv6 := fmt.Sprintf("%d,%d,%d,%d,%d", 0, ifBwCommunity, ifSecCommunity, session.Policy, probeStatusFlag(session.UUID, probeFamilyIPv6))

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

	if err := cfg.Bird.BGPPeerConfTemplate.Execute(outFile, templateData); err != nil {
		return fmt.Errorf("failed to generate MP-BGP config: %v", err)
	}

	return nil
}

func generateTraditionalBGPConfig(outFile *os.File, session *BgpSession, sessionName string, extendedNexthop bool, ifBwCommunity, ifSecCommunity int) error {
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
			FilterParamsIPv4:  fmt.Sprintf("%d,%d,%d,%d,%d", 0, ifBwCommunity, ifSecCommunity, session.Policy, probeStatusFlag(session.UUID, probeFamilyIPv4)),
			FilterParamsIPv6:  fmt.Sprintf("%d,%d,%d,%d,%d", 0, ifBwCommunity, ifSecCommunity, session.Policy, probeStatusFlag(session.UUID, probeFamilyIPv6)),
		}

		if err := cfg.Bird.BGPPeerConfTemplate.Execute(outFile, templateData); err != nil {
			return fmt.Errorf("failed to generate IPv6 BGP config: %v", err)
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
			FilterParamsIPv4:  fmt.Sprintf("%d,%d,%d,%d,%d", 0, ifBwCommunity, ifSecCommunity, session.Policy, probeStatusFlag(session.UUID, probeFamilyIPv4)),
			FilterParamsIPv6:  fmt.Sprintf("%d,%d,%d,%d,%d", 0, ifBwCommunity, ifSecCommunity, session.Policy, probeStatusFlag(session.UUID, probeFamilyIPv6)),
		}

		if err := cfg.Bird.BGPPeerConfTemplate.Execute(outFile, templateData); err != nil {
			return fmt.Errorf("failed to generate IPv4 BGP config: %v", err)
		}
	}

	return nil
}

func getNeighborAddress(session *BgpSession) (string, error) {
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

func deleteBird(session *BgpSession) error {
	confPath := path.Join(cfg.Bird.BGPPeerConfDir, session.Interface+".conf")
	// log.Printf("Removing BIRD configuration for session %s (interface: %s)", session.UUID, session.Interface)

	birdConfMutex.Lock()
	defer birdConfMutex.Unlock()

	if err := os.Remove(confPath); err != nil {
		if os.IsNotExist(err) {
			// log.Printf("BIRD configuration file %s does not exist, nothing to remove", confPath)
			return nil
		}
		return fmt.Errorf("failed to remove BIRD configuration file %s: %v", confPath, err)
	}

	if ok, err := birdPool.Configure(); err != nil {
		log.Printf("failed to configure BIRD: %v", err)
	} else if !ok {
		log.Printf("BIRD configuration failed")
	}

	log.Printf("Successfully removed BIRD configuration for session %s", session.UUID)
	return nil
}

func ensurePeerProbeIPv6Route(session *BgpSession) error {
	if !shouldManagePeerProbeRoute(session) {
		return nil
	}

	nextHop := sessionIPv6NextHop(session)
	if nextHop == "" {
		return fmt.Errorf("session %s has no IPv6 next hop for probe route", session.UUID)
	}

	localIPv6 := stripCIDRSuffix(cfg.IP.IPv6)
	if localIPv6 == "" {
		return fmt.Errorf("ipConfig.ipv6 is required for probe route setup")
	}

	dest := cfg.PeerAPI.ProbeServerIPv6Prefix
	if dest == "" || !strings.Contains(dest, "/") {
		return fmt.Errorf("probeServerIPv6Prefix is required for probe route setup")
	}

	const maxAttempts = 100
	baseMetric := peerProbeRouteMetric(session)
	for attempt := range maxAttempts {
		metric := baseMetric + uint32(attempt)
		metricStr := strconv.FormatUint(uint64(metric), 10)
		args := []string{"-6", "route", "add", dest, "via", nextHop, "src", localIPv6, "dev", session.Interface, "metric", metricStr}
		if output, err := runIPCommand(args...); err != nil {
			if !strings.Contains(output, "File exists") {
				return fmt.Errorf("failed to install peer probe route for session %s (metric %s): %v (output: \"%s\")", session.UUID, metricStr, err, output)
			}
			continue
		}

		return nil
	}

	return fmt.Errorf("failed to install peer probe route for session %s: exhausted metric retries", session.UUID)
}

func removePeerProbeIPv6Route(session *BgpSession) error {
	if !shouldManagePeerProbeRoute(session) {
		return nil
	}

	nextHop := sessionIPv6NextHop(session)
	if nextHop == "" {
		return nil
	}

	localIPv6 := stripCIDRSuffix(cfg.IP.IPv6)
	dest := cfg.PeerAPI.ProbeServerIPv6Prefix
	if localIPv6 == "" || dest == "" || !strings.Contains(dest, "/") {
		return nil
	}

	if output, err := runIPCommand("-6", "route", "del", dest, "via", nextHop, "src", localIPv6, "dev", session.Interface); err != nil {
		if isIgnorableRouteError(output) {
			return nil
		}
		return fmt.Errorf("failed to remove peer probe route for session %s: %v (output: \"%s\")", session.UUID, err, output)
	}

	return nil
}

func shouldManagePeerProbeRoute(session *BgpSession) bool {
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

func sessionIPv6NextHop(session *BgpSession) string {
	if session == nil {
		return ""
	}
	if nh := stripCIDRSuffix(session.IPv6LinkLocal); nh != "" {
		return nh
	}
	return stripCIDRSuffix(session.IPv6)
}

func addInterfaceAddress(ctx context.Context, iface, local, peer string, prefixLen int, label string) error {
	if local == "" {
		return nil
	}

	args := []string{"addr", "add", "dev", iface, ensureCIDR(local, prefixLen)}
	if peer != "" {
		args = append(args, "peer", ensureCIDR(peer, prefixLen))
	}

	if output, err := runIPWithCtx(ctx, args...); err != nil {
		return fmt.Errorf("failed to add %s: %v (output: \"%s\")", label, err, output)
	}
	return nil
}

func setInterfaceMTU(ctx context.Context, iface string, mtu int, label string) error {
	if output, err := runIPWithCtx(ctx, "link", "set", "mtu", strconv.Itoa(mtu), "dev", iface); err != nil {
		return fmt.Errorf("failed to set %s: %v (output: \"%s\")", label, err, output)
	}
	return nil
}

func parseWireguardListenPort(session *BgpSession) (int, error) {
	if len(session.Data) == 0 {
		return 0, nil
	}

	var sessionData SessionData
	if err := json.Unmarshal(session.Data, &sessionData); err != nil {
		log.Printf("Warning: Failed to parse session data: %v", err)
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
		return 0, fmt.Errorf("failed to decode session passthrough data: %v", err)
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
			return 0, fmt.Errorf("failed to decode port(current value: %v) for wireguard: %v", claims, err)
		}
	default:
		return 0, fmt.Errorf("unexpected port value type(current value: %v) for wireguard", claims)
	}
}

func runCommandWithOutput(ctx context.Context, binary string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

func runIPWithCtx(ctx context.Context, args ...string) (string, error) {
	return runCommandWithOutput(ctx, cfg.Bird.IPCommandPath, args...)
}

func runIPCommand(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return runIPWithCtx(ctx, args...)
}

func ensureCIDR(addr string, prefixLen int) string {
	addr = strings.TrimSpace(addr)
	if addr == "" || strings.Contains(addr, "/") {
		return addr
	}
	return fmt.Sprintf("%s/%d", addr, prefixLen)
}

func stripCIDRSuffix(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if idx := strings.Index(addr, "/"); idx >= 0 {
		return addr[:idx]
	}
	return addr
}

func isIgnorableRouteError(output string) bool {
	switch {
	case strings.Contains(output, "No such process"),
		strings.Contains(output, "Cannot find device"),
		strings.Contains(output, "No such file or directory"):
		return true
	default:
		return false
	}
}

func peerProbeRouteMetric(session *BgpSession) uint32 {
	data := session.UUID
	if data == "" {
		data = session.Interface
	}
	if data == "" {
		data = nextHopFallbackKey(session)
	}

	hash := crc32.ChecksumIEEE([]byte(data))
	if hash == 0 || hash < 10000 {
		hash = 10000
	}
	return hash
}

func nextHopFallbackKey(session *BgpSession) string {
	nh := sessionIPv6NextHop(session)
	if nh != "" {
		return nh
	}
	if session.Interface != "" {
		return session.Interface
	}
	return "peer-probe-route"
}
