package main

import (
	"context"
	"encoding/json"
	"fmt"
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

// PassthroughData holds the values decoded from the JWT passthrough
type PassthroughData struct {
	ASN  uint `json:"asn"`
	Port int  `json:"port"`
}

// BirdTemplateData holds the data needed to render a BIRD configuration template
type BirdTemplateData struct {
	SessionName       string // Name of the BGP session
	InterfaceAddr     string // Interface address for the BGP connection
	ASN               uint   // Autonomous System Number of the peer
	IPv4ShouldImport  bool   // Whether to import IPv4 routes
	IPv4ShouldExport  bool   // Whether to export IPv4 routes
	IPv6ShouldImport  bool   // Whether to import IPv6 routes
	IPv6ShouldExport  bool   // Whether to export IPv6 routes
	ExtendedNextHopOn bool   // Whether to enable extended next hop
	FilterParamsIPv4  string // IPv4-specific filter parameters
	FilterParamsIPv6  string // IPv6-specific filter parameters
}

var birdConfMutex sync.Mutex

// configureInterface sets up network interfaces based on the BGP session parameters.
// Currently supports WireGuard and GRE interface types.
func configureInterface(session *BgpSession) error {
	// Set a timeout for commands to prevent hanging
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

// configureWireguardInterface sets up a WireGuard interface for the BGP session
func configureWireguardInterface(ctx context.Context, session *BgpSession) error {
	if session.Credential == "" {
		return fmt.Errorf("empty credential (used as publickey) specified")
	}

	// Delete the interface if it exists to ensure clean state
	if err := deleteInterface(session.Interface); err != nil {
		log.Printf("Warning: Failed to delete existing interface %s: %v", session.Interface, err)
		// Continue anyway as we'll try to recreate it
	}
	// Create the new interface
	cmd := exec.CommandContext(ctx, cfg.Bird.IPCommandPath, "link", "add", "dev", session.Interface, "type", "wireguard")
	outputBytes, err := cmd.CombinedOutput()
	output := string(outputBytes)

	if err != nil {
		return fmt.Errorf("failed to create wireguard interface: %v (output: \"%s\")", err, strings.TrimSpace(output))
	}
	// Parse session data to get the port from passthrough JWT
	port := 0
	if len(session.Data) > 0 {
		var sessionData SessionData
		if err := json.Unmarshal(session.Data, &sessionData); err != nil {
			log.Printf("Warning: Failed to parse session data: %v", err)
		} else if sessionData.Passthrough != "" {
			// Parse the JWT token from passthrough
			token, err := jwt.Parse(sessionData.Passthrough, func(token *jwt.Token) (any, error) {
				// Validate the signing method
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(cfg.PeerAPI.SessionPassthroughJwtSecert), nil
			})

			if err != nil {
				return fmt.Errorf("failed to decode session passthrough data: %v", err)
			} else if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				if portValue, exists := claims["port"]; exists {
					// In JSON numbers are often decoded as float64
					switch v := portValue.(type) {
					case float64:
						port = int(v)
					case int:
						port = v
					case json.Number:
						if p, err := v.Int64(); err == nil {
							port = int(p)
						} else {
							return fmt.Errorf("failed to decode port(current value: %v) for wireguard: %v", claims, err)
						}
					default:
						return fmt.Errorf("unexpected port value type(current value: %v) for wireguard", claims)
					}
				}
			}
		}
	}

	// Configure the peer settings, including optional listen port(must set before addresses)
	wgArgs := []string{
		"set", session.Interface,
		"private-key", cfg.WireGuard.PrivateKeyPath,
	}
	if port != 0 {
		wgArgs = append(wgArgs, "listen-port", strconv.Itoa(port))
	}
	wgArgs = append(wgArgs,
		"peer", session.Credential,
		"persistent-keepalive", strconv.Itoa(cfg.WireGuard.PersistentKeepaliveInterval),
		"allowed-ips", cfg.WireGuard.AllowedIPs,
	)
	if session.Endpoint != "" {
		wgArgs = append(wgArgs, "endpoint", session.Endpoint)
		if _, _, err := net.SplitHostPort(session.Endpoint); err != nil {
			return fmt.Errorf("failed to parse wireguard endpoint \"%s\" : %v", session.Endpoint, err)
		}
	}

	cmd = exec.CommandContext(ctx, cfg.WireGuard.WGCommandPath, wgArgs...)

	// Capture both stdout and stderr
	outputBytes, err = cmd.CombinedOutput()
	output = string(outputBytes)

	if err != nil {
		return fmt.Errorf("failed to configure wireguard: %v (output: \"%s\")", err, strings.TrimSpace(output))
	}

	// Configure IP addresses(also see bringUpInterface)
	if err := configureIPAddresses(ctx, session); err != nil {
		return err
	}

	// Set MTU
	cmd = exec.CommandContext(ctx, cfg.Bird.IPCommandPath, "link", "set", "mtu", strconv.Itoa(session.MTU), "dev", session.Interface)
	mtuOutputBytes, mtuErr := cmd.CombinedOutput()
	mtuOutput := string(mtuOutputBytes)

	if mtuErr != nil {
		return fmt.Errorf("failed to set MTU: %v (output: \"%s\")", mtuErr, strings.TrimSpace(mtuOutput))
	}

	// Bring up interface
	if err := bringUpInterface(ctx, session); err != nil {
		return fmt.Errorf("failed to bring up %s interface: %v", session.Type, err)
	}

	log.Printf("Successfully configured WireGuard interface %s for session %s",
		session.Interface, session.UUID)
	return nil
}

// configureGreInterface sets up a GRE tunnel for the BGP session
// Handles both IPv4 GRE (gre) and IPv6 GRE (ip6gre) tunnel types
func configureGreInterface(ctx context.Context, session *BgpSession) error {
	// Delete the interface if it exists to ensure clean state
	if err := deleteInterface(session.Interface); err != nil {
		log.Printf("Warning: Failed to delete existing interface %s: %v", session.Interface, err)
		// Continue anyway as we'll try to recreate it
	}

	var cmd *exec.Cmd
	isIPv6 := session.Type == "ip6gre"

	if isIPv6 {
		// IPv6 GRE tunnel (ip6gre)
		cmd = exec.CommandContext(ctx, cfg.Bird.IPCommandPath, "-6", "tunnel", "add", session.Interface,
			"mode", "ip6gre",
			"local", cfg.GRE.LocalEndpointHost6,
			"remote", session.Endpoint,
			"ttl", "255",
			"encaplimit", "none")

		log.Printf("Creating IPv6 GRE tunnel: %s with local: %s remote: %s",
			session.Interface, cfg.GRE.LocalEndpointHost6, session.Endpoint)
	} else {
		// IPv4 GRE tunnel (gre)
		cmd = exec.CommandContext(ctx, cfg.Bird.IPCommandPath, "tunnel", "add", session.Interface,
			"mode", "gre",
			"local", cfg.GRE.LocalEndpointHost4,
			"remote", session.Endpoint,
			"ttl", "255")

		log.Printf("Creating IPv4 GRE tunnel: %s with local: %s remote: %s",
			session.Interface, cfg.GRE.LocalEndpointHost4, session.Endpoint)
	}
	outputBytes, err := cmd.CombinedOutput()
	output := string(outputBytes)

	if err != nil {
		return fmt.Errorf("failed to create %s tunnel: %v (output: \"%s\")", session.Type, err, strings.TrimSpace(output))
	}

	// Configure IP addresses(also see bringUpInterface)
	if err := configureIPAddresses(ctx, session); err != nil {
		return err
	}

	// Set MTU
	cmd = exec.CommandContext(ctx, cfg.Bird.IPCommandPath, "link", "set", "mtu", strconv.Itoa(session.MTU), "dev", session.Interface)
	mtuOutputBytes, mtuErr := cmd.CombinedOutput()
	mtuOutput := string(mtuOutputBytes)

	if mtuErr != nil {
		return fmt.Errorf("failed to set GRE MTU: %v (output: \"%s\")", mtuErr, strings.TrimSpace(mtuOutput))
	}

	// Bring up interface
	if err := bringUpInterface(ctx, session); err != nil {
		return fmt.Errorf("failed to bring up %s interface: %v", session.Type, err)
	}

	log.Printf("Successfully configured %s interface %s for session %s",
		session.Type, session.Interface, session.UUID)
	return nil
}

// configureIPAddresses sets up IP addresses on the interface
func configureIPAddresses(ctx context.Context, session *BgpSession) error {
	// Get local IP configuration based on session type
	var localIPv4, localIPv6, localIPv6LinkLocal string
	switch session.Type {
	case "wireguard":
		localIPv4 = cfg.WireGuard.IPv4
		localIPv6 = cfg.WireGuard.IPv6
		localIPv6LinkLocal = cfg.WireGuard.IPv6LinkLocal
	case "gre", "ip6gre":
		localIPv4 = cfg.GRE.IPv4
		localIPv6 = cfg.GRE.IPv6
		localIPv6LinkLocal = cfg.GRE.IPv6LinkLocal
	default:
		// Use WireGuard as fallback for unknown types
		localIPv4 = cfg.WireGuard.IPv4
		localIPv6 = cfg.WireGuard.IPv6
		localIPv6LinkLocal = cfg.WireGuard.IPv6LinkLocal
	}

	// Validate all session IP addresses against security policies
	ipAddresses := []struct {
		ip   string
		name string
	}{
		{session.IPv4, "IPv4"},
		{session.IPv6, "IPv6"},
		{session.IPv6LinkLocal, "IPv6 Link Local"},
	}

	for _, ipAddr := range ipAddresses {
		if allowed, err := validateInterfaceIP(ipAddr.ip); !allowed {
			return fmt.Errorf("%s address %s validation failed: %v", ipAddr.name, ipAddr.ip, err)
		}
	}

	// Configure IPv4 if provided
	if session.IPv4 != "" {
		cmd := exec.CommandContext(ctx, cfg.Bird.IPCommandPath, "addr", "add", "dev", session.Interface,
			localIPv4+"/32", "peer", session.IPv4+"/32")
		ipv4OutputBytes, ipv4Err := cmd.CombinedOutput()
		ipv4Output := string(ipv4OutputBytes)

		if ipv4Err != nil {
			return fmt.Errorf("failed to add IPv4: %v (output: \"%s\")", ipv4Err, strings.TrimSpace(ipv4Output))
		}
	}
	// Configure IPv6 Link-Local if provided
	if session.IPv6LinkLocal != "" {
		cmd := exec.CommandContext(ctx, cfg.Bird.IPCommandPath, "addr", "add", "dev", session.Interface,
			localIPv6LinkLocal+"/64", "peer", session.IPv6LinkLocal+"/64")
		ipv6llOutputBytes, ipv6llErr := cmd.CombinedOutput()
		ipv6llOutput := string(ipv6llOutputBytes)

		if ipv6llErr != nil {
			return fmt.Errorf("failed to add IPv6 link-local: %v (output: \"%s\")", ipv6llErr, strings.TrimSpace(ipv6llOutput))
		}
	}
	// Configure global IPv6 if provided
	if session.IPv6 != "" {
		cmd := exec.CommandContext(ctx, cfg.Bird.IPCommandPath, "addr", "add", "dev", session.Interface,
			localIPv6+"/128", "peer", session.IPv6+"/128")
		ipv6OutputBytes, ipv6Err := cmd.CombinedOutput()
		ipv6Output := string(ipv6OutputBytes)

		if ipv6Err != nil {
			return fmt.Errorf("failed to add IPv6: %v (output: \"%s\")", ipv6Err, strings.TrimSpace(ipv6Output))
		}
	}

	return nil
}

func setIPv6InterfaceRoute(ctx context.Context, session *BgpSession) error {
	// Must be called after the interface is up
	cmd := exec.CommandContext(ctx, cfg.Bird.IPCommandPath, "-6", "route", "add", session.IPv6+"/128", "dev", session.Interface)
	ipv6OutputBytes, ipv6Err := cmd.CombinedOutput()
	ipv6Output := string(ipv6OutputBytes)

	if ipv6Err != nil {
		return fmt.Errorf("failed to add IPv6 route: %v (output: \"%s\")", ipv6Err, strings.TrimSpace(ipv6Output))
	}

	return nil
}

// applySysctlSettings applies sysctl settings to the interface for optimal BGP performance and security
func applySysctlSettings(ctx context.Context, interfaceName string) {
	// Helper function to convert bool to string
	boolToStr := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}

	// Define sysctl parameters with their values and descriptions
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

	// Apply all sysctl parameters
	for param, config := range sysctlParams {
		cmd := exec.CommandContext(ctx, cfg.Sysctl.CommandPath, "-w", fmt.Sprintf("%s=%s", param, config.value))
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[applySysctlSettings] Warning: Failed to set %s for interface %s: %v (output: \"%s\")",
				config.desc, interfaceName, err, strings.TrimSpace(string(output)))
		}
	}
}

func bringUpInterface(ctx context.Context, session *BgpSession) error {
	// Bring up the interface
	cmd := exec.CommandContext(ctx, cfg.Bird.IPCommandPath, "link", "set", "up", "dev", session.Interface)
	outputBytes, err := cmd.CombinedOutput()
	output := string(outputBytes)

	if err != nil {
		return fmt.Errorf("failed to bring up interface %s: %v (output: \"%s\")", session.Interface, err, strings.TrimSpace(output))
	}

	// Set IPv6 route if applicable
	// Linux will not automatically add route for IPv6 ula/gua though we have added peer address
	// for IPv6 link-local, we do not have to do this
	// for IPv4, system will automatically add route for /32 peer address
	if session.IPv6 != "" {
		if err := setIPv6InterfaceRoute(ctx, session); err != nil {
			return fmt.Errorf("failed to set IPv6 dev route for interface: %v", err)
		}
	}

	// Apply sysctl settings for interface
	applySysctlSettings(ctx, session.Interface)

	return nil
}

// deleteInterface removes a network interface, will automatically bring it down first if it exists
func deleteInterface(iface string) error {
	// Set a timeout for commands to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	exist, err := interfaceExists(iface)
	if err != nil {
		log.Printf("Warning: Failed to check if interface %s exists: %v", iface, err)
		// Continue anyway to try deletion
	}

	if err == nil && !exist {
		log.Printf("Interface %s does not exist, no need to delete", iface)
		return nil
	}

	// Bring the interface down first
	downCmd := exec.CommandContext(ctx, cfg.Bird.IPCommandPath, "link", "set", "down", "dev", iface)
	downOutputBytes, downErr := downCmd.CombinedOutput()
	downOutput := string(downOutputBytes)

	if downErr != nil {
		log.Printf("Warning: Failed to bring down interface %s: %v (output: \"%s\")", iface, downErr, strings.TrimSpace(downOutput))
		// Continue with deletion anyway
	}

	// Delete the interface
	delCmd := exec.CommandContext(ctx, cfg.Bird.IPCommandPath, "link", "del", "dev", iface)
	delOutputBytes, delErr := delCmd.CombinedOutput()
	delOutput := string(delOutputBytes)

	if delErr != nil {
		return fmt.Errorf("failed to delete interface %s: %v (output: \"%s\")", iface, delErr, strings.TrimSpace(delOutput))
	}

	log.Printf("Successfully deleted interface %s", iface)
	return nil
}

// configureBird generates and writes the BIRD configuration for a BGP session
func configureBird(session *BgpSession) error {
	confPath := path.Join(cfg.Bird.BGPPeerConfDir, session.Interface+".conf")
	log.Printf("Configuring BIRD for session %s (interface: %s)", session.UUID, session.Interface)

	birdConfMutex.Lock()
	defer birdConfMutex.Unlock()

	// Remove existing config file if it exists
	if err := os.Remove(confPath); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: Failed to remove existing BIRD config at %s: %v", confPath, err)
		// Continue anyway
	}

	// Ensure the template is loaded
	if cfg.Bird.BGPPeerConfTemplate == nil {
		return fmt.Errorf("BIRD peer configuration template is not initialized")
	}

	// Determine community values based on session type
	ifBwCommunity, ifSecCommunity := getCommunityValues(session.Type)

	// Check if MP-BGP or extended nexthop is enabled
	mpBGP := slices.Contains(session.Extensions, "mp-bgp")
	extendedNexthop := slices.Contains(session.Extensions, "extended-nexthop")

	// Create output file
	outFile, err := os.Create(confPath)
	if err != nil {
		return fmt.Errorf("failed to create BIRD config file %s: %v", confPath, err)
	}
	defer outFile.Close()

	// Generate base session name
	sessionName := fmt.Sprintf("DN42_%d_%s", session.ASN, session.Interface)

	// Generate the configuration based on BGP type
	if mpBGP {
		// For MP-BGP, generate a single protocol that handles both IPv4 and IPv6
		if err := generateMPBGPConfig(outFile, session, sessionName, extendedNexthop, ifBwCommunity, ifSecCommunity); err != nil {
			return err
		}
	} else {
		// For traditional BGP, generate separate protocols for IPv4 and IPv6
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

// getCommunityValues returns the bandwidth and security community values based on session type
func getCommunityValues(sessionType string) (int, int) {
	// Default values for unknown session types
	ifBwCommunity := 24
	ifSecCommunity := 31

	// Override defaults for known session types
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

// generateMPBGPConfig creates a single MP-BGP protocol configuration
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

// generateTraditionalBGPConfig creates separate configurations for IPv4 and IPv6 BGP
func generateTraditionalBGPConfig(outFile *os.File, session *BgpSession, sessionName string, extendedNexthop bool, ifBwCommunity, ifSecCommunity int) error {
	// Generate IPv6 config if IPv6 addresses are available
	if session.IPv6LinkLocal != "" || session.IPv6 != "" {
		var interfaceAddr string
		if session.IPv6LinkLocal != "" {
			interfaceAddr = fmt.Sprintf("%s%%'%s'", session.IPv6LinkLocal, session.Interface)
		} else if session.IPv6 != "" {
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

	// Generate IPv4 config if an IPv4 address is available
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

// getNeighborAddress selects the best available interface address for the session
func getNeighborAddress(session *BgpSession) (string, error) {
	// Try to get a suitable interface address in preferred order:
	// 1. IPv6 Link-Local with interface specification
	// 2. Global IPv6
	// 3. IPv4
	if session.IPv6LinkLocal != "" {
		return fmt.Sprintf("%s%%'%s'", session.IPv6LinkLocal, session.Interface), nil
	} else if session.IPv6 != "" {
		return session.IPv6, nil
	} else if session.IPv4 != "" {
		return session.IPv4, nil
	}

	return "", fmt.Errorf("no valid interface addresses for peering session %s", session.UUID)
}

// deleteBird removes the BIRD configuration file for a BGP session
func deleteBird(session *BgpSession) error {
	confPath := path.Join(cfg.Bird.BGPPeerConfDir, session.Interface+".conf")
	log.Printf("Removing BIRD configuration for session %s (interface: %s)", session.UUID, session.Interface)

	birdConfMutex.Lock()
	defer birdConfMutex.Unlock()

	if err := os.Remove(confPath); err != nil {
		if os.IsNotExist(err) {
			// If file doesn't exist, no need to return an error
			log.Printf("BIRD configuration file %s does not exist, nothing to remove", confPath)
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

// configureSession sets up both the network interface and BIRD configuration for a BGP session
func configureSession(session *BgpSession) error {
	// First, configure the network interface
	if err := configureInterface(session); err != nil {
		return fmt.Errorf("interface configuration failed: %w", err)
	}

	// Then, configure the BIRD routing daemon
	if err := configureBird(session); err != nil {
		return fmt.Errorf("BIRD configuration failed: %w", err)
	}

	return nil
}

// deleteSession tears down a BGP session by removing both the interface and BIRD configuration
func deleteSession(session *BgpSession) error {
	// First, delete the network interface
	var interfaceErr error
	if err := deleteInterface(session.Interface); err != nil {
		log.Printf("Warning: Failed to delete interface %s: %v", session.Interface, err)
		interfaceErr = err
		// Continue with BIRD config removal even if interface deletion fails
	}

	// Then, delete the BIRD configuration
	birdErr := deleteBird(session)

	// Return interface error if it occurred, otherwise return BIRD error (if any)
	if interfaceErr != nil {
		return interfaceErr
	}

	if birdErr != nil {
		return birdErr
	}

	return nil
}
