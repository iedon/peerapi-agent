package session

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
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

// ValidateSession performs comprehensive validation of all session inputs
func ValidateSession(session *Session) error {
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

// validateIPAddressIfGiven validates IPv4 and IPv6 addresses
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
