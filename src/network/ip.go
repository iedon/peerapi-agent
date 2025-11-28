package network

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

var (
	reservedPorts      = make(map[int]int64)
	reservedPortsMutex sync.Mutex
)

// ValidateInterfaceIP checks if an IP address is allowed for interface assignment
// Returns true if the IP is allowed, false if it should be blocked
func ValidateInterfaceIP(ipAddr string, allowPublic bool, blacklist []string) (bool, error) {
	if ipAddr == "" {
		return true, nil // Empty IP is allowed
	}

	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %s", ipAddr)
	}

	// Check if public IPs are allowed
	if !allowPublic {
		// Check if it's a public IP
		if IsPublicIP(ip) {
			return false, fmt.Errorf("public IP addresses are not allowed: %s", ipAddr)
		}
	}

	// Check blacklist
	for _, blacklistEntry := range blacklist {
		if IsIPInCIDR(ipAddr, blacklistEntry) {
			return false, fmt.Errorf("IP %s is in blacklist range: %s", ipAddr, blacklistEntry)
		}
	}

	return true, nil
}

// IsPublicIP checks if an IP address is in public IP ranges
func IsPublicIP(ip net.IP) bool {
	// Define private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"127.0.0.0/8",    // Loopback
		"169.254.0.0/16", // Link-local
		"100.64.0.0/10",  // Carrier-grade NAT
		"224.0.0.0/4",    // Multicast
		"100.64.0.0/10",  // Carrier-grade NAT
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local
		"ff00::/8",       // IPv6 multicast
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return false // It's private, not public
		}
	}

	return true // It's public
}

// IsIPInCIDR checks if an IP address is within a CIDR range
func IsIPInCIDR(ipAddr, cidr string) bool {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return false
	}

	// Handle single IP case (no CIDR notation)
	if !strings.Contains(cidr, "/") {
		blacklistIP := net.ParseIP(cidr)
		if blacklistIP == nil {
			return false
		}
		return ip.Equal(blacklistIP)
	}

	// Handle CIDR case
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	return network.Contains(ip)
}

// ExtractHost parses input string (with or without port) and extracts IP/hostname
func ExtractHost(addr string) string {
	// Handle IPv6 [::1]:443
	if strings.HasPrefix(addr, "[") {
		if i := strings.Index(addr, "]"); i != -1 {
			return addr[1:i]
		}
	}
	// For host:port
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr // No port
}

// ResolveToIP resolves hostname to IP
func ResolveToIP(host string) (net.IP, error) {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, err
	}
	return ips[0], nil // fallback to first (IPv6)
}

// GeoIPCountryCode returns the 2-letter country code from IP/hostname
func GeoIPCountryCode(db *geoip2.Reader, input string) (string, error) {
	host := ExtractHost(input)
	ip, err := ResolveToIP(host)
	if err != nil {
		return "", err
	}
	record, err := db.Country(ip)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(record.Country.IsoCode), nil
}

// _getRandomUnusedPort returns a random unused port based on protocol ("tcp" or "udp")
func _getRandomUnusedPort(proto string) (int, error) {
	var addr *net.UDPAddr
	var err error

	switch proto {
	case "tcp":
		// Use port :0 to let the OS choose a free port
		l, err := net.Listen("tcp", ":0")
		if err != nil {
			return 0, err
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port, nil
	case "udp":
		addr, err = net.ResolveUDPAddr("udp", ":0")
		if err != nil {
			return 0, err
		}
		c, err := net.ListenUDP("udp", addr)
		if err != nil {
			return 0, err
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port, nil
	default:
		return 0, fmt.Errorf("unsupported protocol: %s", proto)
	}
}

// GetRandomUnusedPort returns a random unused port based on protocol ("tcp" or "udp")
// It also reserves the port for 5 minutes to prevent race conditions
func GetRandomUnusedPort(proto string) (int, error) {
	const maxRetries = 10

	for range maxRetries {
		port, err := _getRandomUnusedPort(proto)
		if err != nil {
			return 0, fmt.Errorf("failed to get random unused port: %w", err)
		}
		reservedPortsMutex.Lock()
		if expireTimestamp, exists := reservedPorts[port]; exists {
			if time.Now().Unix() < expireTimestamp {
				// Port is reserved, skip it
				reservedPortsMutex.Unlock()
				continue // try again
			}
		}
		reservedPorts[port] = time.Now().Unix() + 300
		reservedPortsMutex.Unlock()
		return port, nil
	}

	return 0, fmt.Errorf("unable to find unused port after %d attempts", maxRetries)
}
