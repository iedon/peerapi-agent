package network

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// GetWireGuardPeerEndpoint gets the actual endpoint for a WireGuard interface/peer combination
// Returns the endpoint address (host:port) or empty string if not found
func GetWireGuardPeerEndpoint(wgCommandPath, interfaceName, publicKey string) (string, error) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Run 'wg show <interface> endpoints'
	cmd := exec.CommandContext(ctx, wgCommandPath, "show", interfaceName, "endpoints")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get WireGuard endpoints for interface %s: %w", interfaceName, err)
	}

	// Parse the output to find the endpoint for our public key
	// Output format: <public_key>\t<endpoint>
	lines := strings.SplitSeq(string(output), "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			continue
		}

		if strings.TrimSpace(parts[0]) == publicKey {
			endpoint := strings.TrimSpace(parts[1])
			return endpoint, nil
		}
	}

	// If we don't find the public key, return empty
	return "", nil
}

// GetWireGuardLastHandshake gets the last handshake time for a WireGuard peer
// Returns Unix timestamp and error
func GetWireGuardLastHandshake(wgCommandPath, interfaceName, publicKey string) (int64, error) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Run 'wg show <interface> latest-handshakes'
	cmd := exec.CommandContext(ctx, wgCommandPath, "show", interfaceName, "latest-handshakes")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("failed to get WireGuard handshakes for interface %s: %w", interfaceName, err)
	}

	// Parse the output to find the handshake time for our public key
	// Output format: <public_key>\t<timestamp>
	lines := strings.SplitSeq(string(output), "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			continue
		}

		if strings.TrimSpace(parts[0]) == publicKey {
			var timestamp int64
			_, err := fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &timestamp)
			if err != nil {
				return 0, fmt.Errorf("failed to parse handshake timestamp: %w", err)
			}
			return timestamp, nil
		}
	}

	return 0, fmt.Errorf("peer %s not found", publicKey)
}

// UpdateWireGuardEndpoint updates the endpoint for a WireGuard peer
func UpdateWireGuardEndpoint(wgCommandPath, interfaceName, publicKey, newEndpoint string) error {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Validate new endpoint format
	if _, _, err := net.SplitHostPort(newEndpoint); err != nil {
		return fmt.Errorf("invalid endpoint format %s: %w", newEndpoint, err)
	}

	// Run 'wg set <interface> peer <public_key> endpoint <endpoint>'
	cmd := exec.CommandContext(ctx, wgCommandPath, "set", interfaceName, "peer", publicKey, "endpoint", newEndpoint)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update WireGuard endpoint: %w, output: %s", err, string(output))
	}

	return nil
}
