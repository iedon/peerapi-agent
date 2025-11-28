package network

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// PingAverage performs ICMP ping and returns average RTT and packet loss
func PingAverage(address string, tries, timeoutSeconds int, pingCommandPath string) (int, float64) {
	rtt, loss, err := systemPing(address, tries, timeoutSeconds, pingCommandPath)
	if err != nil {
		return -1, 1.0
	}
	return rtt, loss
}

// systemPing executes the system (Linux iputils-ping) native ping command and parses the result
func systemPing(address string, count, timeoutSeconds int, pingCommandPath string) (int, float64, error) {
	// Determine if we're dealing with IPv6
	isIPv6 := strings.Contains(address, ":") || strings.Contains(address, "%")

	// Build ping command arguments
	var args []string
	if isIPv6 {
		args = append(args, "-6") // Force IPv6
	} else {
		args = append(args, "-4") // Force IPv4
	}

	// Add common arguments
	const interval float64 = 0.2                                          // interval seconds between packets (200ms)
	args = append(args, "-c", strconv.Itoa(count))                        // packet count
	args = append(args, "-W", strconv.Itoa(timeoutSeconds))               // timeout per packet
	args = append(args, "-i", strconv.FormatFloat(interval, 'f', -1, 64)) // interval between packets (200ms)
	args = append(args, "-q")                                             // quiet mode (only summary)
	args = append(args, address)                                          // target address

	// Create context with timeout (add another 5 seconds buffer to deadline)
	deadline := timeoutSeconds*count + int(float64(count)*interval) + 5 // deadline in seconds
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(deadline)*time.Second)
	defer cancel()

	// Execute ping command
	cmd := exec.CommandContext(ctx, pingCommandPath, args...)

	// Capture both stdout and stderr
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if it's a timeout or context cancellation
		if ctx.Err() == context.DeadlineExceeded {
			return -1, 1.0, fmt.Errorf("ping timeout")
		}
		// For other errors (host unreachable, etc.), try to parse what we can
		if len(output) > 0 {
			return parsePingOutput(string(output))
		}
		return -1, 1.0, fmt.Errorf("ping failed: %w", err)
	}

	return parsePingOutput(string(output))
}

// parsePingOutput parses the output from the ping command
func parsePingOutput(output string) (int, float64, error) {
	// Example output:
	// PING 172.23.91.1 (172.23.91.1) 56(84) bytes of data.
	//
	// --- 172.23.91.1 ping statistics ---
	// 4 packets transmitted, 4 received, 0% packet loss, time 3081ms
	// rtt min/avg/max/mdev = 0.392/0.426/0.503/0.044 ms

	lines := strings.Split(output, "\n")

	var packetLoss float64 = 1.0 // Default to 100% loss
	var avgRTT int = -1          // Default to -1 (no RTT)

	// Parse packet loss from statistics line
	packetLossRegex := regexp.MustCompile(`(\d+)% packet loss`)
	rttRegex := regexp.MustCompile(`rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms`)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse packet loss
		if matches := packetLossRegex.FindStringSubmatch(line); len(matches) > 1 {
			if lossPercent, err := strconv.Atoi(matches[1]); err == nil {
				packetLoss = float64(lossPercent) / 100.0
			}
		}

		// Parse RTT statistics
		if matches := rttRegex.FindStringSubmatch(line); len(matches) > 2 {
			if avgFloat, err := strconv.ParseFloat(matches[2], 64); err == nil {
				avgRTT = int(avgFloat) // Convert to milliseconds
			}
		}
	}

	// If we got 100% packet loss, return -1 for RTT
	if packetLoss >= 1.0 {
		return -1, 1.0, nil
	}

	// If we couldn't parse RTT but had some successful packets, estimate from packet loss
	if avgRTT == -1 && packetLoss < 1.0 {
		return -1, packetLoss, fmt.Errorf("could not parse RTT from ping output")
	}

	return avgRTT, packetLoss, nil
}
