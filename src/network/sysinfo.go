package network

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/matishsiao/goInfo"
)

// GetOsUname returns OS kernel information
func GetOsUname() string {
	gi, _ := goInfo.GetInfo()
	platform := gi.Platform
	if strings.ToLower(platform) == "unknown" {
		platform = runtime.GOARCH
	}
	return fmt.Sprintf("%s %s %s", gi.Kernel, gi.Core, platform)
}

// countConnections reads connection count from /proc filesystem
func countConnections(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		// It's fine if the system doesn't support IPv6, just return 0
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0

	firstLine := true
	for scanner.Scan() {
		if firstLine {
			firstLine = false // skip header
			continue
		}
		count++
	}
	return count, scanner.Err()
}

// GetTcpConnections returns total count of TCP connections (IPv4 + IPv6)
func GetTcpConnections() int {
	tcp4, _ := countConnections("/proc/net/tcp")
	tcp6, _ := countConnections("/proc/net/tcp6")
	return tcp4 + tcp6
}

// GetUdpConnections returns total count of UDP connections (IPv4 + IPv6)
func GetUdpConnections() int {
	udp4, _ := countConnections("/proc/net/udp")
	udp6, _ := countConnections("/proc/net/udp6")
	return udp4 + udp6
}

// GetUptimeSeconds returns system uptime in seconds
func GetUptimeSeconds() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	parts := strings.Fields(string(data))
	if len(parts) < 1 {
		return 0
	}
	uptime, _ := strconv.ParseFloat(parts[0], 64)
	return uptime
}

// GetLoadAverage returns system load averages (1min, 5min, 15min)
func GetLoadAverage() (load1, load5, load15 float64, err error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, err
	}

	parts := strings.Fields(string(data))
	if len(parts) < 3 {
		return 0, 0, 0, fmt.Errorf("unexpected format: %s", data)
	}

	load1, err = strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return
	}
	load5, err = strconv.ParseFloat(parts[1], 64)
	if err != nil {
		return
	}
	load15, err = strconv.ParseFloat(parts[2], 64)
	return
}

// GetLoadAverageStr returns formatted load average string
func GetLoadAverageStr() string {
	load1, load5, load15, err := GetLoadAverage()
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%.2f %.2f %.2f", load1, load5, load15)
}
