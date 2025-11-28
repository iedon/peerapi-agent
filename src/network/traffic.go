package network

import (
	"bufio"
	"fmt"
	"maps"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iedon/peerapi-agent/logger"
)

// NetStat stores network interface statistics
type NetStat struct {
	Name    string
	RxBytes uint64
	TxBytes uint64
}

// TrafficRate stores network interface traffic rates
type TrafficRate struct {
	Name   string
	RxRate uint64 // in bytes per second
	TxRate uint64 // in bytes per second
}

// TrafficMonitor monitors network interface traffic
type TrafficMonitor struct {
	mu     sync.RWMutex
	rates  map[string]TrafficRate
	logger *logger.Logger
}

// NewTrafficMonitor creates a new traffic monitor
func NewTrafficMonitor(log *logger.Logger) *TrafficMonitor {
	return &TrafficMonitor{
		rates:  make(map[string]TrafficRate),
		logger: log,
	}
}

// GetRate retrieves the traffic rate for an interface
func (tm *TrafficMonitor) GetRate(iface string) (TrafficRate, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	rate, exists := tm.rates[iface]
	return rate, exists
}

// GetAllRates returns all traffic rates
func (tm *TrafficMonitor) GetAllRates() map[string]TrafficRate {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	result := make(map[string]TrafficRate, len(tm.rates))
	maps.Copy(result, tm.rates)
	return result
}

// GetRates retrieves the traffic rates for an interface as int64 values
func (tm *TrafficMonitor) GetRates(iface string) (rxRate, txRate int64) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	if rate, exists := tm.rates[iface]; exists {
		return int64(rate.RxRate), int64(rate.TxRate)
	}
	return 0, 0
}

// MonitorRates calculates traffic rates for all network interfaces
func (tm *TrafficMonitor) MonitorRates() {
	// Get initial statistics
	stats1, err1 := readNetStats()
	if err1 != nil {
		tm.logger.Warn("Error reading network stats: %v", err1)
		return
	}

	// Wait 1 second to calculate delta
	time.Sleep(1 * time.Second)

	// Get updated statistics
	stats2, err2 := readNetStats()
	if err2 != nil {
		tm.logger.Warn("Error reading network stats: %v", err2)
		return
	}

	// Process traffic data and update under mutex protection
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Calculate traffic rates for each interface
	for iface, s1 := range stats1 {
		s2, ok := stats2[iface]
		if !ok {
			continue
		}

		// Calculate traffic rates (bytes per second)
		rxRate := s2.RxBytes - s1.RxBytes
		txRate := s2.TxBytes - s1.TxBytes

		// Create or update the traffic rate for this interface
		rate, exist := tm.rates[iface]
		if !exist {
			rate = TrafficRate{
				Name:   iface,
				RxRate: rxRate,
				TxRate: txRate,
			}
		} else {
			rate.RxRate = rxRate
			rate.TxRate = txRate
		}
		tm.rates[iface] = rate
	}

	// Also check for new interfaces in stats2 that weren't in stats1
	for iface := range stats2 {
		if _, ok := stats1[iface]; !ok {
			// New interface appeared, initialize with zeros
			tm.rates[iface] = TrafficRate{
				Name:   iface,
				RxRate: 0,
				TxRate: 0,
			}
		}
	}
}

// readNetStats reads network interface statistics from /proc/net/dev
func readNetStats() (map[string]NetStat, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/net/dev: %w", err)
	}
	defer file.Close()

	stats := make(map[string]NetStat)
	scanner := bufio.NewScanner(file)

	// Skip headers (first two lines)
	for i := 0; i < 2 && scanner.Scan(); i++ {
	}

	// Process each line (one per interface)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)

		if len(fields) < 17 {
			continue
		}

		// Extract interface name and stats
		iface := strings.TrimSuffix(fields[0], ":")
		rxBytes, _ := strconv.ParseUint(fields[1], 10, 64)
		txBytes, _ := strconv.ParseUint(fields[9], 10, 64)

		stats[iface] = NetStat{
			Name:    iface,
			RxBytes: rxBytes,
			TxBytes: txBytes,
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning /proc/net/dev: %w", err)
	}

	return stats, nil
}

// GetInterfaceTraffic returns total RX/TX bytes for specified interfaces
func GetInterfaceTraffic(interfaces []string) (rxTotal, txTotal uint64, err error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	ifaceSet := make(map[string]struct{})
	for _, iface := range interfaces {
		ifaceSet[iface] = struct{}{}
	}

	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		if lineCount <= 2 {
			// Skip headers
			continue
		}

		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if _, ok := ifaceSet[iface]; !ok {
			continue
		}

		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}

		// RX bytes = fields[0], TX bytes = fields[8]
		var rx, tx uint64
		fmt.Sscanf(fields[0], "%d", &rx)
		fmt.Sscanf(fields[8], "%d", &tx)

		rxTotal += rx
		txTotal += tx
	}

	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}

	return rxTotal, txTotal, nil
}
