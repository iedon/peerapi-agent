package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
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

// bandwidthMonitorTask runs every second to monitor bandwidth usage
func bandwidthMonitorTask(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			shutdownStart := time.Now()
			log.Println("[BandwidthMonitor] Shutting down bandwidth monitoring task...")

			// Perform any bandwidth-specific cleanup
			trafficMutex.Lock()
			log.Printf("[BandwidthMonitor] Cleaning up traffic data for %d interfaces", len(localTrafficRate))
			trafficMutex.Unlock()

			log.Printf("[BandwidthMonitor] Bandwidth monitoring task shutdown completed in %v", time.Since(shutdownStart))
			return
		case <-ticker.C:
			monitorTrafficRates()
		}
	}
}

// monitorTrafficRates calculates traffic rates for all network interfaces
func monitorTrafficRates() {
	// Get initial statistics
	stats1, err1 := readNetStats()
	if err1 != nil {
		log.Printf("[BandwidthMonitor] Error reading network stats: %v\n", err1)
		return
	}

	// Wait 1 second to calculate delta
	time.Sleep(1 * time.Second)

	// Get updated statistics
	stats2, err2 := readNetStats()
	if err2 != nil {
		log.Printf("[BandwidthMonitor] Error reading network stats: %v\n", err2)
		return
	}

	// Process traffic data and update under trafficMutex protection
	trafficMutex.Lock()
	defer trafficMutex.Unlock()

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
		rate, exist := localTrafficRate[iface]
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
		localTrafficRate[iface] = rate
	}

	// Also check for new interfaces in stats2 that weren't in stats1
	for iface := range stats2 {
		if _, ok := stats1[iface]; !ok {
			// New interface appeared, initialize with zeros
			localTrafficRate[iface] = TrafficRate{
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
		return nil, fmt.Errorf("failed to open /proc/net/dev: %v", err)
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
		return nil, fmt.Errorf("error scanning /proc/net/dev: %v", err)
	}

	return stats, nil
}

// heartbeatTask sends periodic heartbeats to the PeerAPI server
func heartbeatTask(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(time.Duration(cfg.PeerAPI.HeartbeatInterval) * time.Second)
	defer ticker.Stop()

	uname := getOsUname()
	httpClient := &http.Client{
		Timeout: time.Duration(cfg.PeerAPI.RequestTimeout) * time.Second,
	}

	// Send an initial heartbeat immediately
	sendHeartbeat(httpClient, uname)

	for {
		select {
		case <-ctx.Done():
			shutdownStart := time.Now()
			log.Println("[HeartBeat] Shutting down heartbeat task...")

			// Send one final status update with offline flag
			// We could implement this feature in the future if needed

			log.Printf("[HeartBeat] Heartbeat task shutdown completed in %v", time.Since(shutdownStart))
			return
		case <-ticker.C:
			sendHeartbeat(httpClient, uname)
		}
	}
}

// sendHeartbeat sends a heartbeat message to the PeerAPI server
func sendHeartbeat(httpClient *http.Client, uname string) {
	url := fmt.Sprintf("%s/agent/%s/heartbeat", cfg.PeerAPI.APIURL, cfg.PeerAPI.RouterUUID)
	token, err := generateToken()
	if err != nil {
		log.Printf("[HeartBeat] Failed to generate token: %v\n", err)
		return
	}

	routerSoftware, _ := birdPool.ShowStatus()
	rx, tx, _ := getInterfaceTraffic(cfg.PeerAPI.WanInterfaces)

	// Prepare request body
	requestBody := map[string]any{
		"version":   SERVER_SIGNATURE,
		"kernel":    uname,
		"loadAvg":   getLoadAverageStr(),
		"uptime":    getUptimeSeconds(),
		"rs":        routerSoftware,
		"tx":        tx,
		"rx":        rx,
		"tcp":       getTcpConnections(),
		"udp":       getUdpConnections(),
		"timestamp": time.Now().UnixMilli(),
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		log.Printf("[HeartBeat] Failed to marshal request body: %v\n", err)
		return
	}

	// Create request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Printf("[HeartBeat] Failed to create request: %v\n", err)
		return
	}

	// Set headers
	setHTTPClientHeader(req, token, true)

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("[HeartBeat] Failed to send heartbeat: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[HeartBeat] Server returned status code: %d\n", resp.StatusCode)
	}
}
