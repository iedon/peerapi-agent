package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"slices"
	"sync"
	"time"
)

// MetricJob represents a single metric collection job
type MetricJob struct {
	Session   BgpSession
	Timestamp int64
}

// MetricResult represents the result of metric collection for one session
type MetricResult struct {
	UUID   string
	Metric SessionMetric
	Error  error
}

// collectMetrics collects metrics for all sessions or a specific session using optimized worker pools
func collectMetrics() {
	now := time.Now().Unix()

	// Get active sessions first
	sessionMutex.RLock()
	activeSessions := make([]BgpSession, 0, len(localSessions))
	for _, s := range localSessions {
		if s.Status == PEERING_STATUS_ENABLED || s.Status == PEERING_STATUS_PROBLEM {
			activeSessions = append(activeSessions, s)
		}
	}
	sessionMutex.RUnlock()

	if len(activeSessions) == 0 {
		log.Println("[Metrics] No active sessions to collect metrics from.")
		return
	}

	// Use concurrent processing for metric collection
	newSessionMetrics := batchCollectSessionMetrics(activeSessions, now)

	if len(newSessionMetrics) == 0 {
		log.Println("[Metrics] No metrics collected from active sessions.")
		return
	}

	// Update the local metric map with the latest metrics
	metricMutex.Lock()
	maps.Copy(localMetrics, newSessionMetrics)
	metricMutex.Unlock()

	// Send metrics to PeerAPI
	sendMetricsToPeerAPI(newSessionMetrics)
}

// batchCollectSessionMetrics collects metrics for multiple sessions concurrently
func batchCollectSessionMetrics(sessions []BgpSession, timestamp int64) map[string]SessionMetric {
	if len(sessions) == 0 {
		return make(map[string]SessionMetric)
	}

	startTime := time.Now()

	// Create worker pool for concurrent session processing
	workerCount := min(len(sessions), cfg.Metric.SessionWorkerCount)
	if workerCount == 0 {
		workerCount = min(len(sessions), 8) // Default fallback
	}

	jobs := make(chan MetricJob, len(sessions))
	results := make(chan MetricResult, len(sessions))

	// Start worker goroutines
	var wg sync.WaitGroup
	for range workerCount {
		wg.Add(1)
		go metricWorker(jobs, results, &wg)
	}

	// Send jobs to workers
	for _, session := range sessions {
		jobs <- MetricJob{
			Session:   session,
			Timestamp: timestamp,
		}
	}
	close(jobs)

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	newSessionMetrics := make(map[string]SessionMetric, len(sessions))
	for result := range results {
		if result.Error != nil {
			log.Printf("[Metrics] Failed to collect metrics for session %s: %v", result.UUID, result.Error)
			continue
		}
		newSessionMetrics[result.UUID] = result.Metric
	}

	duration := time.Since(startTime)
	log.Printf("[Metrics] Collected metrics for %d sessions using %d workers in %v",
		len(newSessionMetrics), workerCount, duration)

	return newSessionMetrics
}

// metricWorker processes metric collection jobs concurrently
func metricWorker(jobs <-chan MetricJob, results chan<- MetricResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		result := MetricResult{
			UUID: job.Session.UUID,
		}

		// Collect metrics for this session
		metric, err := collectSessionMetric(job.Session, job.Timestamp)
		if err != nil {
			result.Error = err
		} else {
			result.Metric = metric
		}

		results <- result
	}
}

// collectSessionMetric collects metrics for a single session by querying BIRD directly
func collectSessionMetric(session BgpSession, timestamp int64) (SessionMetric, error) {
	sessionName := fmt.Sprintf("DN42_%d_%s", session.ASN, session.Interface)
	mpBGP := slices.Contains(session.Extensions, "mp-bgp")

	var bgpMetrics []BGPMetric

	// Collect BGP metrics by querying BIRD directly
	if mpBGP {
		// For MP-BGP, query the single session
		state, since, info, ipv4Import, ipv4Export, ipv6Import, ipv6Export, err := birdPool.GetProtocolStatus(sessionName)
		if err != nil {
			// Create default metrics on error
			bgpMetrics = []BGPMetric{
				createBGPMetric(sessionName, "Unknown", fmt.Sprintf("Query error: %v", err), BGP_SESSION_TYPE_MPBGP, "", 0, 0, 0, 0),
			}
		} else {
			bgpMetrics = []BGPMetric{
				createBGPMetric(sessionName, state, info, BGP_SESSION_TYPE_MPBGP,
					since,
					int(ipv4Import), int(ipv4Export),
					int(ipv6Import), int(ipv6Export)),
			}
		}
	} else {
		// For traditional BGP, query v4 and v6 sessions separately
		bgpMetrics = make([]BGPMetric, 0, 2)

		if session.IPv6LinkLocal != "" || session.IPv6 != "" {
			v6Name := sessionName + "_v6"
			state, since, info, _, _, ipv6Import, ipv6Export, err := birdPool.GetProtocolStatus(v6Name)
			if err != nil {
				bgpMetrics = append(bgpMetrics, createBGPMetric(v6Name, "Unknown", fmt.Sprintf("Query error: %v", err), BGP_SESSION_TYPE_IPV6, "", 0, 0, 0, 0))
			} else {
				bgpMetrics = append(bgpMetrics, createBGPMetric(v6Name, state, info, BGP_SESSION_TYPE_IPV6, since,
					0, 0, int(ipv6Import), int(ipv6Export)))
			}
		}

		if session.IPv4 != "" {
			v4Name := sessionName + "_v4"
			state, since, info, ipv4Import, ipv4Export, _, _, err := birdPool.GetProtocolStatus(v4Name)
			if err != nil {
				bgpMetrics = append(bgpMetrics, createBGPMetric(v4Name, "Unknown", fmt.Sprintf("Query error: %v", err), BGP_SESSION_TYPE_IPV4, "", 0, 0, 0, 0))
			} else {
				bgpMetrics = append(bgpMetrics, createBGPMetric(v4Name, state, info, BGP_SESSION_TYPE_IPV4, since,
					int(ipv4Import), int(ipv4Export), 0, 0))
			}
		}
	}

	// Get interface traffic statistics from /proc/net/dev
	rx, tx, _ := getInterfaceTraffic([]string{session.Interface})

	// Get current traffic rates from localTrafficRate
	rxRate, txRate := getTrafficRates(session.Interface)

	// Generate latest metric
	metric := generateSessionMetric(session, timestamp, bgpMetrics, rx, tx, rxRate, txRate)

	return metric, nil
}

// sendMetricsToPeerAPI sends collected metrics to the PeerAPI server
func sendMetricsToPeerAPI(metrics map[string]SessionMetric) {
	startTime := time.Now()

	if len(metrics) == 0 {
		return
	}

	url := fmt.Sprintf("%s/agent/%s/report", cfg.PeerAPI.APIURL, cfg.PeerAPI.RouterUUID)
	token, err := generateToken()
	if err != nil {
		log.Printf("[Metrics] Failed to generate token: %v\n", err)
		return
	}

	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: time.Duration(cfg.PeerAPI.RequestTimeout) * time.Second,
	}

	// Convert metrics map to array
	sessionMutex.RLock()
	metricsArray := make([]SessionMetric, 0, len(metrics))
	for _, metric := range metrics {
		metricsArray = append(metricsArray, metric)
	}
	sessionMutex.RUnlock()

	// Log the metrics being sent for debugging
	log.Printf("[Metrics] Sending %d session metrics to PeerAPI...", len(metricsArray))

	// Create request body
	requestBody := map[string]any{
		"metrics": metricsArray,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		log.Printf("[Metrics] Failed to marshal request body: %v", err)
		return
	}

	// Create request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Printf("[Metrics] Failed to create request: %v", err)
		return
	}

	// Set headers
	setHTTPClientHeader(req, token, true)

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("[Metrics] Failed to send metrics to %s: %v (took %v)", url, err, time.Since(startTime))
		return
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyText := string(bodyBytes)
		log.Printf("[Metrics] Failed to send metrics, status code: %d, response body: %s (took %v)",
			resp.StatusCode, bodyText, time.Since(startTime))
		return
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[Metrics] Failed to read response body: %v (took %v)", err, time.Since(startTime))
		return
	}

	// Parse response
	var response PeerApiResponse
	if err := json.Unmarshal(body, &response); err != nil {
		log.Printf("[Metrics] Failed to parse response: %v, response body: %s (took %v)",
			err, string(body), time.Since(startTime))
		return
	}

	// Check API response code
	if response.Code != 0 {
		log.Printf("[Metrics] PeerAPI returned error: %s (code: %d, took %v)",
			response.Message, response.Code, time.Since(startTime))
		return
	}

	// Success - log completion
	log.Printf("[Metrics] Successfully sent %d session metrics to PeerAPI (took %v)",
		len(metricsArray), time.Since(startTime))
}

// createBGPMetric creates a BGP metric object with the given parameters
func createBGPMetric(name, state, info, sessionType, since string, ipv4Import, ipv4Export, ipv6Import, ipv6Export int) BGPMetric {
	return BGPMetric{
		Name:  name,
		State: state,
		Info:  info,
		Type:  sessionType,
		Since: since,
		Routes: BGPRoutesMetric{
			IPv4: RouteMetricStruct{
				Imported: RouteMetrics{
					Current: ipv4Import,
				},
				Exported: RouteMetrics{
					Current: ipv4Export,
				},
			},
			IPv6: RouteMetricStruct{
				Imported: RouteMetrics{
					Current: ipv6Import,
				},
				Exported: RouteMetrics{
					Current: ipv6Export,
				},
			},
		},
	}
}

// getTrafficRates retrieves current traffic rates for an interface
func getTrafficRates(interfaceName string) (int64, int64) {
	var rxRate, txRate int64 = 0, 0
	trafficMutex.RLock()
	if trafficRate, exists := localTrafficRate[interfaceName]; exists {
		rxRate = int64(trafficRate.RxRate)
		txRate = int64(trafficRate.TxRate)
	}
	trafficMutex.RUnlock()

	return rxRate, txRate
}

// generateSessionMetric creates and initializes a new session metric
func generateSessionMetric(session BgpSession, timestamp int64, bgpMetrics []BGPMetric, rx, tx uint64, rxRate, txRate int64) SessionMetric {
	// Get RTT value from the RTT tracker
	rttValue, lossRate := getRTTValue(session.UUID)

	return SessionMetric{
		UUID:      session.UUID,
		ASN:       session.ASN,
		Timestamp: timestamp,
		BGP:       bgpMetrics,
		Interface: InterfaceMetric{
			IPv4:          session.IPv4,
			IPv6:          session.IPv6,
			IPv6LinkLocal: session.IPv6LinkLocal,
			MAC: func() string {
				mac, _ := getInterfaceMAC(session.Interface)
				return mac
			}(),
			MTU: func() int {
				mtu, _ := getInterfaceMTU(session.Interface)
				if mtu <= 0 {
					mtu = session.MTU
				}
				return mtu
			}(),
			Status: func() string {
				flags, _ := getInterfaceFlags(session.Interface)
				return flags
			}(),
			Traffic: InterfaceTrafficMetric{
				Total:   []int64{int64(tx), int64(rx)}, // [Tx, Rx] - total bytes
				Current: []int64{txRate, rxRate},       // [Tx, Rx] - current rate in bytes per second
			},
		},
		RTT: RTT{
			Current: rttValue,
			Loss:    lossRate,
		},
	}
}

// metricTask schedules periodic metrics collection
func metricTask(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	// Start the regular metrics collection
	ticker := time.NewTicker(time.Duration(cfg.PeerAPI.MetricInterval) * time.Second)
	defer ticker.Stop()

	// Collect metrics immediately on startup
	collectMetrics()

	for {
		select {
		case <-ctx.Done():
			shutdownStart := time.Now()
			log.Println("[Metrics] Shutting down metrics collection task...")

			// Perform any cleanup specific to metrics
			metricMutex.Lock()
			log.Printf("[Metrics] Cleaning up %d metric entries", len(localMetrics))
			metricMutex.Unlock()

			log.Printf("[Metrics] Metrics collection task shutdown completed in %v", time.Since(shutdownStart))
			return
		case <-ticker.C:
			collectMetrics()
		}
	}
}
