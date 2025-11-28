package metrics

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/iedon/peerapi-agent/config"
	"github.com/iedon/peerapi-agent/logger"
	"github.com/iedon/peerapi-agent/network"
	"github.com/iedon/peerapi-agent/session"
)

// RTTManager manages RTT measurements for all sessions
type RTTManager struct {
	mu              sync.RWMutex
	trackers        map[string]*RTTTracker
	failedPingCache map[string]time.Time
	cfg             *config.Config
	logger          *logger.Logger
	pingCommandPath string
}

// NewRTTManager creates a new RTT manager
func NewRTTManager(cfg *config.Config, log *logger.Logger) *RTTManager {
	return &RTTManager{
		trackers:        make(map[string]*RTTTracker),
		failedPingCache: make(map[string]time.Time),
		cfg:             cfg,
		logger:          log,
		pingCommandPath: cfg.Metric.PingCommandPath,
	}
}

// GetRTTValue retrieves the RTT value for a session
func (r *RTTManager) GetRTTValue(sessionUUID string) (int, float64) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tracker, exists := r.trackers[sessionUUID]
	if exists {
		return tracker.LastRTT, tracker.AvgLoss
	}

	return -1, 1.0 // Default to -1 RTT and 100% loss if no tracker exists
}

// GetHistoricalAverageRTT calculates the average RTT from historical measurements
// This filters out failed pings (≤ 0) and returns the average of successful measurements
func (r *RTTManager) GetHistoricalAverageRTT(sessionUUID string) (int, float64) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tracker, exists := r.trackers[sessionUUID]
	if !exists || len(tracker.Metric) == 0 {
		return -1, 1.0
	}

	// Filter out invalid RTT values (failed pings)
	var validRTTs []int
	for _, rtt := range tracker.Metric {
		if rtt > 0 {
			validRTTs = append(validRTTs, rtt)
		}
	}

	if len(validRTTs) == 0 {
		return -1, 1.0 // No successful measurements
	}

	// Calculate average RTT from valid measurements
	var sum int
	for _, rtt := range validRTTs {
		sum += rtt
	}
	avgRTT := sum / len(validRTTs)

	return avgRTT, tracker.AvgLoss
}

// MeasureRTT tries to use the most recently successful IP protocol first, before falling back to others
func (r *RTTManager) MeasureRTT(sessionUUID, ipv4, ipv6, ipv6ll string) int {
	// Check if we have a preferred protocol for this session
	r.mu.RLock()
	tracker, exists := r.trackers[sessionUUID]
	r.mu.RUnlock()

	// Order of attempts based on previous success
	var attemptOrder []string

	if exists && tracker.PreferredProtocol != "" {
		// If we have a recently successful protocol, try it first
		attemptOrder = []string{tracker.PreferredProtocol}
		// Only add fallback protocols if the preferred one has been failing recently
		if tracker.LastRTT == -1 {
			// Add other protocols as fallbacks
			for _, proto := range []string{"ipv6ll", "ipv6", "ipv4"} {
				if proto != tracker.PreferredProtocol {
					attemptOrder = append(attemptOrder, proto)
				}
			}
		}
	} else {
		// Default order: IPv6 link-local first (usually fastest), then IPv6, then IPv4
		attemptOrder = []string{"ipv6ll", "ipv6", "ipv4"}
	}

	// Try protocols in determined order
	for _, proto := range attemptOrder {
		switch proto {
		case "ipv6ll":
			if ipv6ll != "" {
				rtt, loss := r.pingRTT(ipv6ll)
				if rtt != -1 {
					r.updateRTTTracker(sessionUUID, "ipv6ll", rtt, loss)
					return rtt
				}
			}
		case "ipv6":
			if ipv6 != "" {
				rtt, loss := r.pingRTT(ipv6)
				if rtt != -1 {
					r.updateRTTTracker(sessionUUID, "ipv6", rtt, loss)
					return rtt
				}
			}
		case "ipv4":
			if ipv4 != "" {
				rtt, loss := r.pingRTT(ipv4)
				if rtt != -1 {
					r.updateRTTTracker(sessionUUID, "ipv4", rtt, loss)
					return rtt
				}
			}
		}
	}

	// If all attempts fail, update tracker with failure and return -1
	r.updateRTTTracker(sessionUUID, "", -1, 1.0)
	return -1
}

// updateRTTTracker updates the RTT tracking information for a session
func (r *RTTManager) updateRTTTracker(sessionUUID, preferredProtocol string, rtt int, loss float64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	tracker, exists := r.trackers[sessionUUID]
	if !exists {
		tracker = &RTTTracker{
			LastRTT:    -1,
			LastLoss:   1.0,
			Metric:     make([]int, 0),
			LossMetric: make([]float64, 0),
			AvgLoss:    1.0,
		}
		r.trackers[sessionUUID] = tracker
	}

	tracker.LastRTT = rtt
	tracker.LastLoss = loss

	if preferredProtocol != "" {
		// which means we have a successful ping
		tracker.PreferredProtocol = preferredProtocol
	}

	// Record the current LastRTT to the metric array
	tracker.Metric = append(tracker.Metric, tracker.LastRTT)
	// Maintain maxMetricsHistory limit - drop oldest entries if exceeded
	if len(tracker.Metric) > r.cfg.Metric.MaxRTTMetricsHistroy {
		tracker.Metric = tracker.Metric[1:]
	}

	// Record the current loss to the loss metric array
	tracker.LossMetric = append(tracker.LossMetric, tracker.LastLoss)
	// Maintain maxMetricsHistory limit - drop oldest entries if exceeded
	if len(tracker.LossMetric) > r.cfg.Metric.MaxRTTMetricsHistroy {
		tracker.LossMetric = tracker.LossMetric[1:]
	}

	// Calculate average loss rate based on RTT measurements
	tracker.AvgLoss = calculateAvgLossRate(tracker.LossMetric)
}

// calculateAvgLossRate calculates the average packet loss rate from RTT measurements
func calculateAvgLossRate(metrics []float64) float64 {
	if len(metrics) == 0 {
		return 0.0
	}

	var totalLoss float64
	for _, loss := range metrics {
		totalLoss += loss
	}

	return totalLoss / float64(len(metrics))
}

// pingRTT performs actual implementation of ping RTT measurement using ICMP ping
func (r *RTTManager) pingRTT(ip string) (int, float64) {
	// Track recently failed destinations to use shorter timeouts
	r.mu.RLock()
	lastKnownFailedIP, exists := r.failedPingCache[ip]
	r.mu.RUnlock()

	// If this IP has failed recently, use a shorter timeout for the next attempt
	timeout := r.cfg.Metric.PingTimeout
	pingCount := r.cfg.Metric.PingCount

	if exists && time.Since(lastKnownFailedIP) < 10*time.Minute {
		pingCount = r.cfg.Metric.PingCountOnFail // Just do PingCountOnFail attempts for recently failed destinations
	}

	// Use ICMP ping
	rtt, loss := network.PingAverage(ip, pingCount, timeout, r.pingCommandPath)

	// Update the failed IP cache
	r.mu.Lock()
	if rtt <= 0 {
		// Remember this as a failed IP
		r.failedPingCache[ip] = time.Now()
	} else {
		// Remove from failed cache if it succeeds
		delete(r.failedPingCache, ip)
	}
	r.mu.Unlock()

	return rtt, loss
}

// BatchMeasureRTT processes multiple RTT measurements in parallel with context cancellation support
func (r *RTTManager) BatchMeasureRTT(ctx context.Context, sessions []*session.Session) {
	if len(sessions) == 0 {
		return
	}

	r.logger.Debug("Starting batch RTT measurement for %d sessions...", len(sessions))
	startTime := time.Now()

	r.processBatchRTT(ctx, sessions)

	duration := time.Since(startTime)
	r.logger.Info("Completed batch RTT measurement for %d sessions using up to %d workers in %v",
		len(sessions), r.cfg.Metric.PingWorkerCount, duration)
}

// processBatchRTT processes a single batch of RTT measurements
func (r *RTTManager) processBatchRTT(ctx context.Context, sessions []*session.Session) {
	if len(sessions) == 0 {
		return
	}

	// Create a worker pool
	workerCount := min(len(sessions), r.cfg.Metric.PingWorkerCount)

	// Create channels for work distribution
	jobs := make(chan *session.Session, len(sessions))
	results := make(chan struct{}, len(sessions))

	for range workerCount {
		go r.rttWorker(ctx, jobs, results)
	}

	// Send sessions to be processed
	for _, sess := range sessions {
		select {
		case jobs <- sess:
		case <-ctx.Done():
			close(jobs)
			return
		}
	}
	close(jobs)

	// Wait for all jobs to complete or context cancellation
	completedJobs := 0
	for completedJobs < len(sessions) {
		select {
		case <-results:
			completedJobs++
		case <-ctx.Done():
			return
		}
	}
}

// rttWorker is a worker goroutine that processes RTT measurements with context cancellation support
func (r *RTTManager) rttWorker(ctx context.Context, jobs <-chan *session.Session, results chan<- struct{}) {
	for {
		select {
		case sess, ok := <-jobs:
			if !ok {
				return
			}

			// Check if context is cancelled before processing
			select {
			case <-ctx.Done():
				return
			default:
			}

			ipv6LinkLocal := sess.IPv6LinkLocal
			if ipv6LinkLocal != "" {
				ipv6LinkLocal = fmt.Sprintf("%s%%%s", sess.IPv6LinkLocal, sess.Interface)
			}

			// Perform RTT measurement
			r.MeasureRTT(sess.UUID, sess.IPv4, sess.IPv6, ipv6LinkLocal)

			// Signal that this job is done
			select {
			case results <- struct{}{}:
			case <-ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// CleanupCache periodically cleans up the RTT trackers and failed ping cache
func (r *RTTManager) CleanupCache(activeUUIDs map[string]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	trackersRemoved := 0
	cacheEntriesRemoved := 0

	// Cleanup RTT trackers for sessions that no longer exist
	for uuid := range r.trackers {
		if !activeUUIDs[uuid] {
			delete(r.trackers, uuid)
			trackersRemoved++
		}
	}

	// Cleanup failed ping cache (remove entries older than 12 hours)
	for ip, lastFailTime := range r.failedPingCache {
		if time.Since(lastFailTime) > 12*time.Hour {
			delete(r.failedPingCache, ip)
			cacheEntriesRemoved++
		}
	}

	r.logger.Debug("Cleaned up RTT caches (removed %d trackers, %d failed cache entries)",
		trackersRemoved, cacheEntriesRemoved)
}
