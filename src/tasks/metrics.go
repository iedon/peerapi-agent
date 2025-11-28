package tasks

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/iedon/peerapi-agent/api"
	"github.com/iedon/peerapi-agent/bird"
	"github.com/iedon/peerapi-agent/config"
	"github.com/iedon/peerapi-agent/logger"
	"github.com/iedon/peerapi-agent/metrics"
	"github.com/iedon/peerapi-agent/network"
	"github.com/iedon/peerapi-agent/session"
)

// MetricsTask collects and reports session metrics to PeerAPI
type MetricsTask struct {
	cfg            *config.Config
	logger         *logger.Logger
	apiClient      *api.Client
	sessionMgr     *session.Manager
	rttManager     *metrics.RTTManager
	trafficMonitor *network.TrafficMonitor
	birdPool       *bird.BirdPool
}

// MetricJob represents a single metric collection job
type MetricJob struct {
	Session   *session.Session
	Timestamp int64
}

// MetricResult represents the result of metric collection for one session
type MetricResult struct {
	UUID   string
	Metric metrics.SessionMetric
	Error  error
}

// NewMetricsTask creates a new metrics collection task
func NewMetricsTask(
	cfg *config.Config,
	log *logger.Logger,
	apiClient *api.Client,
	sessionMgr *session.Manager,
	rttManager *metrics.RTTManager,
	trafficMonitor *network.TrafficMonitor,
	birdPool *bird.BirdPool,
) *MetricsTask {
	return &MetricsTask{
		cfg:            cfg,
		logger:         log,
		apiClient:      apiClient,
		sessionMgr:     sessionMgr,
		rttManager:     rttManager,
		trafficMonitor: trafficMonitor,
		birdPool:       birdPool,
	}
}

// Run runs the metrics collection task
func (t *MetricsTask) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(t.cfg.PeerAPI.MetricInterval) * time.Second)
	defer ticker.Stop()

	// Collect metrics immediately on startup
	t.collectAndReportMetrics(ctx)

	for {
		select {
		case <-ctx.Done():
			t.logger.Info("Metrics collection task shutting down...")
			return
		case <-ticker.C:
			t.collectAndReportMetrics(ctx)
		}
	}
}

// collectAndReportMetrics collects metrics for all active sessions and reports to PeerAPI
func (t *MetricsTask) collectAndReportMetrics(ctx context.Context) {
	now := time.Now().Unix()

	// Get active sessions
	activeSessions := t.sessionMgr.GetActive()
	if len(activeSessions) == 0 {
		t.logger.Debug("No active sessions to collect metrics from")
		return
	}

	// Collect metrics concurrently using worker pool
	sessionMetrics := t.batchCollectSessionMetrics(activeSessions, now)

	if len(sessionMetrics) == 0 {
		t.logger.Warn("No metrics collected from active sessions")
		return
	}

	t.logger.Debug("Collected metrics for %d sessions", len(sessionMetrics))

	// Send metrics to PeerAPI
	if err := t.apiClient.ReportMetrics(ctx, sessionMetrics); err != nil {
		t.logger.Error("Failed to send metrics to PeerAPI: %v", err)
	} else {
		t.logger.Info("Successfully sent %d session metrics to PeerAPI", len(sessionMetrics))
	}
}

// batchCollectSessionMetrics collects metrics for multiple sessions concurrently
func (t *MetricsTask) batchCollectSessionMetrics(sessions []*session.Session, timestamp int64) []metrics.SessionMetric {
	if len(sessions) == 0 {
		return nil
	}

	startTime := time.Now()

	// Create worker pool for concurrent session processing
	workerCount := min(len(sessions), t.cfg.Metric.SessionWorkerCount)
	if workerCount == 0 {
		workerCount = min(len(sessions), 8) // Default fallback
	}

	jobs := make(chan MetricJob, len(sessions))
	results := make(chan MetricResult, len(sessions))

	// Start worker goroutines
	var wg sync.WaitGroup
	for range workerCount {
		wg.Add(1)
		go t.metricWorker(jobs, results, &wg)
	}

	// Send jobs to workers
	for _, sess := range sessions {
		jobs <- MetricJob{
			Session:   sess,
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
	sessionMetrics := make([]metrics.SessionMetric, 0, len(sessions))
	for result := range results {
		if result.Error != nil {
			t.logger.Warn("Failed to collect metrics for session %s: %v", result.UUID, result.Error)
			continue
		}
		sessionMetrics = append(sessionMetrics, result.Metric)
	}

	duration := time.Since(startTime)
	t.logger.Debug("Collected metrics for %d sessions using %d workers in %v",
		len(sessionMetrics), workerCount, duration)

	return sessionMetrics
}

// metricWorker processes metric collection jobs concurrently
func (t *MetricsTask) metricWorker(jobs <-chan MetricJob, results chan<- MetricResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		result := MetricResult{
			UUID: job.Session.UUID,
		}

		// Collect metrics for this session
		metric, err := t.collectSessionMetric(job.Session, job.Timestamp)
		if err != nil {
			result.Error = err
		} else {
			result.Metric = metric
		}

		results <- result
	}
}

// collectSessionMetric collects metrics for a single session by querying BIRD
func (t *MetricsTask) collectSessionMetric(sess *session.Session, timestamp int64) (metrics.SessionMetric, error) {
	sessionName := fmt.Sprintf("DN42_%d_%s", sess.ASN, sess.Interface)
	mpBGP := slices.Contains(sess.Extensions, "mp-bgp")

	var bgpMetrics []metrics.BGPMetric

	// Collect BGP metrics by querying BIRD directly
	if mpBGP {
		// For MP-BGP, query the single session
		state, since, info, ipv4Import, ipv4Export, ipv6Import, ipv6Export, err := t.birdPool.GetProtocolStatus(sessionName)
		if err != nil {
			// Create default metrics on error
			bgpMetrics = []metrics.BGPMetric{
				t.createBGPMetric(sessionName, "Unknown", fmt.Sprintf("Query error: %v", err),
					session.BGP_SESSION_TYPE_MPBGP, "", 0, 0, 0, 0),
			}
		} else {
			bgpMetrics = []metrics.BGPMetric{
				t.createBGPMetric(sessionName, state, info, session.BGP_SESSION_TYPE_MPBGP, since,
					int(ipv4Import), int(ipv4Export), int(ipv6Import), int(ipv6Export)),
			}
		}
	} else {
		// For traditional BGP, query v4 and v6 sessions separately
		bgpMetrics = make([]metrics.BGPMetric, 0, 2)

		if sess.IPv6LinkLocal != "" || sess.IPv6 != "" {
			v6Name := sessionName + "_v6"
			state, since, info, _, _, ipv6Import, ipv6Export, err := t.birdPool.GetProtocolStatus(v6Name)
			if err != nil {
				bgpMetrics = append(bgpMetrics, t.createBGPMetric(v6Name, "Unknown",
					fmt.Sprintf("Query error: %v", err), session.BGP_SESSION_TYPE_IPV6, "", 0, 0, 0, 0))
			} else {
				bgpMetrics = append(bgpMetrics, t.createBGPMetric(v6Name, state, info,
					session.BGP_SESSION_TYPE_IPV6, since, 0, 0, int(ipv6Import), int(ipv6Export)))
			}
		}

		if sess.IPv4 != "" {
			v4Name := sessionName + "_v4"
			state, since, info, ipv4Import, ipv4Export, _, _, err := t.birdPool.GetProtocolStatus(v4Name)
			if err != nil {
				bgpMetrics = append(bgpMetrics, t.createBGPMetric(v4Name, "Unknown",
					fmt.Sprintf("Query error: %v", err), session.BGP_SESSION_TYPE_IPV4, "", 0, 0, 0, 0))
			} else {
				bgpMetrics = append(bgpMetrics, t.createBGPMetric(v4Name, state, info,
					session.BGP_SESSION_TYPE_IPV4, since, int(ipv4Import), int(ipv4Export), 0, 0))
			}
		}
	}

	// Get interface traffic statistics
	rx, tx, _ := network.GetInterfaceTraffic([]string{sess.Interface})

	// Get current traffic rates from traffic monitor
	rxRate, txRate := t.trafficMonitor.GetRates(sess.Interface)

	// Get RTT value from the RTT manager
	rttValue, lossRate := t.rttManager.GetRTTValue(sess.UUID)

	// Generate session metric
	metric := metrics.SessionMetric{
		UUID:      sess.UUID,
		ASN:       sess.ASN,
		Timestamp: timestamp,
		BGP:       bgpMetrics,
		Interface: metrics.InterfaceMetric{
			IPv4:          sess.IPv4,
			IPv6:          sess.IPv6,
			IPv6LinkLocal: sess.IPv6LinkLocal,
			MAC:           t.getInterfaceMAC(sess.Interface),
			MTU:           t.getInterfaceMTU(sess),
			Status:        t.getInterfaceStatus(sess.Interface),
			Traffic: metrics.InterfaceTrafficMetric{
				Total:   []int64{int64(tx), int64(rx)}, // [Tx, Rx]
				Current: []int64{txRate, rxRate},       // [Tx, Rx]
			},
		},
		RTT: metrics.RTT{
			Current: rttValue,
			Loss:    lossRate,
		},
	}

	return metric, nil
}

// createBGPMetric creates a BGP metric object with the given parameters
func (t *MetricsTask) createBGPMetric(name, state, info, sessionType, since string,
	ipv4Import, ipv4Export, ipv6Import, ipv6Export int) metrics.BGPMetric {
	return metrics.BGPMetric{
		Name:  name,
		State: state,
		Info:  info,
		Type:  sessionType,
		Since: since,
		Routes: metrics.BGPRoutesMetric{
			IPv4: metrics.RouteMetricStruct{
				Imported: metrics.RouteMetrics{Current: ipv4Import},
				Exported: metrics.RouteMetrics{Current: ipv4Export},
			},
			IPv6: metrics.RouteMetricStruct{
				Imported: metrics.RouteMetrics{Current: ipv6Import},
				Exported: metrics.RouteMetrics{Current: ipv6Export},
			},
		},
	}
}

// getInterfaceMAC retrieves the MAC address for an interface
func (t *MetricsTask) getInterfaceMAC(iface string) string {
	mac, err := network.GetInterfaceMAC(iface)
	if err != nil {
		return ""
	}
	return mac
}

// getInterfaceMTU retrieves the MTU for an interface
func (t *MetricsTask) getInterfaceMTU(sess *session.Session) int {
	mtu, err := network.GetInterfaceMTU(sess.Interface)
	if err != nil || mtu <= 0 {
		return sess.MTU
	}
	return mtu
}

// getInterfaceStatus retrieves the status flags for an interface
func (t *MetricsTask) getInterfaceStatus(iface string) string {
	flags, err := network.GetInterfaceFlags(iface)
	if err != nil {
		return ""
	}
	return flags
}
