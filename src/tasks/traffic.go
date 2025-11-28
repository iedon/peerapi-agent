package tasks

import (
	"context"
	"time"

	"github.com/iedon/peerapi-agent/logger"
	"github.com/iedon/peerapi-agent/network"
)

// TrafficMonitorTask monitors network interface traffic
type TrafficMonitorTask struct {
	logger         *logger.Logger
	trafficMonitor *network.TrafficMonitor
}

// NewTrafficMonitorTask creates a new traffic monitor task
func NewTrafficMonitorTask(log *logger.Logger, trafficMon *network.TrafficMonitor) *TrafficMonitorTask {
	return &TrafficMonitorTask{
		logger:         log,
		trafficMonitor: trafficMon,
	}
}

// Run runs the traffic monitoring task
func (t *TrafficMonitorTask) Run(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.logger.Info("Traffic monitoring task shutting down...")
			t.logger.Debug("Cleaning up traffic data for %d interfaces", len(t.trafficMonitor.GetAllRates()))
			return
		case <-ticker.C:
			t.trafficMonitor.MonitorRates()
		}
	}
}
