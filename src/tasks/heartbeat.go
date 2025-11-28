package tasks

import (
	"context"
	"time"

	"github.com/iedon/peerapi-agent/api"
	"github.com/iedon/peerapi-agent/bird"
	"github.com/iedon/peerapi-agent/config"
	"github.com/iedon/peerapi-agent/logger"
	"github.com/iedon/peerapi-agent/network"
	"github.com/iedon/peerapi-agent/version"
)

// HeartbeatTask sends periodic heartbeats to the PeerAPI server
type HeartbeatTask struct {
	cfg       *config.Config
	logger    *logger.Logger
	apiClient *api.Client
	birdPool  *bird.BirdPool
}

// NewHeartbeatTask creates a new heartbeat task
func NewHeartbeatTask(cfg *config.Config, log *logger.Logger, apiClient *api.Client, birdPool *bird.BirdPool) *HeartbeatTask {
	return &HeartbeatTask{
		cfg:       cfg,
		logger:    log,
		apiClient: apiClient,
		birdPool:  birdPool,
	}
}

// Run runs the heartbeat task
func (t *HeartbeatTask) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(t.cfg.PeerAPI.HeartbeatInterval) * time.Second)
	defer ticker.Stop()

	uname := network.GetOsUname()

	// Send an initial heartbeat immediately
	t.sendHeartbeat(ctx, uname)

	for {
		select {
		case <-ctx.Done():
			t.logger.Info("Heartbeat task shutting down...")
			return
		case <-ticker.C:
			t.sendHeartbeat(ctx, uname)
		}
	}
}

func (t *HeartbeatTask) sendHeartbeat(ctx context.Context, uname string) {
	routerSoftware := ""
	if t.birdPool != nil {
		routerSoftware, _ = t.birdPool.ShowStatus()
	}

	rx, tx, _ := network.GetInterfaceTraffic(t.cfg.PeerAPI.WanInterfaces)

	err := t.apiClient.SendHeartbeat(
		ctx,
		version.SERVER_SIGNATURE,
		uname,
		network.GetLoadAverageStr(),
		network.GetUptimeSeconds(),
		routerSoftware,
		tx,
		rx,
		network.GetTcpConnections(),
		network.GetUdpConnections(),
	)

	if err != nil {
		t.logger.Error("Failed to send heartbeat: %v", err)
	}
}
