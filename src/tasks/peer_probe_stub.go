//go:build !linux

package tasks

import (
	"context"

	"github.com/iedon/peerapi-agent/session"
)

// initialize initializes the peer probe task (stub for non-Linux platforms)
func (t *PeerProbeTask) initialize() error {
	t.logger.Warn("Peer probe task disabled: peer probes require linux-specific networking features")
	return nil
}

// executeProbes is a no-op for non-Linux platforms
func (t *PeerProbeTask) executeProbes(ctx context.Context, sessions []*session.Session) {
	// No-op on non-Linux platforms
}
