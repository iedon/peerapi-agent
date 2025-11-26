//go:build !linux

package main

import (
	"context"
	"log"
	"sync"
)

func peerProbeTask(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	log.Println("[PeerProbe] Task disabled: peer probes require linux-specific networking features")
}
