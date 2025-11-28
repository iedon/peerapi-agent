package version

import (
	"fmt"
	"runtime"
)

const (
	SERVER_NAME    = "iEdon-PeerAPI-Agent"
	SERVER_VERSION = "2.0.0"
)

var GIT_COMMIT string // Set at build time via -ldflags "-X github.com/iedon/peerapi-agent/version.GIT_COMMIT=$(git rev-parse --short HEAD)"
var SERVER_SIGNATURE = fmt.Sprintf("%s (%s; %s; %s; %s)", SERVER_NAME+"/"+SERVER_VERSION, func() string {
	if GIT_COMMIT != "" {
		return GIT_COMMIT
	}
	return "unknown"
}(), runtime.GOOS, runtime.GOARCH, runtime.Version())
