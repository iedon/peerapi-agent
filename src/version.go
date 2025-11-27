package main

import (
	"fmt"
	"runtime"
)

const (
	SERVER_NAME    = "iEdon-PeerAPI-Agent"
	SERVER_VERSION = "1.9.5"
)

var GIT_COMMIT string // Set at build time via -ldflags "-X main.GIT_COMMIT=$(git rev-parse --short HEAD)"
var SERVER_SIGNATURE = fmt.Sprintf("%s (%s; %s; %s; %s)", SERVER_NAME+"/"+SERVER_VERSION, func() string {
	if GIT_COMMIT != "" {
		return GIT_COMMIT
	}
	return "unknown"
}(), runtime.GOOS, runtime.GOARCH, runtime.Version())
