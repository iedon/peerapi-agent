package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/iedon/peerapi-agent/app"
)

const (
	version = "2.0.0"
)

func main() {
	// Parse command line flags
	configFile := flag.String("c", "config.json", "Path to configuration file")
	showVersion := flag.Bool("v", false, "Show version information")
	flag.Parse()

	// Show version and exit
	if *showVersion {
		fmt.Printf("PeerAPI Agent v%s\n", version)
		os.Exit(0)
	}

	// Create and run application
	application, err := app.New(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize application: %v\n", err)
		os.Exit(1)
	}

	// Run application
	if err := application.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Application error: %v\n", err)
		os.Exit(1)
	}
}
