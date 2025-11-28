package cmd

import (
	"context"
	"os/exec"
	"strings"
)

// RunCommand executes a command and returns its output
func RunCommand(ctx context.Context, binary string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}
