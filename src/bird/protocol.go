package bird

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
)

// ProtocolMetrics represents the metrics for a single BGP protocol/session.
type ProtocolMetrics struct {
	State      string
	Since      string
	Info       string
	IPv4Import int64
	IPv4Export int64
	IPv6Import int64
	IPv6Export int64
}

// ProtocolResult represents a parsed protocol output entry.
type ProtocolResult struct {
	SessionName string
	Metrics     ProtocolMetrics
	Error       error
}

// BatchQuery describes a BIRD CLI query to be executed.
type BatchQuery struct {
	SessionName string
	Command     string
}

// BatchResult holds the response of a BatchQuery execution.
type BatchResult struct {
	SessionName string
	Output      string
	Error       error
}

var (
	routeLineRegex = regexp.MustCompile(`^Routes:\s+(\d+)\s+imported,(?:\s+\d+\s+filtered,)?\s+(\d+)\s+exported`)
	channelRegex   = regexp.MustCompile(`^Channel\s+(ipv[46])$`)
	stateDownRegex = regexp.MustCompile(`^State:.*DOWN`)
)

func parseProtocolOutput(data []byte) (string, string, string, int64, int64, int64, int64, error) {
	if len(data) == 0 {
		return "", "", "", 0, 0, 0, 0, nil
	}

	lines := bytes.Split(data, []byte("\n"))
	if len(lines) < 2 {
		return "", "", "", 0, 0, 0, 0, nil
	}

	var (
		state, since, info     string
		ipv4Import, ipv4Export int64
		ipv6Import, ipv6Export int64
		currentChannel         string
	)

	header := bytes.Fields(lines[1])
	if len(header) >= 4 {
		state = string(header[3])
	}
	if len(header) >= 5 {
		since = string(header[4])
	}
	if len(header) >= 6 {
		since = strings.TrimSpace(since + " " + string(header[5]))
	}
	if len(header) > 6 {
		info = string(bytes.Join(header[6:], []byte(" ")))
	}

	for _, raw := range lines[2:] {
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}

		if matches := channelRegex.FindStringSubmatch(line); len(matches) == 2 {
			currentChannel = matches[1]
			continue
		}

		if stateDownRegex.MatchString(line) {
			switch currentChannel {
			case "ipv4":
				ipv4Import, ipv4Export = 0, 0
			case "ipv6":
				ipv6Import, ipv6Export = 0, 0
			}
			continue
		}

		if matches := routeLineRegex.FindStringSubmatch(line); len(matches) == 3 {
			imported, err1 := strconv.ParseInt(matches[1], 10, 64)
			exported, err2 := strconv.ParseInt(matches[2], 10, 64)
			if err1 == nil && err2 == nil {
				switch currentChannel {
				case "ipv4":
					ipv4Import, ipv4Export = imported, exported
				case "ipv6":
					ipv6Import, ipv6Export = imported, exported
				}
			}
		}
	}

	return state, strings.TrimSpace(since), strings.TrimSpace(info), ipv4Import, ipv4Export, ipv6Import, ipv6Export, nil
}
