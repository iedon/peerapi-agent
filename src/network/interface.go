package network

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
)

// InterfaceExists checks if a network interface exists
func InterfaceExists(iface string) (bool, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		if lineCount <= 2 {
			// Skip headers
			continue
		}

		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		_iface := strings.TrimSpace(parts[0])
		if _iface == iface {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, err
	}

	return false, nil
}

// GetInterfaceMTU returns the MTU of the given interface from /sys/class/net/<iface>/mtu
func GetInterfaceMTU(name string) (int, error) {
	data, err := os.ReadFile("/sys/class/net/" + name + "/mtu")
	if err != nil {
		return 0, fmt.Errorf("failed to read MTU: %w", err)
	}
	mtuStr := strings.TrimSpace(string(data))
	mtu, err := strconv.Atoi(mtuStr)
	if err != nil {
		return 0, fmt.Errorf("invalid MTU format: %w", err)
	}
	return mtu, nil
}

// GetInterfaceMAC returns the MAC address of an interface
func GetInterfaceMAC(ifaceName string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", err
	}
	mac := iface.HardwareAddr.String()
	if mac == "" {
		return "", fmt.Errorf("no MAC address found for interface %s", ifaceName)
	}
	return mac, nil
}

// GetInterfaceFlags returns the list of string flags (e.g. UP, BROADCAST) for the given interface
func GetInterfaceFlags(name string) (string, error) {
	data, err := os.ReadFile("/sys/class/net/" + name + "/flags")
	if err != nil {
		return "", fmt.Errorf("failed to read flags: %w", err)
	}
	flagStr := strings.TrimSpace(string(data))
	flags, err := strconv.ParseUint(flagStr, 0, 64)
	if err != nil {
		return "", fmt.Errorf("invalid flags format: %w", err)
	}

	var result []string
	for bit, name := range interfaceFlagMap {
		if flags&bit != 0 {
			result = append(result, name)
		}
	}
	slices.Sort(result)
	return strings.Join(result, ", "), nil
}

var interfaceFlagMap = map[uint64]string{
	0x1:     "UP",
	0x2:     "Broadcast",
	0x4:     "Debug",
	0x8:     "Loopback",
	0x10:    "PointToPoint",
	0x20:    "NoTrailers",
	0x40:    "Running",
	0x80:    "NoARP",
	0x100:   "Promisc",
	0x200:   "AllMulti",
	0x400:   "Master",
	0x800:   "Slave",
	0x1000:  "Multicast",
	0x2000:  "PortSel",
	0x4000:  "AutoMedia",
	0x8000:  "Dynamic",
	0x10000: "LowerUp",
	0x20000: "Dormant",
	0x40000: "Echo",
}
