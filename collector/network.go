package collector

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// NetworkStats captures coarse network counters useful for ML features
// (e.g. detect outbound exfil bursts via sustained nonzero TX deltas).
type NetworkStats struct {
	Interfaces []NetworkInterface `json:"interfaces"`
}

type NetworkInterface struct {
	Name    string `json:"name"`
	RXBytes int64  `json:"rx_bytes"`
	TXBytes int64  `json:"tx_bytes"`
	RXPkts  int64  `json:"rx_packets"`
	TXPkts  int64  `json:"tx_packets"`
}

// CollectNetwork pulls per-interface counters via `netstat -ib` (macOS)
// or `/proc/net/dev` (Linux). On parse failures, returns whatever was
// successfully parsed plus a nil error — partial data is better than none.
func CollectNetwork() (NetworkStats, error) {
	switch runtime.GOOS {
	case "darwin":
		return collectNetworkMacOS()
	case "linux":
		return collectNetworkLinux()
	default:
		return NetworkStats{}, nil
	}
}

func collectNetworkMacOS() (NetworkStats, error) {
	out, err := exec.Command("netstat", "-ib").Output()
	if err != nil {
		return NetworkStats{}, err
	}
	var stats NetworkStats
	seen := map[string]bool{}
	lines := strings.Split(string(out), "\n")
	if len(lines) > 0 {
		lines = lines[1:] // skip header
	}
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 11 {
			continue
		}
		name := f[0]
		if seen[name] {
			continue
		}
		seen[name] = true
		rxp, _ := strconv.ParseInt(f[4], 10, 64)
		rxb, _ := strconv.ParseInt(f[6], 10, 64)
		txp, _ := strconv.ParseInt(f[7], 10, 64)
		txb, _ := strconv.ParseInt(f[9], 10, 64)
		stats.Interfaces = append(stats.Interfaces, NetworkInterface{
			Name: name, RXBytes: rxb, TXBytes: txb, RXPkts: rxp, TXPkts: txp,
		})
	}
	return stats, nil
}

func collectNetworkLinux() (NetworkStats, error) {
	out, err := exec.Command("cat", "/proc/net/dev").Output()
	if err != nil {
		return NetworkStats{}, err
	}
	var stats NetworkStats
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if i < 2 {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}
		rxb, _ := strconv.ParseInt(fields[0], 10, 64)
		rxp, _ := strconv.ParseInt(fields[1], 10, 64)
		txb, _ := strconv.ParseInt(fields[8], 10, 64)
		txp, _ := strconv.ParseInt(fields[9], 10, 64)
		stats.Interfaces = append(stats.Interfaces, NetworkInterface{
			Name: name, RXBytes: rxb, TXBytes: txb, RXPkts: rxp, TXPkts: txp,
		})
	}
	return stats, nil
}
