package collector

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// SystemMetrics is the lightweight host-level summary that feeds the
// ML feature builder.
type SystemMetrics struct {
	LoadAvg1m     float64 `json:"load_avg_1m"`
	LoadAvg5m     float64 `json:"load_avg_5m"`
	LoadAvg15m    float64 `json:"load_avg_15m"`
	MemTotalKB    int64   `json:"mem_total_kb"`
	MemFreeKB     int64   `json:"mem_free_kb"`
	CPUCount      int     `json:"cpu_count"`
}

// CollectSystemMetrics is best-effort: failures in any one field don't
// fail the whole call, so a partially populated struct is normal.
func CollectSystemMetrics() (SystemMetrics, error) {
	var s SystemMetrics
	s.LoadAvg1m, s.LoadAvg5m, s.LoadAvg15m = readLoadAvg()
	s.CPUCount = readCPUCount()
	s.MemTotalKB, s.MemFreeKB = readMem()
	return s, nil
}

func readLoadAvg() (float64, float64, float64) {
	out, err := exec.Command("uptime").Output()
	if err != nil {
		return 0, 0, 0
	}
	s := string(out)
	idx := strings.Index(s, "load average")
	if idx < 0 {
		idx = strings.Index(s, "load averages")
		if idx < 0 {
			return 0, 0, 0
		}
	}
	rest := s[idx:]
	colon := strings.Index(rest, ":")
	if colon < 0 {
		return 0, 0, 0
	}
	vals := strings.FieldsFunc(rest[colon+1:], func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n'
	})
	parse := func(i int) float64 {
		if i >= len(vals) {
			return 0
		}
		f, _ := strconv.ParseFloat(vals[i], 64)
		return f
	}
	return parse(0), parse(1), parse(2)
}

func readCPUCount() int {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("sysctl", "-n", "hw.ncpu").Output()
		if err == nil {
			n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
			return n
		}
	case "linux":
		out, err := exec.Command("nproc").Output()
		if err == nil {
			n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
			return n
		}
	}
	return runtime.NumCPU()
}

func readMem() (total, free int64) {
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("cat", "/proc/meminfo").Output()
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			switch f[0] {
			case "MemTotal:":
				total, _ = strconv.ParseInt(f[1], 10, 64)
			case "MemAvailable:":
				free, _ = strconv.ParseInt(f[1], 10, 64)
			}
		}
	case "darwin":
		out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
		if err == nil {
			t, _ := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
			total = t / 1024
		}
	}
	return
}
