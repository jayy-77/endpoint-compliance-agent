package collector

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// FallbackCollector provides basic system data collection without osquery
type FallbackCollector struct{}

// NewFallbackCollector creates a new fallback collector
func NewFallbackCollector() *FallbackCollector {
	return &FallbackCollector{}
}

// CollectUsers returns basic user information using system commands
func (f *FallbackCollector) CollectUsers() ([]map[string]string, error) {
	var users []map[string]string

	switch runtime.GOOS {
	case "darwin", "linux":
		// Use getent or dscl on macOS
		cmd := exec.Command("getent", "passwd")
		if runtime.GOOS == "darwin" {
			cmd = exec.Command("dscl", ".", "list", "/Users")
		}
		
		output, err := cmd.Output()
		if err != nil {
			return users, err
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			
			if runtime.GOOS == "darwin" {
				// macOS dscl output
				users = append(users, map[string]string{
					"username": line,
					"uid":      "0", // Placeholder
					"gid":      "0", // Placeholder
					"description": "User",
					"directory": "/Users/" + line,
					"shell":    "/bin/bash",
				})
			} else {
				// Linux getent output: username:x:uid:gid:description:home:shell
				parts := strings.Split(line, ":")
				if len(parts) >= 7 {
					users = append(users, map[string]string{
						"username":    parts[0],
						"uid":         parts[2],
						"gid":         parts[3],
						"description": parts[4],
						"directory":   parts[5],
						"shell":       parts[6],
					})
				}
			}
		}
	}

	return users, nil
}

// CollectProcesses returns basic process information
func (f *FallbackCollector) CollectProcesses(limit int) ([]map[string]string, error) {
	var processes []map[string]string

	switch runtime.GOOS {
	case "darwin", "linux":
		cmd := exec.Command("ps", "aux")
		output, err := cmd.Output()
		if err != nil {
			return processes, err
		}

		lines := strings.Split(string(output), "\n")
		count := 0
		for i, line := range lines {
			if i == 0 || line == "" || count >= limit {
				continue // Skip header
			}

			fields := strings.Fields(line)
			if len(fields) >= 11 {
				processes = append(processes, map[string]string{
					"pid":     fields[1],
					"name":    fields[10],
					"path":    fields[10],
					"cmdline": strings.Join(fields[10:], " "),
					"uid":     fields[0],
				})
				count++
			}
		}
	}

	return processes, nil
}

// CollectOpenPorts returns listening ports using netstat
func (f *FallbackCollector) CollectOpenPorts() ([]int, error) {
	var ports []int

	switch runtime.GOOS {
	case "darwin", "linux":
		cmd := exec.Command("netstat", "-tuln")
		output, err := cmd.Output()
		if err != nil {
			return ports, err
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "LISTEN") || strings.Contains(line, "tcp") {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					// Extract port from address:port format
					addr := fields[3]
					if strings.Contains(addr, ":") {
						parts := strings.Split(addr, ":")
						if len(parts) > 1 {
							portStr := parts[len(parts)-1]
							if port, err := strconv.Atoi(portStr); err == nil && port > 0 {
								ports = append(ports, port)
							}
						}
					}
				}
			}
		}
	}

	return ports, nil
}

// CollectPackages returns basic package information
func (f *FallbackCollector) CollectPackages(limit int) ([]map[string]string, error) {
	var packages []map[string]string

	switch runtime.GOOS {
	case "darwin":
		// Try Homebrew
		if _, err := exec.LookPath("brew"); err == nil {
			cmd := exec.Command("brew", "list", "--formula")
			output, err := cmd.Output()
			if err == nil {
				lines := strings.Split(string(output), "\n")
				count := 0
				for _, line := range lines {
					if line == "" || count >= limit {
						continue
					}
					packages = append(packages, map[string]string{
						"name":    line,
						"version": "unknown",
						"source":  "homebrew",
						"arch":    runtime.GOARCH,
					})
					count++
				}
			}
		}
	case "linux":
		// Try dpkg (Debian/Ubuntu)
		if _, err := exec.LookPath("dpkg"); err == nil {
			cmd := exec.Command("dpkg", "-l")
			output, err := cmd.Output()
			if err == nil {
				lines := strings.Split(string(output), "\n")
				count := 0
				for _, line := range lines {
					if strings.HasPrefix(line, "ii") && count < limit {
						fields := strings.Fields(line)
						if len(fields) >= 3 {
							packages = append(packages, map[string]string{
								"name":    fields[1],
								"version": fields[2],
								"source":  "dpkg",
								"arch":    runtime.GOARCH,
							})
							count++
						}
					}
				}
			}
		}
	}

	return packages, nil
}

// HealthCheck always returns nil for fallback collector
func (f *FallbackCollector) HealthCheck() error {
	return nil
}
