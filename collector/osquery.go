package collector

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	osquery "github.com/osquery/osquery-go"
)

// OSQueryCollector connects to osquery and runs SQL queries to collect data.
type OSQueryCollector struct {
	SocketPath string
	Timeout    time.Duration
}

// Collector is an interface for system data collection, enabling future extensions.
type Collector interface {
	CollectUsers() ([]map[string]string, error)
	CollectProcesses(limit int) ([]map[string]string, error)
	CollectOpenPorts() ([]int, error)
	CollectPackages(limit int) ([]map[string]string, error)
}

func NewOSQueryCollector() *OSQueryCollector {
	socket := os.Getenv("OSQUERY_SOCKET")
	if socket == "" {
		// Common default on macOS/Linux when using osqueryd
		socket = "/var/osquery/osquery.em"
	}
	return &OSQueryCollector{SocketPath: socket, Timeout: 5 * time.Second}
}

// EnsureOSQueryRunning checks if osquery is running and starts it if needed
func (c *OSQueryCollector) EnsureOSQueryRunning() error {
	// First check if socket exists and is responsive
	if err := c.HealthCheck(); err == nil {
		return nil // Already running
	}

	fmt.Println("osquery not running, attempting to start...")

	// Try to start osquery daemon
	if err := c.startOSQueryDaemon(); err != nil {
		fmt.Printf("Failed to start osquery: %v\n", err)
		fmt.Println("Falling back to basic system collection...")
		return fmt.Errorf("osquery unavailable: %w", err)
	}

	// Wait a moment for daemon to start
	time.Sleep(2 * time.Second)

	// Verify it's now running
	if err := c.HealthCheck(); err != nil {
		return fmt.Errorf("osquery failed to start properly: %w", err)
	}

	fmt.Println("osquery started successfully!")
	return nil
}

func (c *OSQueryCollector) startOSQueryDaemon() error {
	// Create socket directory
	socketDir := filepath.Dir(c.SocketPath)
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Find osquery binary
	osqueryPath, err := c.findOSQueryBinary()
	if err != nil {
		return fmt.Errorf("osquery not found: %w", err)
	}

	// Start osquery daemon
	cmd := exec.Command(osqueryPath,
		"--ephemeral",
		"--disable_database",
		"--tls_disable=true",
		"--extensions_socket="+c.SocketPath,
		"--pidfile="+filepath.Join(socketDir, "osqueryd.pid"),
		"--logger_path="+socketDir,
		"--config_path="+filepath.Join(socketDir, "osquery.conf"),
	)

	// Start in background
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start osquery daemon: %w", err)
	}

	return nil
}

func (c *OSQueryCollector) findOSQueryBinary() (string, error) {
	// Check common locations
	paths := []string{
		"/usr/local/bin/osqueryd",
		"/usr/bin/osqueryd",
		"/opt/homebrew/bin/osqueryd",
		"/usr/local/opt/osquery/bin/osqueryd",
	}

	// Also check PATH
	if path, err := exec.LookPath("osqueryd"); err == nil {
		paths = append([]string{path}, paths...)
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// Try to install osquery
	return c.installOSQuery()
}

func (c *OSQueryCollector) installOSQuery() (string, error) {
	fmt.Println("osquery not found, attempting to install...")

	switch runtime.GOOS {
	case "darwin":
		return c.installOSQueryMacOS()
	case "linux":
		return c.installOSQueryLinux()
	default:
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func (c *OSQueryCollector) installOSQueryMacOS() (string, error) {
	// Try Homebrew
	if _, err := exec.LookPath("brew"); err == nil {
		fmt.Println("Installing osquery via Homebrew...")
		cmd := exec.Command("brew", "install", "osquery")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("homebrew install failed: %w", err)
		}
		return "/opt/homebrew/bin/osqueryd", nil
	}
	return "", fmt.Errorf("homebrew not available")
}

func (c *OSQueryCollector) installOSQueryLinux() (string, error) {
	// Try apt (Ubuntu/Debian)
	if _, err := exec.LookPath("apt"); err == nil {
		fmt.Println("Installing osquery via apt...")
		cmd := exec.Command("sudo", "apt", "update")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("apt update failed: %w", err)
		}

		cmd = exec.Command("sudo", "apt", "install", "-y", "osquery")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("apt install failed: %w", err)
		}
		return "/usr/bin/osqueryd", nil
	}

	// Try yum (RHEL/CentOS)
	if _, err := exec.LookPath("yum"); err == nil {
		fmt.Println("Installing osquery via yum...")
		cmd := exec.Command("sudo", "yum", "install", "-y", "osquery")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("yum install failed: %w", err)
		}
		return "/usr/bin/osqueryd", nil
	}

	return "", fmt.Errorf("no package manager found (apt/yum)")
}

func (c *OSQueryCollector) query(query string) ([]map[string]string, error) {
	client, err := osquery.NewClient(c.SocketPath, c.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to create osquery client: %w", err)
	}
	defer client.Close()

	resp, err := client.Query(query)
	if err != nil {
		return nil, fmt.Errorf("osquery query failed: %w", err)
	}
	if resp.Status != nil && resp.Status.Code != 0 {
		return nil, fmt.Errorf("osquery error code %d: %s", resp.Status.Code, resp.Status.Message)
	}
	return resp.Response, nil
}

// CollectUsers returns local system users from the users table.
func (c *OSQueryCollector) CollectUsers() ([]map[string]string, error) {
	const q = "SELECT username, uid, gid, description, directory, shell FROM users;"
	return c.query(q)
}

// CollectProcesses returns a subset of processes.
func (c *OSQueryCollector) CollectProcesses(limit int) ([]map[string]string, error) {
	if limit <= 0 {
		limit = 50
	}
	q := fmt.Sprintf("SELECT pid, name, path, cmdline, uid FROM processes LIMIT %d;", limit)
	return c.query(q)
}

// CollectOpenPorts returns listening TCP/UDP ports using osquery listening_ports table.
func (c *OSQueryCollector) CollectOpenPorts() ([]int, error) {
	rows, err := c.query("SELECT port FROM listening_ports WHERE address != '::' AND port > 0;")
	if err != nil {
		return nil, err
	}
	ports := make([]int, 0, len(rows))
	for _, r := range rows {
		var p int
		// osquery returns strings; safe parse
		fmt.Sscanf(r["port"], "%d", &p)
		if p > 0 {
			ports = append(ports, p)
		}
	}
	return ports, nil
}

// CollectPackages tries osquery packages table.
func (c *OSQueryCollector) CollectPackages(limit int) ([]map[string]string, error) {
	if limit <= 0 {
		limit = 100
	}
	q := fmt.Sprintf("SELECT name, version, source, arch FROM packages LIMIT %d;", limit)
	return c.query(q)
}

// HealthCheck ensures the socket is reachable by issuing a trivial distributed ping.
func (c *OSQueryCollector) HealthCheck() error {
	client, err := osquery.NewClient(c.SocketPath, c.Timeout)
	if err != nil {
		return fmt.Errorf("failed to create osquery client: %w", err)
	}
	defer client.Close()
	// Lightweight connectivity check: trivial query
	resp, err := client.Query("SELECT 1 as ok;")
	if err != nil {
		return fmt.Errorf("osquery health query failed: %w", err)
	}
	if resp.Status != nil && resp.Status.Code != 0 {
		return fmt.Errorf("osquery health status %d: %s", resp.Status.Code, resp.Status.Message)
	}
	return nil
}
