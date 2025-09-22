package collector

import (
	"fmt"
	"os"
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
	// Use a lightweight API to ensure connectivity
	_, err = client.GetQueries()
	if err != nil {
		// Some setups may not enable distributed; fallback to a simple query
		_, qErr := client.Query("SELECT 1 as ok;")
		if qErr != nil {
			return fmt.Errorf("osquery health check failed: %v / %v", err, qErr)
		}
	}
	return nil
}
