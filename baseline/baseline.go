package baseline

import "time"

// SnapshotFromCollected builds a Snapshot from the raw maps the collectors return.
// Kept in this package so callers don't need to know how processes are
// aggregated (by name → count).
func SnapshotFromCollected(
	hostname string,
	processes []map[string]string,
	openPorts []int,
	users []map[string]string,
	packages []map[string]string,
) Snapshot {
	procCounts := map[string]int{}
	for _, p := range processes {
		name := p["name"]
		if name == "" {
			continue
		}
		procCounts[name]++
	}
	return Snapshot{
		CollectedAt: time.Now().UTC(),
		Hostname:    hostname,
		Processes:   procCounts,
		OpenPorts:   openPorts,
		UserCount:   len(users),
		PkgCount:    len(packages),
	}
}
