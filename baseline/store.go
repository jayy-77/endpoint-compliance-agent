// Package baseline maintains a rolling record of "normal" endpoint state
// (process names, listening ports, package counts) and surfaces it to the
// ML scorer for behavioral anomaly detection (UEBA-lite).
//
// The store is intentionally simple — a JSON file on disk — so the agent
// stays single-binary friendly. Concurrency is internal to the agent
// process; no remote write contention is expected.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Snapshot captures one observation of endpoint state.
type Snapshot struct {
	CollectedAt time.Time      `json:"collected_at"`
	Hostname    string         `json:"hostname"`
	Processes   map[string]int `json:"processes"` // name -> count
	OpenPorts   []int          `json:"open_ports"`
	UserCount   int            `json:"user_count"`
	PkgCount    int            `json:"pkg_count"`
}

// Baseline is the aggregation of many snapshots.
type Baseline struct {
	StartedAt        time.Time      `json:"started_at"`
	LastUpdated      time.Time      `json:"last_updated"`
	SnapshotsSeen   int            `json:"snapshots_seen"`
	ProcessFreq      map[string]int `json:"process_freq"`     // total times each process name was seen
	PortFreq         map[int]int    `json:"port_freq"`
	UserCountSeries []int          `json:"user_count_series"`
	PkgCountSeries  []int          `json:"pkg_count_series"`
	MaxSeriesLen     int            `json:"max_series_len"`
}

// Store wraps a Baseline with thread-safe access and JSON persistence.
type Store struct {
	mu   sync.Mutex
	path string
	data *Baseline
}

const defaultSeriesLen = 256

func NewStore(path string) *Store {
	return &Store{path: path}
}

func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		s.data = &Baseline{
			StartedAt:    time.Now().UTC(),
			ProcessFreq:  map[string]int{},
			PortFreq:     map[int]int{},
			MaxSeriesLen: defaultSeriesLen,
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read baseline: %w", err)
	}
	var bl Baseline
	if err := json.Unmarshal(b, &bl); err != nil {
		return fmt.Errorf("parse baseline: %w", err)
	}
	if bl.ProcessFreq == nil {
		bl.ProcessFreq = map[string]int{}
	}
	if bl.PortFreq == nil {
		bl.PortFreq = map[int]int{}
	}
	if bl.MaxSeriesLen == 0 {
		bl.MaxSeriesLen = defaultSeriesLen
	}
	s.data = &bl
	return nil
}

func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

// Update folds a snapshot into the baseline.
func (s *Store) Update(snap Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.LastUpdated = snap.CollectedAt
	s.data.SnapshotsSeen++
	for name, count := range snap.Processes {
		s.data.ProcessFreq[name] += count
	}
	for _, p := range snap.OpenPorts {
		s.data.PortFreq[p]++
	}
	s.data.UserCountSeries = trim(append(s.data.UserCountSeries, snap.UserCount), s.data.MaxSeriesLen)
	s.data.PkgCountSeries = trim(append(s.data.PkgCountSeries, snap.PkgCount), s.data.MaxSeriesLen)
}

func trim(xs []int, maxLen int) []int {
	if len(xs) <= maxLen {
		return xs
	}
	return xs[len(xs)-maxLen:]
}

func (s *Store) Data() Baseline {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		return Baseline{}
	}
	return *s.data
}

// TopProcesses returns the n most frequently observed process names.
func (s *Store) TopProcesses(n int) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		return nil
	}
	type kv struct {
		name  string
		count int
	}
	pairs := make([]kv, 0, len(s.data.ProcessFreq))
	for k, v := range s.data.ProcessFreq {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].count > pairs[j].count })
	if n > len(pairs) {
		n = len(pairs)
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = pairs[i].name
	}
	return out
}
