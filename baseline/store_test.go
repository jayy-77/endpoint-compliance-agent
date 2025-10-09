package baseline

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_LoadCreatesEmpty(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(filepath.Join(dir, "b.json"))
	require.NoError(t, s.Load())
	assert.Equal(t, 0, s.Data().SnapshotsSeen)
}

func TestStore_UpdatePersistsBetweenLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "b.json")
	s := NewStore(path)
	require.NoError(t, s.Load())

	s.Update(Snapshot{
		CollectedAt: time.Now(),
		Processes:   map[string]int{"chrome": 5, "ssh": 1},
		OpenPorts:   []int{22, 80},
		UserCount:   3,
		PkgCount:    100,
	})
	require.NoError(t, s.Save())

	s2 := NewStore(path)
	require.NoError(t, s2.Load())
	d := s2.Data()
	assert.Equal(t, 1, d.SnapshotsSeen)
	assert.Equal(t, 5, d.ProcessFreq["chrome"])
	assert.Equal(t, 1, d.PortFreq[80])
	assert.Equal(t, []int{3}, d.UserCountSeries)
}

func TestStore_TopProcesses(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(filepath.Join(dir, "b.json"))
	require.NoError(t, s.Load())
	s.Update(Snapshot{Processes: map[string]int{"a": 10, "b": 2, "c": 5}})
	got := s.TopProcesses(2)
	assert.Equal(t, []string{"a", "c"}, got)
}

func TestStore_SeriesTrimsToMaxLen(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(filepath.Join(dir, "b.json"))
	require.NoError(t, s.Load())
	for i := 0; i < 300; i++ {
		s.Update(Snapshot{UserCount: i, PkgCount: i})
	}
	d := s.Data()
	assert.LessOrEqual(t, len(d.UserCountSeries), d.MaxSeriesLen)
}
