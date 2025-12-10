package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefault_NoEnv(t *testing.T) {
	c := Default()
	assert.Equal(t, "oneshot", c.Mode)
	assert.Equal(t, 5*time.Minute, c.Interval)
	assert.InDelta(t, 0.7, c.ML.Threshold, 1e-9)
}

func TestLoad_MissingFileIsDefault(t *testing.T) {
	c, err := Load("/no/such/path.yaml")
	require.NoError(t, err)
	assert.Equal(t, Default().Mode, c.Mode)
}

func TestLoad_OverridesFromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
mode: streaming
interval: 1m
ml:
  url: http://ml:8000/score
  threshold: 0.5
exporter:
  enabled: true
  addr: ":9101"
`), 0o644))

	c, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, "streaming", c.Mode)
	assert.Equal(t, time.Minute, c.Interval)
	assert.Equal(t, "http://ml:8000/score", c.ML.URL)
	assert.InDelta(t, 0.5, c.ML.Threshold, 1e-9)
	assert.True(t, c.Exporter.Enabled)
}
