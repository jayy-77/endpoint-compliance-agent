package ml

import (
	"testing"

	"compliance-agent/baseline"
	"github.com/stretchr/testify/assert"
)

func TestBuildFeatures_UnknownRatios(t *testing.T) {
	snap := baseline.Snapshot{
		Processes: map[string]int{"chrome": 2, "newproc": 1},
		OpenPorts: []int{22, 9999},
	}
	base := baseline.Baseline{
		ProcessFreq: map[string]int{"chrome": 100},
		PortFreq:    map[int]int{22: 50},
	}
	f := BuildFeatures(snap, base)
	assert.InDelta(t, 0.5, f["unknown_process_ratio"], 1e-9)
	assert.InDelta(t, 0.5, f["unknown_port_ratio"], 1e-9)
	assert.Equal(t, 3.0, f["process_count"])
}

func TestBuildFeatures_ZScoresStableWithFlatSeries(t *testing.T) {
	snap := baseline.Snapshot{UserCount: 5}
	base := baseline.Baseline{
		UserCountSeries: []int{5, 5, 5, 5, 5},
	}
	f := BuildFeatures(snap, base)
	assert.InDelta(t, 0.0, f["user_count_zscore"], 1e-9)
}

func TestBuildFeatures_ZScoreDetectsSpike(t *testing.T) {
	snap := baseline.Snapshot{UserCount: 50}
	base := baseline.Baseline{
		UserCountSeries: []int{5, 5, 6, 4, 5, 6, 5},
	}
	f := BuildFeatures(snap, base)
	assert.Greater(t, f["user_count_zscore"], 4.0)
}
