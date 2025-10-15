// Package ml turns endpoint snapshots into numerical features and
// sends them to a Python anomaly scorer.
package ml

import (
	"math"

	"compliance-agent/baseline"
)

// FeatureOrder is the canonical vector layout shared between Go (collector)
// and Python (scorer). Keep in sync with ml_service/main.py FEATURE_ORDER.
var FeatureOrder = []string{
	"process_count",
	"unique_processes",
	"unknown_process_ratio",
	"open_port_count",
	"unknown_port_ratio",
	"user_count",
	"pkg_count",
	"process_count_zscore",
	"user_count_zscore",
	"pkg_count_zscore",
}

// Features is the Go-side counterpart to a Python feature dict.
type Features map[string]float64

// BuildFeatures derives a feature vector from a snapshot plus the baseline.
// Anything the baseline hasn't seen contributes to an "unknown_*" ratio,
// which is the most useful signal for ML behavioral detection.
func BuildFeatures(snap baseline.Snapshot, base baseline.Baseline) Features {
	totalProcs := 0
	uniqueProcs := len(snap.Processes)
	unknownProcs := 0
	for name, count := range snap.Processes {
		totalProcs += count
		if _, seen := base.ProcessFreq[name]; !seen {
			unknownProcs++
		}
	}
	unknownProcRatio := 0.0
	if uniqueProcs > 0 {
		unknownProcRatio = float64(unknownProcs) / float64(uniqueProcs)
	}

	unknownPorts := 0
	for _, p := range snap.OpenPorts {
		if _, seen := base.PortFreq[p]; !seen {
			unknownPorts++
		}
	}
	unknownPortRatio := 0.0
	if len(snap.OpenPorts) > 0 {
		unknownPortRatio = float64(unknownPorts) / float64(len(snap.OpenPorts))
	}

	return Features{
		"process_count":         float64(totalProcs),
		"unique_processes":      float64(uniqueProcs),
		"unknown_process_ratio": unknownProcRatio,
		"open_port_count":       float64(len(snap.OpenPorts)),
		"unknown_port_ratio":    unknownPortRatio,
		"user_count":            float64(snap.UserCount),
		"pkg_count":             float64(snap.PkgCount),
		"process_count_zscore":  zscore(float64(totalProcs), base.PkgCountSeries),
		"user_count_zscore":     zscore(float64(snap.UserCount), base.UserCountSeries),
		"pkg_count_zscore":      zscore(float64(snap.PkgCount), base.PkgCountSeries),
	}
}

func zscore(value float64, series []int) float64 {
	if len(series) < 2 {
		return 0
	}
	var sum, sumSq float64
	for _, v := range series {
		sum += float64(v)
		sumSq += float64(v) * float64(v)
	}
	n := float64(len(series))
	mean := sum / n
	variance := math.Max(sumSq/n-mean*mean, 0)
	if variance < 1e-9 {
		return 0
	}
	return (value - mean) / math.Sqrt(variance)
}
