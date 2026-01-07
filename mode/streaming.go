// Package mode contains agent run-modes. The default is one-shot (collect
// once and exit). Streaming mode runs forever, scoring on each tick.
package mode

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"compliance-agent/baseline"
	"compliance-agent/collector"
	"compliance-agent/config"
	"compliance-agent/exporter"
	"compliance-agent/ml"
)

// Runner is the dependency surface streaming mode talks through. main()
// builds the concrete impl; tests can swap in fakes.
type Runner struct {
	Cfg         config.Config
	Collector   collector.Collector
	Baseline    *baseline.Store
	Scorer      *ml.Scorer
	Exporter    *exporter.Server
	SnapshotLog *os.File // optional: append JSONL snapshots for training
}

// RunStreaming loops until ctx is cancelled, taking one snapshot per
// interval. Per-iteration error doesn't kill the loop — the agent's job
// is to keep producing observations.
func RunStreaming(ctx context.Context, r Runner) error {
	tick := time.NewTicker(r.Cfg.Interval)
	defer tick.Stop()

	// First snapshot immediately so we don't wait an interval to bootstrap.
	if err := r.once(ctx); err != nil {
		log.Printf("streaming: initial tick failed: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			if err := r.once(ctx); err != nil {
				log.Printf("streaming: tick failed: %v", err)
			}
		}
	}
}

func (r Runner) once(ctx context.Context) error {
	hostname, _ := os.Hostname()
	users, err := r.Collector.CollectUsers()
	if err != nil {
		return fmt.Errorf("users: %w", err)
	}
	procs, err := r.Collector.CollectProcesses(50)
	if err != nil {
		return fmt.Errorf("procs: %w", err)
	}
	ports, _ := r.Collector.CollectOpenPorts()
	pkgs, _ := r.Collector.CollectPackages(200)

	snap := baseline.SnapshotFromCollected(hostname, procs, ports, users, pkgs)
	r.Baseline.Update(snap)

	feats := ml.BuildFeatures(snap, r.Baseline.Data())
	score, model, scoreErr := r.Scorer.Score(ctx, feats)
	if scoreErr != nil {
		log.Printf("score failed (%s): %v", model, scoreErr)
	}

	out := map[string]any{
		"snapshot":  snap,
		"features":  feats,
		"score":     score,
		"model":     model,
		"anomaly":   score >= r.Cfg.ML.Threshold,
		"timestamp": snap.CollectedAt,
	}

	if r.Exporter != nil {
		b, _ := json.Marshal(out)
		r.Exporter.SetReport(b)
	}
	if r.SnapshotLog != nil {
		fb, _ := json.Marshal(feats)
		_, _ = r.SnapshotLog.Write(append(fb, '\n'))
	}
	return r.Baseline.Save()
}
