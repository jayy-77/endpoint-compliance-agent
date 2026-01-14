package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"compliance-agent/alerting"
	"compliance-agent/analyzer"
	"compliance-agent/baseline"
	"compliance-agent/collector"
	"compliance-agent/config"
	"compliance-agent/exporter"
	"compliance-agent/ml"
	"compliance-agent/mode"
	"compliance-agent/report"
)

func main() {
	// Parse command line flags
	testSlack := flag.Bool("test-slack", false, "Test Slack connection and send a test message")
	configPath := flag.String("config", "", "Path to YAML config (optional)")
	streaming := flag.Bool("streaming", false, "Run in streaming mode (loop forever)")
	flag.Parse()

	if *testSlack {
		fmt.Println("Testing Slack connection...")
		slackClient := alerting.NewSlackClient()
		if err := slackClient.TestConnection(); err != nil {
			log.Fatalf("Slack test failed: %v\nSet SLACK_WEBHOOK_URL environment variable", err)
		}
		fmt.Println("✅ Slack connection test successful!")
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config load: %v", err)
	}
	if *streaming {
		cfg.Mode = "streaming"
	}

	// Streaming mode short-circuits the one-shot flow.
	if cfg.Mode == "streaming" {
		runStreaming(cfg)
		return
	}

	fmt.Println("Compliance Agent: collecting system data...")

	var c collector.Collector = collector.NewOSQueryCollector()

	// Try to ensure osquery is running, fallback to basic collection if not
	if osqCollector, ok := c.(*collector.OSQueryCollector); ok {
		if err := osqCollector.EnsureOSQueryRunning(); err != nil {
			fmt.Printf("Using fallback data collection: %v\n", err)
			c = collector.NewFallbackCollector()
		}
	}

	users, err := c.CollectUsers()
	if err != nil {
		log.Fatalf("failed to collect users: %v", err)
	}
	procs, err := c.CollectProcesses(25)
	if err != nil {
		log.Fatalf("failed to collect processes: %v", err)
	}

	// Phase 5 additions: open ports and packages
	openPorts, err := c.CollectOpenPorts()
	if err != nil {
		log.Printf("failed to collect open ports: %v", err)
	}
	packages, err := c.CollectPackages(200)
	if err != nil {
		log.Printf("failed to collect packages: %v", err)
	}

	fmt.Println("Users:")
	dumpJSON(users)
	fmt.Println("Processes:")
	dumpJSON(procs)

	// Phase 3: simple compliance policies
	policies := analyzer.Policies{
		AllowedUsers: []string{"root", "admin"},
		AllowedPorts: []int{22, 80, 443},
	}
	userViolations := analyzer.AnalyzeUsers(users, policies)
	portViolations := analyzer.AnalyzePorts(openPorts, policies)
	fmt.Println("Compliance Violations (users):")
	dumpJSON(userViolations)
	fmt.Println("Compliance Violations (ports):")
	dumpJSON(portViolations)

	// Phase 4: build and save JSON report
	hostname, _ := os.Hostname()
	var violations []map[string]string
	for _, v := range userViolations {
		violations = append(violations, map[string]string{"category": v.Category, "message": v.Message})
	}
	for _, v := range portViolations {
		violations = append(violations, map[string]string{"category": v.Category, "message": v.Message})
	}
	// Behavioral / UEBA layer: build the baseline-aware feature vector,
	// score it, and attach the score to the report metadata so downstream
	// SIEM rules can branch on it.
	bstore := baseline.NewStore(cfg.Baseline.Path)
	if err := bstore.Load(); err != nil {
		log.Printf("baseline load: %v", err)
	}
	snap := baseline.SnapshotFromCollected(hostname, procs, openPorts, users, packages)
	bstore.Update(snap)
	feats := ml.BuildFeatures(snap, bstore.Data())
	scorer := ml.NewScorer(cfg.ML.URL, cfg.ML.Timeout)
	score, model, scoreErr := scorer.Score(context.Background(), feats)
	if scoreErr != nil {
		log.Printf("ml score failed: %v (model=%s)", scoreErr, model)
	}
	if err := bstore.Save(); err != nil {
		log.Printf("baseline save: %v", err)
	}
	mlMeta := map[string]interface{}{
		"score":     score,
		"model":     model,
		"threshold": cfg.ML.Threshold,
		"anomaly":   score >= cfg.ML.Threshold,
		"features":  feats,
	}

	rep := report.ComplianceReport{
		GeneratedAt:   time.Now().UTC(),
		Hostname:      hostname,
		Users:         users,
		Processes:     procs,
		OpenPorts:     openPorts,
		Packages:      packages,
		Violations:    violations,
		ExtraMetadata: map[string]interface{}{"ml": mlMeta},
	}
	b, _ := rep.ToJSON()
	fmt.Println("Compliance Report JSON:")
	fmt.Println(string(b))
	if err := rep.SaveToFile("compliance_report.json"); err != nil {
		log.Printf("failed to save report: %v", err)
	} else {
		fmt.Println("Saved report to compliance_report.json")
	}

	// Phase 5: Send alerts to Slack (if configured)
	slackClient := alerting.NewSlackClient()

	// Test Slack connection first
	if err := slackClient.TestConnection(); err != nil {
		fmt.Printf("Slack not configured or connection failed: %v\n", err)
		fmt.Println("To enable Slack alerts, set SLACK_WEBHOOK_URL environment variable")
	} else {
		fmt.Println("Slack connection successful! Sending compliance report...")

		// Convert report to Slack format
		slackReport := alerting.ComplianceReport{
			GeneratedAt:   rep.GeneratedAt,
			Hostname:      rep.Hostname,
			Users:         rep.Users,
			Processes:     rep.Processes,
			OpenPorts:     rep.OpenPorts,
			Packages:      rep.Packages,
			Violations:    rep.Violations,
			ExtraMetadata: rep.ExtraMetadata,
		}

		// Send compliance report
		if err := slackClient.SendComplianceReport(slackReport); err != nil {
			log.Printf("Failed to send compliance report to Slack: %v", err)
		} else {
			fmt.Println("✅ Compliance report sent to Slack successfully!")
		}

		// Send critical violation alerts if any
		if len(violations) > 0 {
			if err := slackClient.SendViolationAlert(hostname, violations); err != nil {
				log.Printf("Failed to send violation alert to Slack: %v", err)
			} else {
				fmt.Println("🚨 Violation alerts sent to Slack!")
			}
		}
	}
}

func dumpJSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Printf("json encode error: %v", err)
		return
	}
	fmt.Println(string(b))
}

// runStreaming wires up the agent dependencies and runs the streaming mode
// loop. It uses the same collector/baseline/ML stack as the one-shot path
// so we don't have two code paths drifting apart.
func runStreaming(cfg config.Config) {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var c collector.Collector = collector.NewOSQueryCollector()
	if osqC, ok := c.(*collector.OSQueryCollector); ok {
		if err := osqC.EnsureOSQueryRunning(); err != nil {
			log.Printf("osquery unavailable, using fallback: %v", err)
			c = collector.NewFallbackCollector()
		}
	}

	bstore := baseline.NewStore(cfg.Baseline.Path)
	if err := bstore.Load(); err != nil {
		log.Printf("baseline load: %v", err)
	}

	var exp *exporter.Server
	if cfg.Exporter.Enabled {
		exp = exporter.New(cfg.Exporter.Addr)
		go func() {
			log.Printf("exporter listening on %s", cfg.Exporter.Addr)
			if err := exp.ListenAndServe(); err != nil {
				log.Printf("exporter shutdown: %v", err)
			}
		}()
	}

	runner := mode.Runner{
		Cfg:       cfg,
		Collector: c,
		Baseline:  bstore,
		Scorer:    ml.NewScorer(cfg.ML.URL, cfg.ML.Timeout),
		Exporter:  exp,
	}
	if err := mode.RunStreaming(ctx, runner); err != nil && err != context.Canceled {
		log.Printf("streaming exited: %v", err)
	}
}
