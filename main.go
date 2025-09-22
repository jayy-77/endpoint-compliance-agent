package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"compliance-agent/analyzer"
	"compliance-agent/collector"
	"compliance-agent/report"
)

func main() {
	fmt.Println("Compliance Agent: collecting users and processes via osquery...")

	c := collector.NewOSQueryCollector()
	if err := c.HealthCheck(); err != nil {
		log.Fatalf("osquery not available: %v\nSet OSQUERY_SOCKET if needed, e.g. /var/osquery/osquery.em", err)
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
		AllowedUsers: []string{"root", "jaykumar"},
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
	rep := report.ComplianceReport{
		GeneratedAt: time.Now().UTC(),
		Hostname:    hostname,
		Users:       users,
		Processes:   procs,
		OpenPorts:   openPorts,
        Packages:    packages,
		Violations:  violations,
	}
	b, _ := rep.ToJSON()
	fmt.Println("Compliance Report JSON:")
	fmt.Println(string(b))
	if err := rep.SaveToFile("compliance_report.json"); err != nil {
		log.Printf("failed to save report: %v", err)
	} else {
		fmt.Println("Saved report to compliance_report.json")
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
