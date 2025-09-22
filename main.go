package main

import (
    "encoding/json"
    "fmt"
    "log"

    "compliance-agent/analyzer"
    "compliance-agent/collector"
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

	fmt.Println("Users:")
	dumpJSON(users)
	fmt.Println("Processes:")
	dumpJSON(procs)

    // Phase 3: simple compliance policies
    policies := analyzer.Policies{
        AllowedUsers: []string{"root", "jaykumar"},
        AllowedPorts: []int{22, 80, 443},
    }
    // Placeholder: open ports collection will be added later; use an empty slice for now
    var openPorts []int
    userViolations := analyzer.AnalyzeUsers(users, policies)
    portViolations := analyzer.AnalyzePorts(openPorts, policies)
    fmt.Println("Compliance Violations (users):")
    dumpJSON(userViolations)
    fmt.Println("Compliance Violations (ports):")
    dumpJSON(portViolations)
}

func dumpJSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Printf("json encode error: %v", err)
		return
	}
	fmt.Println(string(b))
}
