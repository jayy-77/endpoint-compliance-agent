package main

import (
    "encoding/json"
    "fmt"
    "log"

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
}

func dumpJSON(v any) {
    b, err := json.MarshalIndent(v, "", "  ")
    if err != nil {
        log.Printf("json encode error: %v", err)
        return
    }
    fmt.Println(string(b))
}
