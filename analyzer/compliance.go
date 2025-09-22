package analyzer

import (
    "fmt"
    "sort"
)

type Policies struct {
    AllowedUsers []string
    AllowedPorts []int
}

type Violation struct {
    Category string `json:"category"`
    Message  string `json:"message"`
}

type AnalysisResult struct {
    Violations []Violation `json:"violations"`
}

// AnalyzeUsers checks if collected users are a subset of allowed users.
func AnalyzeUsers(collectedUsers []map[string]string, policies Policies) []Violation {
    allowed := make(map[string]struct{})
    for _, u := range policies.AllowedUsers {
        allowed[u] = struct{}{}
    }
    var v []Violation
    for _, row := range collectedUsers {
        username := row["username"]
        if username == "" {
            continue
        }
        if _, ok := allowed[username]; !ok {
            v = append(v, Violation{
                Category: "user",
                Message:  fmt.Sprintf("unexpected user present: %s", username),
            })
        }
    }
    return v
}

// AnalyzePorts checks if open/listening ports are in the allowed set.
// Pass a slice of port numbers. Collection added in later phases.
func AnalyzePorts(openPorts []int, policies Policies) []Violation {
    allowed := make(map[int]struct{})
    for _, p := range policies.AllowedPorts {
        allowed[p] = struct{}{}
    }
    sort.Ints(openPorts)
    var v []Violation
    for _, p := range openPorts {
        if _, ok := allowed[p]; !ok {
            v = append(v, Violation{
                Category: "port",
                Message:  fmt.Sprintf("unexpected open port: %d", p),
            })
        }
    }
    return v
}


