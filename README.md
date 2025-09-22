## Compliance Agent (DevSecOps)

Go-based endpoint compliance agent that collects system/security data using osquery, evaluates simple policies, and generates JSON reports.

### Phases
- Phase 1: Project Skeleton & Basic Binary
- Phase 2: Collect System Data via osquery (users, processes)
- Phase 3: Check Compliance Rules (allowed users, allowed ports)
- Phase 4: Generate JSON Reports
- Phase 5: Add Firewall & Package Checks
- Phase 6: Modularize for Extensions (collector/analyzer/report)
- Phase 7 (Optional): Dockerize & Periodic Execution

### Quick Start
```bash
go run ./...
```

### Requirements
- Go 1.22+
- osquery daemon running (e.g., socket at /var/osquery/osquery.em)

### Roadmap
- HTTP shipping, alerting, Docker support
- Additional collectors (open ports, firewall, packages)
- Cross-platform support

### Folder Structure
```
compliance-agent/
├── main.go
├── collector/
│   └── osquery.go
├── analyzer/
│   └── compliance.go
├── report/
│   └── report.go
├── Dockerfile (optional)
├── go.mod
├── go.sum
└── README.md
```

### Suggested Phases and Commit Messages
- Phase 1: chore: initialize project and main binary skeleton
- Phase 2: feat: collect users and processes via osquery
- Phase 3: feat: add compliance rules for users and ports
- Phase 4: feat: generate JSON compliance report
- Phase 5: feat: include firewall rules and installed packages
- Phase 6: refactor: modularize code for extensibility
- Phase 7: feat: dockerize agent and add periodic execution

### License
MIT


