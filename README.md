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

### License
MIT


