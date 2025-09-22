<p align="center">
  <img src="assets/logo.svg" alt="Compliance Agent" width="520" />
</p>

## Compliance Agent

Compliance Agent is an open-source DevSecOps endpoint compliance tool written in Go. It collects system and security telemetry via osquery, evaluates simple compliance policies (e.g., allowed users and ports), and generates structured JSON reports that can be saved to disk or shipped elsewhere in future extensions.

<p align="center">
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white" alt="Go Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"></a>
  <a href="Dockerfile"><img src="https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white" alt="Docker"></a>
  <a href="https://github.com/jaykumar/endpoint-compliance-agent/pulls"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs welcome"></a>
</p>

### Features
- Collects users, processes, open ports, and installed packages using osquery
- Evaluates collected data against simple compliance policies
- Produces a structured JSON compliance report (writes to `compliance_report.json`)
- Modular design prepared for extensions (alerting, HTTP shipping, Docker)

### Architecture
- `collector`: osquery-based system data collection
- `analyzer`: policy definitions and evaluation logic
- `report`: JSON report struct, serialization, and file write helper
- `main.go`: orchestrates collection → analysis → report

### Prerequisites
- Go 1.22+
- osquery installed and running
  - Default socket path is `/var/osquery/osquery.em`
  - Override with env var `OSQUERY_SOCKET`

### Usage
Run directly from source:
```bash
go run ./...
```

Build and run the binary:
```bash
go build -o compliance-agent
./compliance-agent
```

Environment configuration:
- `OSQUERY_SOCKET`: Path to osquery extension socket (default `/var/osquery/osquery.em`)

### Output
The agent prints collected data and violations to stdout and writes a JSON report to `compliance_report.json`, for example:
```json
{
  "generated_at": "2025-09-22T10:00:00Z",
  "hostname": "host.example",
  "users": [ {"username": "root", "uid": "0" } ],
  "processes": [ ... ],
  "open_ports": [22, 80],
  "packages": [ {"name": "bash", "version": "5.2" } ],
  "violations": [ {"category": "user", "message": "unexpected user present: test"} ]
}
```

### Docker
Build the container image:
```bash
docker build -t compliance-agent .
```

Note: To use osquery inside containers, you typically need to run osquery on the host and provide access to its socket. Containerized usage may require additional configuration depending on your environment.

### Why Compliance Agent?
- Minimal runtime dependencies using osquery for rich, cross-platform system data
- Clear, structured JSON outputs that are easy to integrate with SIEM/ELK
- Simple policy model to start, designed for incremental hardening and features

### Roadmap
- HTTP exporter for sending reports to a central service
- Alerting integrations (Slack, email, SIEM)
- Additional collectors (firewall rules, deeper package metadata, OS hardening)
- Cross-platform support (macOS, Linux variants)

### Contributing
Contributions are welcome! Please open an issue to discuss significant changes. For small fixes and improvements:
1. Fork the repo
2. Create a feature branch
3. Commit with clear messages
4. Open a PR against `main`

### License
MIT


