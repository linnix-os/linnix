# Linnix

**Real-time system failure detection using eBPF.**

[![CI](https://github.com/linnix-os/linnix/actions/workflows/docker.yml/badge.svg)](https://github.com/linnix-os/linnix/actions/workflows/docker.yml)
[![License](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/linnixos/cognitod?style=flat-square)](https://github.com/linnix-os/linnix/pkgs/container/cognitod)
[![GitHub Stars](https://img.shields.io/github/stars/linnix-os/linnix?style=social)](https://github.com/linnix-os/linnix)

---

## Try It Now (30 seconds)

```bash
git clone https://github.com/linnix-os/linnix.git && cd linnix
./quickstart.sh
```

Linnix monitors real-time system events with **<1% CPU overhead** using eBPF.

**Optional: Run demo scenarios** to see detection in action:

```bash
# Enable demo mode in docker-compose.yml
sed -i 's/# command: \["cognitod"/command: ["cognitod"/' docker-compose.yml

# Restart to run 5 demo scenarios
docker-compose restart cognitod
```

**Demo scenarios:**
- **Fork bomb** - detects >10 forks/second for 2s
- **Memory leak** - detects gradual RSS growth pattern
- **CPU spike** - detects sustained high CPU (>50% for 5s)
- **Runaway tree** - detects high CPU parent+child processes
- **Short-lived jobs** - detects exec/exit cycle patterns

<p align="center">
  <img src="docs/images/linnix-demo.gif" alt="Linnix detecting a fork storm" width="800"/>
</p>

**Dashboard:** http://localhost:3000 | **API:** http://localhost:3000/alerts | **Enforcement:** http://localhost:3000/actions

---

---

## Modes

Linnix runs in two modes, configured in `linnix.toml`:

- **`monitor` (Default)**: Safe by default. Detects failures and proposes actions, but **NEVER** executes them automatically. Requires human approval via API.
- **`enforce`**: Advanced mode. Automatically executes actions (like killing processes) when strict safety rules are met.

---

## Human-in-the-Loop Enforcement

![Enforcement Demo](docs/images/enforcement-demo.gif)

When AI detects system failures, it proposes enforcement actions—but only humans can approve them.

```bash
# 1. AI detects issue and proposes action
[eBPF] CPU spike: 92% for 8 seconds
[LLM]  Proposes: kill 31337

# 2. Review pending action
$ curl http://localhost:3000/actions
[{"id": "action-1", "action": {"type": "kill_process", "pid": 31337}, "status": "pending"}]

# 3. Human approves
$ curl -X POST http://localhost:3000/actions/action-1/approve -d '{"approver": "sre-alice"}'

# 4. Audit trail
$ docker logs cognitod | grep APPROVED
[linnix_audit] APPROVED action-1 by sre-alice
```

**Why human approval?** Security (no prompt injection), compliance (audit trail), trust (progressive automation).

**API:** `GET /actions`, `GET /actions/{id}`, `POST /actions/{id}/approve`, `POST /actions/{id}/reject`

See [DEMO_ENFORCEMENT.md](DEMO_ENFORCEMENT.md) for full walkthrough.

---

## How It Works

Linnix can detect 5 different failure patterns (when demo mode is enabled):

| Scenario | Detection Rule | Trigger |
|----------|----------------|---------|
| Fork bomb | forks_per_sec | >10 forks/second for 2s |
| Memory leak | subtree_rss_mb | Gradual growth pattern |
| CPU spike | subtree_cpu_pct | >50% CPU for 5s |
| Runaway tree | High CPU subtree | Parent+child >90% CPU |
| Short-lived jobs | Rapid exec/exit | Process churn detection |
| **Circuit Breaker** | **PSI + CPU Saturation** | **>90% CPU + >40% PSI (Stall) for 15s** |

**How?** eBPF monitors at the kernel level (fork, exec, exit events). Rules engine analyzes patterns and alerts in real-time.

All detection rules are configurable in `configs/rules.yaml`

### 🛡️ Circuit Breaker with Grace Period
Prevents system thrashing by monitoring **Pressure Stall Information (PSI)**.
- **Dual-Signal Detection**: Triggers only when CPU is high (>90%) **AND** processes are actually stalled (>40% PSI).
- **Grace Period**: Configurable delay (default 15s) prevents killing processes during transient spikes.
- **Incident Analysis**: Automatically captures system state and uses LLM to analyze the root cause.

### Deploy to Kubernetes

Linnix can be deployed as a DaemonSet to monitor every node in your cluster.

```bash
# Apply the manifests
kubectl apply -f k8s/

# Check status
kubectl get daemonset -n default linnix-agent
```

See [k8s/README.md](k8s/README.md) for advanced configuration (RBAC, capabilities).

## Configuration:
```toml
[circuit_breaker]
enabled = true
cpu_usage_threshold = 90.0
cpu_psi_threshold = 40.0
grace_period_secs = 15  # Prevents false positives
```

---

## Installation (After Demo)

### Docker (Recommended)

```bash
git clone https://github.com/linnix-os/linnix.git && cd linnix
docker-compose up -d
```

- **Dashboard:** http://localhost:3000
- **API:** http://localhost:3000/alerts
- **Prometheus:** http://localhost:3000/metrics

### Native Install (Ubuntu 22.04+)

```bash
# Download and install (runs as your user - no sudo needed)
curl -fsSL https://raw.githubusercontent.com/linnix-os/linnix/main/install.sh | bash

# Or manually:
wget https://github.com/linnix-os/linnix/releases/latest/download/cognitod-linux-amd64
chmod +x cognitod-linux-amd64

# Grant capabilities (one-time, requires sudo)
sudo setcap cap_bpf+eip cap_perfmon+eip cognitod-linux-amd64

# Run (no sudo needed)
./cognitod-linux-amd64
```

**Requirements:**
- Linux 5.8+ with BTF enabled (`ls /sys/kernel/btf/vmlinux`)
- Docker (for containerized deployment) - no sudo needed if in docker group
- 2+ vCPU, 4GB+ RAM (8GB if using LLM)

**Security:** Linnix uses minimal Linux capabilities (CAP_BPF + CAP_PERFMON) instead of root. See [SECURITY.md](SECURITY.md).

**Uninstall:**
```bash
# Stop user service
systemctl --user stop linnix-cognitod
systemctl --user disable linnix-cognitod

# Or stop system service (if installed system-wide)
sudo systemctl stop linnix-cognitod
sudo systemctl disable linnix-cognitod
```

---

## Demo Mode

Run simulated system failures to test detection rules:

```bash
# Run all 5 demo scenarios
docker exec linnix-cognitod cognitod --demo all

# Or run specific scenarios
docker exec linnix-cognitod cognitod --demo fork-storm
docker exec linnix-cognitod cognitod --demo cpu-spike
docker exec linnix-cognitod cognitod --demo memory-leak
docker exec linnix-cognitod cognitod --demo runaway-tree
docker exec linnix-cognitod cognitod --demo short-jobs
```

**Watch demo output:**
```bash
docker logs -f linnix-cognitod | grep -i demo
curl -N http://localhost:3000/stream  # Watch alerts in real-time
```

---

## What Linnix Does

### Core Monitoring (eBPF)

Monitors at the kernel level using eBPF:
- Process lifecycle: fork, exec, exit
- CPU/memory telemetry from scheduler
- File descriptor tracking
- Network connection monitoring

- Network connection monitoring

**<1% CPU overhead** - no polling `/proc`, direct kernel events via perf buffers. See [Performance Benchmarks](docs/OVERHEAD.md).

### Detection (Rules Engine)

Built-in pattern detection catches:
- **Fork storms** - rapid process spawning (>10/sec)
- **Memory leaks** - gradual RSS growth (>50MB/10s)
- **CPU thrashing** - processes stuck in loops
- **FD exhaustion** - files not closed (approaching limit)

### Incident Forensics
- **Incident Store**: Stores full incident context (snapshots, process tree) in SQLite for post-mortem analysis.
- **LLM Analysis**: Automatically analyzes root cause and suggests fixes.

### Optional: Local LLM Analysis

- Runs llama.cpp with 3B quantized model
- Analyzes patterns the rules engine flags
- **Completely optional** - rules engine works standalone
- No external API calls (privacy-first)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Kernel Space (eBPF)                       │
├──────────────────────────────────────────────────────────────┤
│  fork hook  →  exec hook  →  exit hook  →  CPU/mem sampling  │
└────────────────────────┬─────────────────────────────────────┘
                         │ Perf buffers
                         ▼
┌──────────────────────────────────────────────────────────────┐
│                   User Space (cognitod)                      │
├──────────────────────────────────────────────────────────────┤
│  • Event processing    • Process tree tracking               │
│  • State management    • Rules engine                        │
│  • HTTP/SSE API        • Prometheus metrics                  │
│  • Incident Store (SQLite)                                   │
└────────────────────────┬─────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
   ┌─────────┐    ┌──────────┐   ┌─────────────┐
   │ CLI     │    │ LLM      │   │ Prometheus  │
   │ Stream  │    │(Optional)│   │ Grafana     │
   └─────────┘    └──────────┘   └─────────────┘
```
