#!/bin/bash
# Generates GitHub Wiki pages from source code
# Code is the source of truth

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WIKI_DIR="${PROJECT_ROOT}/wiki"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Generating Linnix GitHub Wiki${NC}"
echo "Output directory: $WIKI_DIR"
echo ""

mkdir -p "$WIKI_DIR"

# ============================================================================
# Helper Functions
# ============================================================================

extract_routes() {
    grep -E '\.route\("/' "$PROJECT_ROOT/cognitod/src/api/mod.rs" | \
        sed 's/.*\.route("\([^"]*\)", \(get\|post\|put\|delete\).*/| `\1` | \U\2\E |/' | \
        sort -u
}

extract_config_sections() {
    grep -E '^\[' "$PROJECT_ROOT/configs/linnix.toml" | \
        sed 's/\[/| `/; s/\]/` |/'
}

# ============================================================================
# Generate Home.md
# ============================================================================

echo -e "${GREEN}Generating Home.md${NC}"
cat > "$WIKI_DIR/Home.md" << 'EOF'
# Linnix Wiki

Welcome to the official Linnix documentation wiki.

**Linnix** is an eBPF-powered Linux observability platform with AI-assisted incident triage for Kubernetes and bare-metal systems.

## Quick Navigation

| Section | Description |
|---------|-------------|
| [Getting Started](Getting-Started) | Installation and first steps |
| [Architecture Overview](Architecture-Overview) | System design and components |
| [API Reference](API-Reference) | HTTP API endpoints |
| [Configuration Guide](Configuration-Guide) | Config file options |
| [CLI Reference](CLI-Reference) | Command-line tool usage |
| [Collector Guide](Collector-Guide) | eBPF probe documentation |
| [Safety Model](Safety-Model) | Security and enforcement guarantees |
| [Troubleshooting](Troubleshooting) | Common issues and solutions |

## Component Overview

| Component | Purpose | Port |
|-----------|---------|------|
| cognitod | Main daemon - eBPF loader, event processor, API server | 3000 |
| linnix-cli | CLI client for querying cognitod | - |
| linnix-reasoner | LLM integration for AI insights | - |
| llama-server | Local LLM inference (optional) | 8090 |

## Key Features

- **Low Overhead**: <1% CPU using eBPF ring buffers
- **AI-Powered Triage**: Local LLM explains incident root causes
- **Monitor-First**: Never takes action without human approval
- **Privacy-First**: All analysis happens locally

## Quick Start

```bash
# Docker (fastest)
git clone https://github.com/linnix-os/linnix.git && cd linnix
./quickstart.sh

# Kubernetes
kubectl apply -f k8s/
kubectl port-forward svc/linnix-dashboard 3000:3000
```

---
*This wiki is auto-generated from source code. Code is the source of truth.*
EOF

# ============================================================================
# Generate API-Reference.md
# ============================================================================

echo -e "${GREEN}Generating API-Reference.md${NC}"
cat > "$WIKI_DIR/API-Reference.md" << 'EOF'
# API Reference

Base URL: `http://localhost:3000`

## Authentication

Set the `LINNIX_API_TOKEN` environment variable to enable Bearer token authentication.

```bash
# With auth enabled
curl -H "Authorization: Bearer <token>" http://localhost:3000/status
```

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
EOF

# Extract routes from code and append
grep -E '\.route\("/' "$PROJECT_ROOT/cognitod/src/api/mod.rs" 2>/dev/null | \
    sed 's/.*\.route("\([^"]*\)", \(get\|post\|put\|delete\|axum::routing::\(get\|post\)\).*/| `\1` | \U\2\E | - |/' | \
    sed 's/AXUM::ROUTING::GET/GET/; s/AXUM::ROUTING::POST/POST/' | \
    sort -u >> "$WIKI_DIR/API-Reference.md"

cat >> "$WIKI_DIR/API-Reference.md" << 'EOF'

## Detailed Endpoint Documentation

### Health & Status

#### GET /healthz
Returns health status of the daemon.

```bash
curl http://localhost:3000/healthz
# {"status":"ok","version":"0.1.0"}
```

#### GET /status
Returns detailed system status including probe state and reasoner config.

```bash
curl http://localhost:3000/status | jq
```

### Process Monitoring

#### GET /processes
Returns all tracked processes with CPU/memory metrics.

```bash
curl http://localhost:3000/processes | jq
```

#### GET /graph/{pid}
Returns process tree ancestry for the given PID.

```bash
curl http://localhost:3000/graph/1234 | jq
```

### Event Streaming

#### GET /stream
Server-Sent Events (SSE) stream of real-time process events.

```bash
curl -N http://localhost:3000/stream
```

### Insights & Incidents

#### GET /insights
Returns AI-generated insights about current system state.

```bash
curl http://localhost:3000/insights | jq
```

#### GET /incidents
Returns list of detected incidents.

```bash
curl http://localhost:3000/incidents | jq
```

### Metrics

#### GET /metrics
Returns metrics in JSON format.

```bash
curl http://localhost:3000/metrics | jq
```

#### GET /metrics/prometheus
Returns metrics in Prometheus text exposition format.

```bash
curl http://localhost:3000/metrics/prometheus
```

---
*Source: `cognitod/src/api/mod.rs`*
EOF

# ============================================================================
# Generate Configuration-Guide.md
# ============================================================================

echo -e "${GREEN}Generating Configuration-Guide.md${NC}"
cat > "$WIKI_DIR/Configuration-Guide.md" << 'EOF'
# Configuration Guide

## Config File Location

Cognitod searches for configuration in this order:
1. `LINNIX_CONFIG` environment variable
2. `--config` command-line flag
3. `/etc/linnix/linnix.toml` (default)

## Configuration Sections

EOF

# Add sections from actual config file
if [ -f "$PROJECT_ROOT/configs/linnix.toml" ]; then
    echo '```toml' >> "$WIKI_DIR/Configuration-Guide.md"
    cat "$PROJECT_ROOT/configs/linnix.toml" >> "$WIKI_DIR/Configuration-Guide.md"
    echo '```' >> "$WIKI_DIR/Configuration-Guide.md"
fi

cat >> "$WIKI_DIR/Configuration-Guide.md" << 'EOF'

## Section Reference

### [api]
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen_addr` | string | "127.0.0.1:3000" | HTTP server bind address |
| `auth_token` | string | null | Optional API authentication token |

### [runtime]
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `offline` | bool | false | Disable all external HTTP egress |

### [telemetry]
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `sample_interval_ms` | u64 | 1000 | CPU/memory sampling interval |
| `retention_seconds` | u64 | 60 | Event retention window |

### [reasoner]
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | true | Enable AI reasoning |
| `endpoint` | string | "http://localhost:8090/v1/chat/completions" | LLM endpoint URL |
| `model` | string | "linnix-3b-distilled" | Model name |
| `window_seconds` | u64 | 10 | Analysis window |
| `timeout_ms` | u64 | 30000 | Request timeout |
| `min_eps_to_enable` | u64 | 10 | Minimum events/sec threshold |

### [prometheus]
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | true | Enable /metrics/prometheus endpoint |

### [notifications.apprise]
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `urls` | Vec<string> | [] | Apprise notification URLs |
| `min_severity` | string | "info" | Minimum severity to notify |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `LINNIX_CONFIG` | Override config file path |
| `LINNIX_BPF_PATH` | Override eBPF object path |
| `LINNIX_LISTEN_ADDR` | Override listen address |
| `LINNIX_API_TOKEN` | Set API authentication token |
| `LLM_ENDPOINT` | Override LLM endpoint |
| `LLM_MODEL` | Override LLM model |
| `OPENAI_API_KEY` | API key for OpenAI-compatible endpoints |

---
*Source: `cognitod/src/config.rs`*
EOF

# ============================================================================
# Generate CLI-Reference.md
# ============================================================================

echo -e "${GREEN}Generating CLI-Reference.md${NC}"
cat > "$WIKI_DIR/CLI-Reference.md" << 'EOF'
# CLI Reference

The `linnix-cli` tool provides command-line access to cognitod.

## Installation

```bash
cargo install --path linnix-cli
```

## Global Options

| Option | Description |
|--------|-------------|
| `--host <URL>` | Cognitod server URL (default: http://127.0.0.1:3000) |
| `-h, --help` | Show help |
| `-V, --version` | Show version |

## Commands

### doctor
Check system health and connectivity.

```bash
linnix-cli doctor
```

### processes
List all tracked processes.

```bash
linnix-cli processes
```

### stream
Stream real-time events from cognitod.

```bash
linnix-cli stream
```

### alerts
View recent alerts.

```bash
linnix-cli alerts
```

### export
Export data in various formats.

```bash
linnix-cli export --format json --output data.json
```

### stats
Show system statistics.

```bash
linnix-cli stats
```

### metrics
Display metrics.

```bash
linnix-cli metrics
```

---
*Source: `linnix-cli/src/main.rs`*
EOF

# ============================================================================
# Generate Collector-Guide.md
# ============================================================================

echo -e "${GREEN}Generating Collector-Guide.md${NC}"
cat > "$WIKI_DIR/Collector-Guide.md" << 'EOF'
# eBPF Collector Guide

The Linnix collector uses eBPF to capture kernel events with minimal overhead.

## Probe Inventory

### Mandatory Probes (Lifecycle)
| Purpose | Hook | Type |
|---------|------|------|
| Process exec | `sched/sched_process_exec` | Tracepoint |
| Process fork | `sched/sched_process_fork` | Tracepoint |
| Process exit | `sched/sched_process_exit` | Tracepoint |

### Optional Probes (Telemetry)
| Purpose | Hook | Type | Default |
|---------|------|------|---------|
| TCP send/recv | `tcp_sendmsg`, `tcp_recvmsg` | kprobe | Disabled |
| UDP send/recv | `udp_sendmsg`, `udp_recvmsg` | kprobe | Disabled |
| File I/O | `vfs_read`, `vfs_write` | kprobe | Disabled |
| Block I/O | `block/block_bio_queue` | Tracepoint | Disabled |
| Page faults | `page_fault_*` | BTF Tracepoint | Requires BTF |

## Kernel Requirements

| Kernel | Support Level |
|--------|--------------|
| 5.4+ | Basic (sched tracepoints) |
| 5.8+ | Full (BTF support) |
| 5.15+ | Enhanced (page fault tracking) |

## Required Capabilities

```
CAP_BPF       - Load eBPF programs
CAP_PERFMON   - Read perf events
CAP_SYS_ADMIN - Required on older kernels
```

## Building eBPF Programs

```bash
# Requires Rust nightly-2024-12-10
cargo xtask build-ebpf
```

Output: `target/bpfel-unknown-none/release/linnix-ai-ebpf-ebpf`

## BPF Object Search Path

1. `LINNIX_BPF_PATH` environment variable
2. `/usr/local/share/linnix/linnix-ai-ebpf-ebpf`
3. `target/bpfel-unknown-none/release/linnix-ai-ebpf-ebpf`
4. `target/bpf/*.o` (fallback)

## BTF Support

Check if your system has BTF:
```bash
ls -la /sys/kernel/btf/vmlinux
```

If present, Linnix can derive struct offsets dynamically for enhanced telemetry.

---
*Source: `docs/collector.md`, `linnix-ai-ebpf/`*
EOF

# ============================================================================
# Generate Safety-Model.md
# ============================================================================

echo -e "${GREEN}Generating Safety-Model.md${NC}"
cat > "$WIKI_DIR/Safety-Model.md" << 'EOF'
# Safety Model

Linnix is designed with safety as the #1 priority.

## Monitor-First Guarantee

By default, Linnix runs in **Monitor Mode**:

✅ **What it does:**
- Detects incidents
- Logs events
- Sends alerts
- Proposes remediation actions

❌ **What it does NOT do:**
- Execute kill/throttle actions
- Modify running processes
- Change system configuration

## Enforcement Safety Rails

When enforcement is explicitly enabled:

### Protected Processes
- PID 1 (init) - Never killed
- Kernel threads - Never killed
- Allowlisted processes (kubelet, containerd, systemd)

### Grace Periods
- Minimum 15 seconds before any action
- Configurable per detection rule
- Multiple confirmation thresholds

### Code Reference
```rust
// From cognitod/src/enforcement/safety.rs
fn is_protected(pid: u32, comm: &str) -> bool {
    if pid == 1 { return true; }
    if is_kernel_thread(pid) { return true; }
    ALLOWLIST.contains(comm)
}
```

## AI Safety

The LLM is used for **analysis only**, never for real-time decisions:

```
Decision Path: Rules Engine (Rust) → Alert
Analysis Path: Alert → LLM → Explanation
```

The LLM cannot trigger enforcement actions.

## Privilege Requirements

| Capability | Purpose | Risk |
|------------|---------|------|
| CAP_BPF | Load eBPF programs | Read-only kernel access |
| CAP_PERFMON | Read trace events | Process visibility |
| CAP_NET_ADMIN | Network monitoring | Optional |

**Not required:** `privileged: true`, full root access

---
*Source: `SAFETY.md`, `cognitod/src/enforcement/safety.rs`*
EOF

# ============================================================================
# Generate Getting-Started.md
# ============================================================================

echo -e "${GREEN}Generating Getting-Started.md${NC}"
cat > "$WIKI_DIR/Getting-Started.md" << 'EOF'
# Getting Started

## Prerequisites

- Linux kernel 5.4+ (5.8+ recommended)
- Docker and Docker Compose (for quick start)
- Or: Rust toolchain (for building from source)

## Quick Start with Docker

```bash
git clone https://github.com/linnix-os/linnix.git
cd linnix
./quickstart.sh
```

This starts:
- **cognitod** on port 3000 (dashboard & API)
- **llama-server** on port 8090 (local LLM)

## Quick Start on Kubernetes

```bash
kubectl apply -f k8s/
kubectl port-forward svc/linnix-dashboard 3000:3000
```

Open http://localhost:3000

## Verify Installation

```bash
# Health check
curl http://localhost:3000/healthz
# Expected: {"status":"ok","version":"..."}

# System status
curl http://localhost:3000/status | jq

# Real-time events
curl -N http://localhost:3000/stream
```

## First Steps

1. **Watch the dashboard**: Open http://localhost:3000
2. **Generate activity**: Run `stress --cpu 2 --timeout 10`
3. **View insights**: `curl http://localhost:3000/insights | jq`
4. **Use the CLI**: `linnix-cli doctor`

## Next Steps

- [Configuration Guide](Configuration-Guide) - Customize settings
- [API Reference](API-Reference) - Full endpoint documentation
- [Safety Model](Safety-Model) - Understand guarantees

---
*Source: `README.md`, `quickstart.sh`*
EOF

# ============================================================================
# Generate Architecture-Overview.md
# ============================================================================

echo -e "${GREEN}Generating Architecture-Overview.md${NC}"
cat > "$WIKI_DIR/Architecture-Overview.md" << 'EOF'
# Architecture Overview

## System Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        Kernel Space                             │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  eBPF Probes                                             │   │
│  │  • sched_process_exec  • sched_process_fork             │   │
│  │  • sched_process_exit  • (optional: net, io, syscall)   │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         │ Perf Buffer                           │
└─────────────────────────┼───────────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                        User Space                               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Cognitod Daemon                                          │  │
│  │  ┌─────────┐  ┌──────────┐  ┌─────────┐  ┌────────────┐ │  │
│  │  │ Runtime │→ │ Handlers │→ │ Context │→ │ API Server │ │  │
│  │  └─────────┘  └──────────┘  └─────────┘  └────────────┘ │  │
│  │       │                                        │          │  │
│  │       ▼                                        ▼          │  │
│  │  ┌─────────┐                           ┌──────────────┐  │  │
│  │  │ Alerts  │                           │ HTTP :3000   │  │  │
│  │  └─────────┘                           └──────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────┐    ┌──────────────────────────────────┐  │
│  │  linnix-cli      │◄──►│  External: Slack, Prometheus     │  │
│  └──────────────────┘    └──────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. eBPF Probes (Kernel Space)
- **Location**: `linnix-ai-ebpf/linnix-ai-ebpf-ebpf/src/program.rs`
- **Function**: Capture process lifecycle events
- **Overhead**: <1% CPU

### 2. Cognitod (User Space Daemon)
- **Location**: `cognitod/src/main.rs`
- **Function**: Event processing, state management, API server
- **Key modules**:
  - `runtime/` - eBPF loading, perf buffer polling
  - `handler/` - Event processing pipeline
  - `api/` - HTTP endpoints (Axum)
  - `context.rs` - Process state tracking
  - `alerts.rs` - Alert generation

### 3. Handler Pipeline
- **JSONL Handler**: Append events to file
- **Rules Handler**: YAML-based detection rules
- **ILM Handler**: Integrated LLM insights

### 4. API Server
- **Framework**: Axum
- **Port**: 3000 (default)
- **Endpoints**: /healthz, /status, /stream, /insights, etc.

### 5. CLI Client
- **Location**: `linnix-cli/src/`
- **Function**: Query API, stream events

## Data Flow

```
Kernel → Perf Buffer → Cognitod → Handlers → [Alerts, Insights, API] → CLI/Dashboard
```

---
*Source: `docs/architecture.md`, source code analysis*
EOF

# ============================================================================
# Generate Troubleshooting.md
# ============================================================================

echo -e "${GREEN}Generating Troubleshooting.md${NC}"
cat > "$WIKI_DIR/Troubleshooting.md" << 'EOF'
# Troubleshooting

## Common Issues

### eBPF Load Failure

**Symptom**: "Failed to load eBPF program"

**Solutions**:
1. Check kernel version: `uname -r` (need 5.4+)
2. Verify capabilities: `getcap /usr/local/bin/cognitod`
3. Check BTF: `ls /sys/kernel/btf/vmlinux`
4. Run with sudo for initial testing

### API Not Responding

**Symptom**: `curl localhost:3000/healthz` fails

**Solutions**:
1. Check if running: `systemctl status cognitod`
2. Check logs: `journalctl -u cognitod -f`
3. Verify listen address in config
4. Check port conflicts: `netstat -tlnp | grep 3000`

### No Insights Generated

**Symptom**: `/insights` returns empty

**Solutions**:
1. Check LLM server: `curl localhost:8090/health`
2. Verify reasoner config in linnix.toml
3. Check `min_eps_to_enable` threshold
4. Generate some activity: `stress --cpu 1 --timeout 10`

### High CPU Usage

**Symptom**: cognitod using >5% CPU

**Solutions**:
1. Increase `sample_interval_ms`
2. Disable optional probes
3. Check for fork storms on host
4. Review event rate: `curl localhost:3000/metrics | jq .events_per_second`

## Diagnostic Commands

```bash
# Service status
systemctl status cognitod

# View logs
journalctl -u cognitod -f

# Health check
curl http://localhost:3000/healthz

# Full status
curl http://localhost:3000/status | jq

# Check eBPF programs
bpftool prog list | grep linnix

# Run doctor
linnix-cli doctor

# Check metrics
curl http://localhost:3000/metrics | jq
```

## Log Analysis

```bash
# Filter errors
journalctl -u cognitod --since "1 hour ago" | grep -E "ERROR|error|failed"

# Check startup
journalctl -u cognitod | head -50
```

---
*For additional help, open an issue on GitHub.*
EOF

# ============================================================================
# Generate _Sidebar.md
# ============================================================================

echo -e "${GREEN}Generating _Sidebar.md${NC}"
cat > "$WIKI_DIR/_Sidebar.md" << 'EOF'
**[[Home]]**

**Getting Started**
* [[Getting Started]]
* [[Architecture Overview]]

**Reference**
* [[API Reference]]
* [[Configuration Guide]]
* [[CLI Reference]]

**Deep Dives**
* [[Collector Guide]]
* [[Safety Model]]

**Help**
* [[Troubleshooting]]
EOF

# ============================================================================
# Summary
# ============================================================================

echo ""
echo -e "${GREEN}Wiki generated successfully!${NC}"
echo ""
echo "Files created in $WIKI_DIR:"
ls -la "$WIKI_DIR"
echo ""
echo "To publish to GitHub Wiki:"
echo "  1. Clone your wiki: git clone https://github.com/linnix-os/linnix.wiki.git"
echo "  2. Copy files: cp wiki/*.md linnix.wiki/"
echo "  3. Push: cd linnix.wiki && git add -A && git commit -m 'Update wiki' && git push"
