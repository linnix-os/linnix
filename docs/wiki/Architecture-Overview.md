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
