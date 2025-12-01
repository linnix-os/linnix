# How Linnix Works

Linnix combines eBPF probes, BTF-powered compatibility helpers, and an AI reasoner to turn raw kernel events into actionable guidance. This page walks through the full stack so you can understand what runs on your hosts and how to customize it.

```
┌─────────────┐   fork/exec/exit   ┌──────────────┐   JSON/SSE   ┌─────────────┐
│   Kernel    │ ─────────────────▶ │   cognitod   │ ───────────▶ │ Dash / CLI  │
│  eBPF map   │   perf buffers     │  (Rust)      │   insights   │  Prometheus │
└─────────────┘                    └──────────────┘              └─────────────┘
          ▲                                  │                              │
          │                                  ▼                              │
      BTF offsets                      LLM Reasoner ◀───────────────────────┘
```

## 1. eBPF Probes

- **Tracepoints**: `sched_process_fork`, `sched_process_exec`, and `sched_process_exit` are always-on hooks that emit a struct whenever a process forks, executes a new binary, or exits. Linnix attaches pure-Rust (Aya) eBPF programs here so every lifecycle event is captured even if the process lives for microseconds.
- **Sampling**: Lightweight CPU and RSS deltas are sampled in-kernel and stored in per-CPU maps. Because logic executes in kernel space, there are no expensive context switches or text parsing overhead.
- **Optional probes**: Network (kprobes on `tcp_sendmsg` / `udp_*`), file I/O, block I/O, and syscall hooks can be switched on for deeper insights. They are rate-limited in the default build so your perf buffers remain focused on lifecycle telemetry.

### Why it stays under 1% CPU
- Event-driven execution (only runs when Linux already emits a tracepoint).
- Per-CPU ring buffers avoid lock contention.
- Binary structs (~200 bytes) instead of verbose logs keep memory traffic minimal.

## 2. BTF: Kernel Compatibility Glue

- **BTF (BPF Type Format)** files (usually `/sys/kernel/btf/vmlinux`) describe kernel struct layouts. Linnix parses them at startup to compute offsets for `task_struct`, socket stats, and RSS fields.
- **Dynamic offsets** mean the same cognitod build works on Ubuntu 20.04 (5.13 kernel) and modern 6.x kernels without recompiling the eBPF code.
- **Graceful degradation**: When BTF is unavailable (older 4.x/5.4 kernels), Linnix still captures fork/exec/exit events but skips advanced metrics (page-fault deltas, richer RSS). Logs clearly note the degraded mode so operators can decide whether to ship a BTF package.

## 3. Userspace Daemon (cognitod)

1. **Perf buffer listener** (`stream_listener.rs`) copies events into a high-throughput queue.
2. **State tracker** rebuilds a live process tree with parent/child relationships, command lines, namespaces, and resource snapshots.
3. **Rules engine** evaluates heuristics such as “fork storm”, “exec loop”, “zombie accumulation”, and “CPU pinned > 60s”.
4. **APIs**:
   - `http://localhost:3000/stream` (Server-Sent Events)
   - `http://localhost:3000/insights` (AI output)
   - `http://localhost:3000/metrics` (JSON) and `/metrics/prometheus`
5. **Prometheus integration** is just a config flag; no sidecar required.

## 4. AI Reasoning Loop

- **Input**: The rules engine emits structured incidents (process IDs, workload tags, CPU/RSS stats, historical context).
- **Transport**: Cognitod posts these payloads to the Linnix reasoner via HTTP. Defaults point to the bundled `linnix-3b-distilled` model served through llama.cpp, but any OpenAI-compatible endpoint works.
- **Prompting**: Reasoner prompts include:
  1. Situation summary (“cron forked 400 children in 10s”).
  2. Host metadata (kernel, distro, container tags).
  3. Playbook hints (rate limiting, cgroup tuning, kill/scale decisions).
- **Output**: Natural-language insight blocks with remediation steps, severity, and TTL. These show up in the dashboard and CLI (`linnix-reasoner --insights`).
- **Offline mode**: If you cannot expose an LLM endpoint, disable the reasoner and Linnix still surfaces rule hits via JSON/SSE; you simply lose the narrative output.

## 5. Putting It All Together

| Step | Component | What to check |
|------|-----------|---------------|
| 1 | Kernel | `uname -r` ≥ 5.8 recommended, `ls /sys/kernel/btf/vmlinux` to confirm BTF |
| 2 | eBPF assets | `cargo xtask build-ebpf` (development) or use shipped object files |
| 3 | Daemon | `sudo systemctl status cognitod` or `./quickstart.sh` |
| 4 | LLM endpoint | `curl http://localhost:8090/v1/models` |
| 5 | Insights | `curl -N http://localhost:3000/stream` and `curl http://localhost:3000/insights | jq` |

Once the loop is running, Linnix continuously turns kernel-space events into contextual human guidance without leaving your infrastructure.
