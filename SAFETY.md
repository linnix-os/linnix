# Linnix Safety Model

Trust is our #1 priority. Linnix is designed to be **safe to install** and **safe to run** on production systems.

## 1. The "Monitor-First" Guarantee

By default, Linnix runs in **Monitor Mode**.

*   **What it does:** Detects incidents, logs them, sends alerts, and proposes remediation actions (e.g., "Kill process 123").
*   **What it does NOT do:** It will **never** execute an enforcement action (kill, throttle, pause) without explicit human approval or strict opt-in configuration.

You can deploy Linnix to 1,000 nodes without fear of it acting as a "loose cannon."

## 2. Architecture Safety

### Privileges
*   **systemd**: the shipped unit runs with only `CAP_BPF` and `CAP_PERFMON`, plus systemd sandboxing (`ProtectSystem=strict`, `NoNewPrivileges`, ...).
*   **Kubernetes**: the shipped DaemonSet currently runs `privileged: true` with `hostPID`. A capabilities-only variant is documented but not yet tested in CI.

Kernel floor: Linux 5.12+ (x86_64) / 5.18+ (arm64) with BTF. See [docs/security/blast-radius.md](docs/security/blast-radius.md) for the full privilege, egress and listener inventory.

### Resource Limits (The "Watcher" shouldn't kill the "Watched")
*   **CPU Overhead**: Target <1% CPU usage. We use eBPF ring buffers to avoid expensive context switches.
*   **Memory Cap**: The Kubernetes DaemonSet sets hard limits (`500m` CPU, `512Mi` memory), so a leak in Linnix restarts the pod without affecting the host. `runtime.rss_cap_mb` and `cpu_target_pct` only log warnings; under systemd, add `MemoryMax`/`CPUQuota` through a drop-in for hard ceilings.

## 3. Enforcement Safety (Opt-In)

If you choose to enable **Enforcement Mode** (e.g., for automated circuit breaking), we enforce:

1.  **Grace Periods**: No action is taken until a condition persists for `X` seconds (default 15s).
2.  **Safety Rails**:
    *   Never kill PID 1.
    *   Never kill kernel threads.
    *   Allow-lists for critical system processes (e.g., `kubelet`, `containerd`).

## 4. AI Safety

The AI (LLM) is used for **Analysis** and **Triage**, not for the hot-path decision loop.

*   **Decision Path**: Deterministic Rules Engine (Rust) -> Triggers Alert.
*   **Analysis Path**: LLM analyzes the metadata *after* the alert is triggered to explain *why*.

We do not let an LLM decide to kill a process in real-time.
