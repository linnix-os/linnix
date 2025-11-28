# Linnix Safety Model

Trust is our #1 priority. Linnix is designed to be **safe to install** and **safe to run** on production systems.

## 1. The "Monitor-First" Guarantee

By default, Linnix runs in **Monitor Mode**.

*   **What it does:** Detects incidents, logs them, sends alerts, and proposes remediation actions (e.g., "Kill process 123").
*   **What it does NOT do:** It will **never** execute an enforcement action (kill, throttle, pause) without explicit human approval or strict opt-in configuration.

You can deploy Linnix to 1,000 nodes without fear of it acting as a "loose cannon."

## 2. Architecture Safety

### Minimal Privileges
Linnix does not run as a privileged container if configured correctly. It requires specific Linux capabilities:
*   `CAP_BPF`: To load eBPF programs.
*   `CAP_PERFMON` (or `CAP_SYS_ADMIN` on older kernels): To read trace events.
*   `CAP_NET_ADMIN`: Only if network monitoring is enabled.

It does **not** require full `privileged: true` access to the host filesystem.

### Resource Limits (The "Watcher" shouldn't kill the "Watched")
*   **CPU Overhead**: Target <1% CPU usage. We use eBPF ring buffers to avoid expensive context switches.
*   **Memory Cap**: The agent is configured with strict memory limits. If Linnix itself leaks memory, it will restart without affecting the host.

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
