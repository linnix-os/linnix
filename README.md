# Linnix

**AI-Assisted Incident Triage for Kubernetes & Linux**

[![CI](https://github.com/linnix-os/linnix/actions/workflows/docker.yml/badge.svg)](https://github.com/linnix-os/linnix/actions/workflows/docker.yml)
[![License](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/linnixos/cognitod?style=flat-square)](https://github.com/linnix-os/linnix/pkgs/container/cognitod)

---

## "Why is this node slow?"

Linnix answers the hardest question in platform engineering. It uses **eBPF** to monitor Linux kernel events and an **AI Engine** to explain *exactly* what is causing system instability.

**Stop guessing.** Linnix automatically detects and explains:
*   **Noisy Neighbors**: Which container is starving others of CPU?
*   **Fork Bombs**: Rapid process creation storms.
*   **Memory Leaks**: Gradual RSS growth patterns.
*   **PSI Saturation**: CPU/IO/Memory stalls that don't show up in top.

> [!IMPORTANT]
> **Safety First:** Linnix runs in **Monitor Mode** by default. It detects issues and proposes solutions, but **never** takes action without human approval.

### 🔒 Security & Privacy

- **[Security Policy](SECURITY.md)**: See our security model, privileges required, and vulnerability reporting process
- **[Safety Guarantees](SAFETY.md)**: Understand our "Monitor-First" architecture and safety controls
- **[Architecture Overview](docs/architecture.md)**: System diagram and data flow for security reviews

**Key Promise**: All analysis happens locally. No data leaves your infrastructure unless you explicitly configure Slack notifications. [Learn more about data privacy →](SECURITY.md#data-privacy)

---

## Quickstart (Kubernetes)

Deploy Linnix as a DaemonSet to monitor your cluster.

```bash
# Apply the manifests
kubectl apply -f k8s/
```

**Access the API:**
```bash
kubectl port-forward daemonset/linnix-agent 3000:3000
# API available at http://localhost:3000
# Stream events: curl http://localhost:3000/stream
```

## Quickstart (Docker)

Try it on your local machine in 30 seconds.

```bash
git clone https://github.com/linnix-os/linnix.git && cd linnix
./quickstart.sh
```

---

## How It Works

1.  **Collector (eBPF)**: Sits in the kernel, watching `fork`, `exec`, `exit`, and scheduler events with <1% overhead.
2.  **Reasoning Engine**: Aggregates signals (PSI + CPU + Process Tree) to detect failure patterns.
3.  **Triage Assistant**: When a threshold is breached, Linnix captures the system state and explains the root cause.

### Supported Detections

| Incident Type | Detection Logic | Triage Value |
| :--- | :--- | :--- |
| **Circuit Breaker** | High PSI (>40%) + High CPU (>90%) | Identifies the *specific* process tree causing the stall. |
| **Fork Storm** | >10 forks/sec for 2s | Catches runaway scripts before they crash the node. |
| **Memory Leak** | Sustained RSS growth | Flags containers that will eventually OOM. |
| **Short-lived Jobs** | Rapid exec/exit churn | Identifies inefficient build scripts or crash loops. |

---

## Safety & Architecture

Linnix is designed for production safety.

*   **Monitor-First**: Enforcement capabilities are opt-in and require explicit configuration.
*   **Low Overhead**: Uses eBPF perf buffers, not `/proc` polling.
*   **Privilege Isolation**: Can run with `CAP_BPF` and `CAP_PERFMON` on bare metal. Kubernetes DaemonSet currently uses privileged mode for simplicity.

See [SAFETY.md](SAFETY.md) for our detailed safety model.

---

## License

*   **Agent (`cognitod`)**: AGPL-3.0
*   **eBPF Collector**: GPL-2.0 or MIT (eBPF programs must be GPL-compatible for kernel loading)

See [LICENSE_FAQ.md](LICENSE_FAQ.md) for details.
