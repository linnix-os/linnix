# Linnix

**Find which process is hurting your SLOs — not just who's using CPU, but who's causing stalls.**

[![CI](https://github.com/linnix-os/linnix/actions/workflows/docker.yml/badge.svg)](https://github.com/linnix-os/linnix/actions/workflows/docker.yml)
[![License](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18042323.svg)](https://doi.org/10.5281/zenodo.18042323)

---

## The Problem

`top` shows 80% CPU. Prometheus shows high latency. But *which pod* is actually stalling your payment service?

Linnix uses **eBPF** + **PSI (Pressure Stall Information)** to answer this. PSI measures actual stall time — not usage, but contention. A pod using 40% CPU with 60% PSI is worse than one using 100% CPU with 5% PSI.

**What Linnix detects:**
- **Noisy Neighbors**: Which container is starving others
- **Fork Storms**: Runaway process creation before it crashes the node
- **Stall Attribution**: "Pod X caused 300ms stall to Pod Y" — exposed as a Prometheus counter keyed on the offender/victim pair
- **PSI Saturation**: CPU/IO/Memory pressure that doesn't show in `top`

> [!IMPORTANT]
> **Monitor-only by default.** Linnix detects and reports — it never takes action without explicit configuration.

> [!NOTE]
> **We tell you when attribution is degraded.** If eBPF can't attach (unsupported kernel, missing BTF), Linnix keeps serving PSI from `/proc/pressure` — pressure exists, but you lose *who caused it*, the reason you installed Linnix. `/readyz` reports 503 in that state instead of looking healthy. See [FAQ](docs/FAQ.md#how-do-i-tell-whether-linnix-is-actually-collecting).

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

## Visualize in 30 seconds

Linnix exports the attribution as Prometheus counters, so the "who is stalling whom" view works in the Grafana you already run.

```bash
kubectl apply -f k8s/                       # scrape annotations included
# Grafana → Dashboards → New → Import → Upload JSON file
#   k8s/grafana/linnix-noisy-neighbor.json
```

<!-- TODO: screenshot of the imported dashboard against a cluster with real stall data -->

| Metric | Type | Labels |
| --- | --- | --- |
| `linnix_pod_psi_pressure_total` | counter (µs) | `namespace`, `pod`, `node` |
| `linnix_stall_induced_seconds_total` | counter (s) | `offender_pod`, `offender_namespace`, `victim_pod`, `victim_namespace` |
| `linnix_blame_series_evicted_total` | counter | — |

The second one is the differentiator: a workload **pair** series. Most monitoring can tell you a pod is under pressure; this says which other pod is causing it.

```promql
# Who is suffering
topk(10, rate(linnix_pod_psi_pressure_total[5m]))

# Who is causing it
topk(10, sum by (offender_pod) (rate(linnix_stall_induced_seconds_total[5m])))

# Blame for one victim
sum by (offender_pod) (rate(linnix_stall_induced_seconds_total{victim_pod="payment-api"}[5m]))
```

Each victim's stall is split across its offenders in proportion to blame, so summing these never exceeds the stall that actually occurred. Attributions above `attribution_threshold_ms` also emit a JSON line on stdout with `"event_type": "linnix.stall_attribution"` for log-based tooling.

---

## Kubernetes Features

Linnix has first-class Kubernetes support:

- **Pod Attribution**: Every process event is tagged with `pod_name`, `namespace`, `container_id`
- **Namespace Awareness**: Filter and query by namespace
- **PSI Contribution Tracking**: See which pod contributed to system-wide PSI pressure
- **cgroup Integration**: Maps processes to their cgroups for container-level aggregation

```bash
# Example: Get processes causing stalls in the payments namespace
curl "http://localhost:3000/processes?namespace=payments&sort=psi_contribution"
```

---

## Early Adopters

This project is under active development. If you're using it or evaluating it, open an issue or email parth21.shah@gmail.com.

---

## License

*   **Agent (`cognitod`)**: AGPL-3.0
*   **eBPF Collector**: GPL-2.0 or MIT (eBPF programs must be GPL-compatible for kernel loading)

Commercial licensing available for teams that can't use AGPL. See [LICENSE_FAQ.md](LICENSE_FAQ.md) for details.
