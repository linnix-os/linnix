# Performance Overhead

Linnix is designed to be lightweight and unobtrusive. We continuously benchmark `cognitod` to ensure it stays within its resource budget.

## Benchmark Results

**Date:** 2025-11-24
**Version:** 0.1.0 (release build)
**Environment:** 16 vCPU, Ubuntu 22.04
**Configuration:**
- Reasoner (LLM): Disabled (to measure core overhead)
- Mode: Userspace-only (BPF disabled for benchmark isolation)

| Scenario | Avg CPU% (1 core) | Max RSS (MB) | Description |
|----------|-------------------|--------------|-------------|
| **Idle** | 3.63% | 75.4 MB | Baseline monitoring (PSI polling, API) |
| **CPU Stress** | 3.63% | 69.7 MB | System under 100% CPU load |
| **Fork Stress** | 4.10% | 69.9 MB | High process churn (stress-ng --fork 4) |

> **Note:** These numbers represent the userspace daemon overhead. The eBPF probes running in kernel space add negligible overhead (<1%) due to the JIT-compiled, event-driven nature of eBPF.

## Methodology

We use `stress-ng` to generate load and `pidstat` to measure resource usage of the `cognitod` process.

```bash
# Idle
sleep 30

# CPU Stress
stress-ng --cpu 4 --timeout 30s

# Fork Stress
stress-ng --fork 4 --timeout 30s
```

## Resource Limits

By default, `cognitod` is configured with strict safety limits:

```toml
[runtime]
cpu_target_pct = 25   # Throttle if usage exceeds 25% of one core
rss_cap_mb = 512      # Hard memory limit
events_rate_cap = 100000 # Max events/sec processed
```
