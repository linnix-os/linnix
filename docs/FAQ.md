# Linnix FAQ

## What kernel versions are supported?
- **Minimum**: Linux **5.12** on x86_64, Linux **5.18** on arm64/aarch64. The eBPF programs use atomic fetch-and-add (`BPF_FETCH`) for the sequencer's ticket reservation, and the kernel verifier rejects those instructions below these versions. Support landed in 5.12 for x86_64 and 5.18 for arm64.
- **Recommended**: Linux 5.15+ (x86_64) / 6.1+ (arm64) with BTF packages installed (Ubuntu 22.04+, Amazon Linux 2023, Fedora 33+, modern Debian).
- **Below the minimum**: both the primary and the `rss_trace` fallback object fail to load. `cognitod` does not crash — it logs `eBPF initialization failed ...; running without kernel instrumentation` and continues in userspace-only mode, which means **no eBPF telemetry at all**. Check your logs for that warning if metrics look empty.
- **BTF tips**: Ship `/sys/kernel/btf/vmlinux` (or package-specific paths) so Linnix can compute struct offsets dynamically. Without BTF, the daemon logs a warning and continues with degraded telemetry.

## How do I tell whether Linnix is actually collecting?

Linnix does not fail closed. If the eBPF probes cannot attach, `cognitod` keeps
running and still serves PSI read from `/proc/pressure` — but the per-process
stall attribution, the part you installed it for, is gone. Two endpoints
distinguish these states:

- **`/healthz`** — liveness. 200 whenever the process is up. It stays 200 even
  when degraded, because restarting cannot fix an unsupported kernel; the body
  carries `kernel_instrumentation: active | unavailable`.
- **`/readyz`** — readiness. **503** when the probes are not attached, with a
  `reason` explaining what to check. This is what the Kubernetes readinessProbe
  and the container HEALTHCHECK use, so a degraded node shows as `0/1 Ready`
  rather than looking healthy.

For alerting, scrape `linnix_kernel_instrumentation_active` (1 = probes
attached, 0 = userspace-only) from `/metrics/prometheus`.

Deployments that intentionally run without kernel instrumentation can set
`require_kernel_instrumentation = false` under `[api]` in `linnix.toml`.

## How much overhead should I expect?
- The in-kernel eBPF probes add **under 1% CPU** (see [performance-proof.md](performance-proof.md)) — event-driven tracepoints, not polling.
- The full `cognitod` userspace daemon (PSI polling, attribution, API) runs **~3.6-4.1% of one core** and 10-20 MB RAM on typical hosts (see [OVERHEAD.md](OVERHEAD.md)).
- Reasons it is lightweight:
  1. Tracepoints fire only when the kernel already handles fork/exec/exit events (event-driven, no polling).
  2. Per-CPU buffers and lock-free maps avoid contention.
  3. Binary payloads (~200 bytes) minimize copies between kernel and userspace.
- If you see overhead well above these figures, check for debug builds, noisy workloads during benchmarking, or missing BTF (which forces slower fallback paths). Run `sudo ./test_ebpf_overhead.sh` to capture a reproducible report.

## How does Linnix handle data privacy?
- **On-host processing**: All capture, reasoning, and dashboards run on your infrastructure. There is no mandatory SaaS ingestion or remote control plane.
- **BYO LLM**: Point the reasoner to any OpenAI-compatible endpoint. Use your own llama.cpp deployment, enterprise LLM gateway, or even air-gapped models.
- **Network controls**: Block outbound traffic entirely if needed. Linnix does not require the internet once binaries/models are installed.
- **Data minimization**: eBPF payloads include PIDs, command lines, and lightweight resource counters—no application payloads or user data are copied from memory.

## Do I still need Prometheus, Datadog, or Elastic?
Yes. Linnix focuses on process-level truth and AI explanations. Continue using Prometheus/Grafana for historical metrics, or Datadog/Elastic for traces and logs. Linnix exposes its own `/metrics/prometheus`, so you can scrape its counters into the rest of your observability stack.

## Can I disable the AI reasoner?
Absolutely. Set the reasoner endpoint to empty in `linnix.toml` or stop the LLM container. The daemon will keep emitting rule hits and raw events over JSON/SSE; you simply lose the natural-language summaries.

## What permissions are required?
- Run cognitod with `CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_ADMIN`, or just start it as root.
- Ensure `/sys/fs/bpf` is writable so programs and maps can be pinned.
- Some optional probes (network/file IO) may require kernel configs such as `CONFIG_KPROBE_EVENTS`.

Still stuck? Open a GitHub Discussion or file an issue with your kernel version, cognitod logs, and what you observed. The team actively triages “Good First Issues” for new contributors.
