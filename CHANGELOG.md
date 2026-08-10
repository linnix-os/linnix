# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2026-08-09

### Added
- **Stall Attribution Emit Seam**: All completed PSI stall attributions now route through a single `AttributionSink` (`cognitod/src/attribution.rs`), fanning out to a structured JSON event, an alert on the existing broadcast channel, and pod-labeled Prometheus counters (`linnix_stall_induced_seconds_total{offender_pod, victim_pod, ...}`)
  - New `attributed_stall_us` field splits a victim's stall proportionally across offenders by blame score, instead of duplicating the full stall duration per offender
  - `calculate_blame_attributions` extracted as a free function for testability

### Changed
- **Degraded eBPF Visibility**: New `/readyz` endpoint returns 503 when eBPF probes fail to attach, naming likely causes (kernel floor, missing BTF, tracefs, CAP_BPF/CAP_PERFMON). Previously `/healthz` stayed `200 ok` in this state, silently falling back to PSI-only (pressure signal, no per-process attribution)
  - New `linnix_kernel_instrumentation_active` gauge
  - New `api.require_kernel_instrumentation` config flag (default `true`)
  - K8s DaemonSet, Dockerfile, and compose healthchecks updated to use `/readyz`
- **Linnix-Claw extracted**: the agent-to-agent payment/settlement subsystem moved to its own repo (`linnix-os/linnix-claw`), letting core Linnix focus solely on PSI/eBPF stall attribution
  - eBPF object size reduced 43,096 → 27,184 bytes (-37%)
  - Dropped the `lsm=bpf` boot-parameter requirement

## [0.2.0] - 2025-11-26

### Added
- **Kubernetes Support**: Full K8s deployment with DaemonSet, ConfigMap, and RBAC manifests
  - Production-ready manifests in `k8s/` directory
  - EKS quick-start config (`infrastructure/eks-cluster.yaml`)
  - Tested on local kind clusters and AWS EKS
  - Documentation in `k8s/README.md`
- **Monitor-Only Mode**: Safe default mode that detects issues but requires human approval
  - Set via `mode = "monitor"` in circuit breaker config
  - Enforces `require_human_approval = true` automatically
- **Overhead Benchmarking**: Automated benchmarking and documentation
  - Script: `scripts/benchmark_overhead.sh`
  - Results documented in `docs/OVERHEAD.md`
  - Proven <4% CPU overhead, ~70MB RSS

### Changed
- K8s ConfigMap defaults to monitor mode and disables LLM (saves memory)
- README updated with K8s deployment instructions and overhead metrics link

### Security
- Removed `hostPort` from K8s DaemonSet to prevent unauthenticated API exposure
- Added auth token reminder in ConfigMap

### Fixed
- K8s DaemonSet: Removed `args` field to use Dockerfile CMD (fixes container exec issue)

## [0.1.1] - 2025-11-23

### Security
- API authentication improvements
- Reduced capabilities
- SHA256 verification

## [0.1.0] - Initial Release

### Added
- PSI-based system monitoring
- Circuit breaker with grace period
- LLM-powered incident analysis
- Basic API server

[0.2.0]: https://github.com/linnix-os/linnix/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/linnix-os/linnix/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/linnix-os/linnix/releases/tag/v0.1.0
