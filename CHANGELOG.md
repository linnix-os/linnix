# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **`cognitod --check-config`**: validates a config file and exits non-zero if anything is wrong — parse errors, plus any section or key the daemon does not read. Runs unprivileged, so it belongs in CI and pre-deploy checks. This is where strict validation lives; startup stays permissive so a node carrying a retired key still boots.
- **`--config <PATH>` now works.** The flag was declared with a doc comment and a default, but never read — `Config::load()` only ever consulted `LINNIX_CONFIG` or the packaged path, so `cognitod --config /my.toml` silently loaded something else. Precedence is now `--config` > `LINNIX_CONFIG` > `/etc/linnix/linnix.toml`.

### Changed
- **`[telemetry]` is now wired to the behaviour it describes.** `sample_interval_ms` and `retention_seconds` shipped in every config and were documented with defaults, but nothing read them — the values were hardcoded in `main.rs`, and the documented numbers were wrong by 5x in both directions (sampling was 5s, not the documented 1s; retention 300s, not 60s). `min_eps_to_enable`, removed in #58, was likewise hardcoded as `eps >= 20` behind a "YAGNI cleanup" note. All three now come from `[telemetry]`, **defaulting to the values the daemon actually used**, so behaviour is unchanged for anyone who does not set them. `sample_interval_ms` and `retention_seconds` are clamped (100..=60000 ms, 10..=3600 s) with a warning, since sampling drives the <4% CPU overhead claim and retention bounds per-node memory; `--check-config` reports out-of-range values as errors.
- **A malformed config file is now fatal.** Previously "file absent" and "file present but unparseable" both returned `Config::default()` behind one `warn!`, so a typo silently swapped every setting — thresholds, endpoints, PSI paths — for defaults the operator never chose, while the daemon reported healthy. A missing file still yields defaults; an unreadable or unparseable one aborts startup. Config is also loaded before the capability check, so config errors are reported rather than hidden behind a `CAP_BPF` failure.

### Removed
- `scripts/generate_wiki.sh` still emitted `window_seconds` and `min_eps_to_enable` rows after #58 removed them from the generated docs; regenerating the wiki would have reintroduced them.
- **Dead ILM telemetry surface**: the `local_ilm` handler was deleted in `737b763` (v0.2.0 era), but its counters, exporters, and status fields survived it. Nothing has incremented them since, so they reported zero/false unconditionally.
  - **Breaking (metrics)**: `linnix_ilm_windows_total`, `linnix_ilm_timeouts_total`, `linnix_ilm_insights_total`, `linnix_ilm_schema_errors_total`, and the `linnix_ilm_enabled` gauge are no longer exported. All were permanently `0`, so no dashboard could have been showing meaningful data; no shipped Grafana dashboard referenced them.
  - **Breaking (API)**: `/status` no longer returns `reasoner.ilm_enabled`, `reasoner.ilm_disabled_reason`, `ilm_windows`, `ilm_timeouts`, `ilm_insights`, or `ilm_schema_errors`.
  - Removed the `ilm-test` cargo feature (declared with zero `cfg` uses).

### Fixed
- **`linnix-cli doctor` reported "AI Analysis: Disabled" unconditionally**, including on a fully configured and working reasoner, because it read the never-set `ilm_enabled` flag. It now reads `reasoner.configured` and reports "Configured" / "Not configured".

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
