# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **Incident Lab episode format (v0.1)**: `cognitod::episode::Episode` is the shared record capture and replay agree on -- pre/post-window signal series per candidate, the pod/ownership graph, trigger and rule versions, the daemon's diagnosis, ground truth or a correction, evidence cited, and outcome. See `datasets/schema/episode.schema.json` and the golden fixture at `datasets/episodes/golden/fork_storm_v0.1.json`. Nothing writes or reads these yet outside the fixture test -- capture and replay land with the Incident Lab (`xtask lab`).
- **Five-way feedback taxonomy**: `correct | wrong_culprit | wrong_reason | incomplete | what_fixed_it` replaces the old `useful | noise` (plus `wrong_root_cause`, which the `feedback` table's migration allowed but no code ever constructed). Splits "wrong" into what specifically failed -- the offending pod or the reason code -- which is the axis the Incident Lab scores. `linnix feedback <id> <rating>`, the Slack action buttons, and `/insights/{id}/feedback` and `/api/feedback` all take the new taxonomy; `linnix blame` now prints the correcting command under each insight. Migration `007_widen_feedback_taxonomy.sql` remaps existing rows (`useful`→`correct`, `noise`→`incomplete`, `wrong_root_cause`→`wrong_culprit`).
- **`evidence_refs` on `Insight`**: ids of the facts that grounded the insight's summary. Empty rather than omitted when nothing grounded it. Part of the v0.2 insight schema bump below; nothing populates it from the live analyzer pipeline yet.

### Changed
- **`InsightReason` and `attribution::BlameReason` are merged into one reason-code vocabulary** (`cognitod::schema::InsightReason`), because reason-code accuracy cannot be scored against two disagreeing enums. `BlameReason::HighCpuContention` (wire value `high_cpu_contention`) is now `InsightReason::NoisyNeighbor` (`noisy_neighbor`); `BlameReason::ShortJobChurn` and the old `InsightReason::ShortJobFlood` (`short_job_flood`) both collapse to `InsightReason::ShortJobChurn` (`short_job_churn`). New variants cover the rest of the failure library: `cpu_throttled`, `disk_pressure`, `network_saturation`, `deployment_regression`. **Breaking (wire)**: the `linnix.stall_attribution` JSON event's `offender.reason` and the `/attribution` API's `reason` field now emit `noisy_neighbor` instead of `high_cpu_contention`; saved log-pipeline queries faceting on that string need updating. `cognitod::attribution::BlameReason` is removed; `classify_blame_reason` replaces `BlameReason::classify` and returns `InsightReason`.
- **`datasets/schema/insight.schema.json` bumped to v0.2**, regenerated from `cognitod::schema::Insight` instead of hand-maintained. The v0.1 shape (`class`/`why`/`actions`, `additionalProperties: false`) rejected every field the daemon actually emits and was never wired to it -- the `/insights/schema` route had been commented out as "YAGNI cleanup" and `scripts/fetch_insight_schema.py`, which `.github/copilot-instructions.md` names as the way to regenerate it, did not exist. The v0.1 examples move to `datasets/examples/v0.1-legacy/` so the corpus never mixes shapes.

- **`linnix-cli investigate <namespace>/<pod> --since 20m`**: names the workloads that stalled a pod, ranked by summed attributed stall, with the evidence behind each. The data was already persisted; reaching it meant querying `/attribution` by hand and doing arithmetic the raw rows actively mislead you on — `stall_us` repeats the victim's total on every offender row of a window, and the endpoint returns one row per offender *per window*, so reading it in order ranks by a single window rather than the period. A window with no contention says so instead of naming the least-innocent pod. Percentages are shares of the stall that could be pinned on a neighbour, and both that figure and the victim's total are printed so the unattributed remainder stays visible.
- **`/attribution` rows now carry `reason`**, the signal that dominated the stored blame score (`high_cpu_contention`, `fork_storm`, `short_job_churn`). Derived server-side so it cannot drift from the score it is reported alongside. Rows with no signal at all — only possible on rows predating migration 005, since a live attribution needs a non-zero score to be stored — are left unclassified rather than reported as `high_cpu_contention`, the branch three zero defaults happen to fall into.
- **Grounded incident investigations.** The analyzer now states what the daemon observed as a numbered list of facts and requires the model to *cite* them by id rather than restate them. A hypothesis citing a fact that was never supplied is discarded rather than reported, and rendering resolves every citation through the daemon's own wording — so a hypothesis cannot misquote its own evidence. Stored in a new `incidents.investigation` column (migration 006) beside the unchanged raw reply; a reply that fails to ground leaves the column NULL with the text intact, which is what distinguishes a broken endpoint from a model that answers badly.
- **`cognitod --check-config`**: validates a config file and exits non-zero if anything is wrong — parse errors, plus any section or key the daemon does not read. Runs unprivileged, so it belongs in CI and pre-deploy checks. This is where strict validation lives; startup stays permissive so a node carrying a retired key still boots.
- **`--config <PATH>` now works.** The flag was declared with a doc comment and a default, but never read — `Config::load()` only ever consulted `LINNIX_CONFIG` or the packaged path, so `cognitod --config /my.toml` silently loaded something else. Precedence is now `--config` > `LINNIX_CONFIG` > `/etc/linnix/linnix.toml`.

### Changed
- **The incident analyzer returns a grounded investigation instead of prose.** `IncidentAnalyzer::analyze` previously returned the model's reply as a `String`, which was stored verbatim and never parsed — `parse_analysis` existed but nothing in the daemon called it, so an answer that invented a pod name or a CPU figure was indistinguishable from a sound one. It now returns an `AnalysisOutcome` carrying the raw reply and, when the reply grounds, the checked hypotheses.
  - **Breaking (lib API)**: `IncidentAnalysis`, its `PodContribution` (a duplicate of `schema::PodContribution`), and `IncidentAnalyzer::parse_analysis` are removed; `cognitod::incidents` now exports `AnalysisOutcome`, `Fact` and `IncidentInvestigation`. `IncidentStore::add_llm_analysis` takes an `&AnalysisOutcome` rather than a `String`.
  - Hypothesis categories reuse the existing `schema::InsightReason` vocabulary rather than free text, so a model cannot coin an incident type nothing downstream handles.
  - A reply must contain a `hypotheses` key to parse at all. Without that, every JSON object is a valid reply — a refusal, or a stale endpoint still answering in the old summary format — and each would ground into an empty investigation reading as "hypotheses were proposed and none held up" rather than "the question was never answered". An explicit `{"hypotheses": []}` remains valid: that is the model addressing the schema and having nothing.
  - The model's confidence is stored as `model_stated_confidence` and rendered as its own estimate, because nothing calibrates it against outcomes. A value outside 0.0–1.0 is dropped rather than clamped — rounding 1.7 down to 1.0 would manufacture total certainty from a malformed field.
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
