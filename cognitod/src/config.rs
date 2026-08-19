use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_CONFIG_PATH: &str = "/etc/linnix/linnix.toml";
const ENV_CONFIG_PATH: &str = "LINNIX_CONFIG";

/// Which config file to read: `--config` beats `LINNIX_CONFIG` beats the
/// packaged path. The CLI flag is the most explicit signal, so it wins; it used
/// to be declared and then never read at all.
pub fn resolve_config_path(explicit: Option<PathBuf>) -> PathBuf {
    explicit
        .or_else(|| std::env::var(ENV_CONFIG_PATH).ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
}

/// `[telemetry]` — sampling and retention.
///
/// These keys shipped in every config and were documented with defaults, but
/// nothing ever read them: the values they name were hardcoded in main.rs, and
/// the documented numbers disagreed with reality by 5x in both directions
/// (sampling was 5s not 1s; retention 300s not 60s). The defaults here are the
/// values the daemon actually used, so wiring the knobs changes no behaviour
/// for anyone who does not set them.
#[derive(Debug, Deserialize, Clone)]
pub struct TelemetrySettings {
    /// How often the system CPU/memory snapshot is refreshed.
    #[serde(default = "default_sample_interval_ms")]
    pub sample_interval_ms: u64,
    /// How long process history is kept before pruning.
    #[serde(default = "default_retention_seconds")]
    pub retention_seconds: u64,
    /// Events/sec below which snapshots are not forwarded to handlers.
    /// Previously hardcoded as `eps >= 20` with a "YAGNI cleanup" note.
    #[serde(default = "default_min_eps_to_enable")]
    pub min_eps_to_enable: u64,
    #[serde(flatten)]
    pub unknown: std::collections::BTreeMap<String, toml::Value>,
}

/// Sampling faster than this burns CPU for no signal, and the project advertises
/// <4% overhead; slower than the ceiling makes the dashboard useless.
pub const SAMPLE_INTERVAL_MS_BOUNDS: (u64, u64) = (100, 60_000);
/// Retention bounds memory on a per-node agent, so it is not unbounded.
pub const RETENTION_SECONDS_BOUNDS: (u64, u64) = (10, 3_600);

fn default_sample_interval_ms() -> u64 {
    5_000 // what main.rs actually slept for
}

fn default_retention_seconds() -> u64 {
    300 // what ContextStore was actually constructed with
}

fn default_min_eps_to_enable() -> u64 {
    20 // what `is_active` actually compared against
}

impl Default for TelemetrySettings {
    fn default() -> Self {
        Self {
            sample_interval_ms: default_sample_interval_ms(),
            retention_seconds: default_retention_seconds(),
            min_eps_to_enable: default_min_eps_to_enable(),
            unknown: Default::default(),
        }
    }
}

impl TelemetrySettings {
    pub fn sample_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.sample_interval_ms)
    }

    pub fn retention(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.retention_seconds)
    }

    /// Out-of-range values, described. Used by `--check-config`.
    fn range_problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let (lo, hi) = SAMPLE_INTERVAL_MS_BOUNDS;
        if !(lo..=hi).contains(&self.sample_interval_ms) {
            problems.push(format!(
                "[telemetry] sample_interval_ms = {} is outside {lo}..={hi}",
                self.sample_interval_ms
            ));
        }
        let (lo, hi) = RETENTION_SECONDS_BOUNDS;
        if !(lo..=hi).contains(&self.retention_seconds) {
            problems.push(format!(
                "[telemetry] retention_seconds = {} is outside {lo}..={hi}",
                self.retention_seconds
            ));
        }
        problems
    }

    /// Pull out-of-range values back into bounds, loudly. A too-small sampling
    /// interval is a CPU-overhead footgun on every node, so it is corrected
    /// rather than obeyed.
    fn clamp_with_warning(&mut self) {
        for problem in self.range_problems() {
            log::warn!("[config] {problem}; clamping");
        }
        let (lo, hi) = SAMPLE_INTERVAL_MS_BOUNDS;
        self.sample_interval_ms = self.sample_interval_ms.clamp(lo, hi);
        let (lo, hi) = RETENTION_SECONDS_BOUNDS;
        self.retention_seconds = self.retention_seconds.clamp(lo, hi);
    }
}

/// API server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default)]
    pub auth_token: Option<String>,
    /// Optional Unix domain socket path for local-only connections.
    /// UDS connections bypass token auth (local identity verified by socket credentials).
    /// Default: None (UDS disabled). Set to e.g. "/var/run/linnix/cognitod.sock" to enable.
    #[serde(default)]
    pub unix_socket: Option<String>,
    /// When true (default), /readyz reports NOT ready if the eBPF probes failed
    /// to attach. Linnix's whole function is kernel-derived stall attribution, so
    /// a node running userspace-only is not doing its job and should be visible
    /// as such rather than reporting healthy. Set false for deployments that
    /// intentionally run without kernel instrumentation.
    #[serde(default = "default_require_kernel_instrumentation")]
    pub require_kernel_instrumentation: bool,
}

fn default_require_kernel_instrumentation() -> bool {
    true
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            auth_token: None,
            unix_socket: None,
            require_kernel_instrumentation: default_require_kernel_instrumentation(),
        }
    }
}

fn default_listen_addr() -> String {
    "127.0.0.1:3000".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationConfig {
    pub apprise: Option<AppriseConfig>,
    pub slack: Option<SlackConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppriseConfig {
    pub urls: Vec<String>,
    #[serde(default)]
    pub min_severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    pub webhook_url: String,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default = "default_dashboard_url")]
    pub dashboard_base_url: String,
}

fn default_dashboard_url() -> String {
    "http://localhost:3000".to_string()
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct Config {
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    #[allow(dead_code)]
    pub logging: LoggingConfig,
    #[serde(default)]
    #[allow(dead_code)]
    pub outputs: OutputConfig,
    /// Deprecated `[prometheus]` section, folded into `outputs` on load.
    #[serde(default)]
    pub prometheus: Option<LegacyPrometheusConfig>,
    #[serde(default)]
    #[allow(dead_code)]
    pub rules: RulesFileConfig,
    #[serde(default)]
    pub reasoner: ReasonerConfig,
    #[serde(default)]
    pub probes: ProbesConfig,
    #[serde(default)]
    pub notifications: Option<NotificationConfig>,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    #[serde(default)]
    pub noise_budget: NoiseBudgetConfig,
    #[serde(default)]
    pub privacy: PrivacyConfig,
    #[serde(default)]
    pub psi: PsiConfig,
    #[serde(default)]
    pub telemetry: TelemetrySettings,
    /// Top-level sections/keys no field matches. Captured so `--check-config`
    /// can name them; a typo'd `[reasner]` is otherwise indistinguishable from
    /// having configured nothing.
    #[serde(flatten)]
    pub unknown: std::collections::BTreeMap<String, toml::Value>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PrivacyConfig {
    /// If true, sensitive fields (pod names, namespaces) will be hashed in alerts.
    #[serde(default = "default_redact_sensitive_data")]
    pub redact_sensitive_data: bool,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            redact_sensitive_data: default_redact_sensitive_data(),
        }
    }
}

fn default_redact_sensitive_data() -> bool {
    false
}

#[derive(Debug, Deserialize, Clone)]
pub struct NoiseBudgetConfig {
    /// Maximum number of alerts allowed per hour
    #[serde(default = "default_max_alerts_per_hour")]
    pub max_alerts_per_hour: u32,
    /// If true, suppress alerts when budget is exceeded (default: true)
    #[serde(default = "default_noise_budget_enabled")]
    pub enabled: bool,
}

impl Default for NoiseBudgetConfig {
    fn default() -> Self {
        Self {
            max_alerts_per_hour: default_max_alerts_per_hour(),
            enabled: default_noise_budget_enabled(),
        }
    }
}

fn default_max_alerts_per_hour() -> u32 {
    10 // Default to 10 alerts per hour to prevent spam
}

fn default_noise_budget_enabled() -> bool {
    true
}

impl Config {
    /// Load configuration, resolving the path as `--config` > `LINNIX_CONFIG` >
    /// the packaged default. A missing file yields defaults; a malformed one is
    /// an error. See [`Config::load_from`].
    pub fn load(explicit: Option<PathBuf>) -> anyhow::Result<Self> {
        Self::load_from(&resolve_config_path(explicit))
    }

    /// Load from a specific path.
    ///
    /// A **missing** file yields defaults — that is a legitimate way to run.
    /// A file that exists but cannot be read or parsed is a hard error.
    ///
    /// Both cases used to return `Config::default()` with a single `warn!`, so a
    /// typo in `linnix.toml` silently swapped every setting for a default the
    /// operator never chose — different thresholds, endpoints and PSI paths,
    /// with the daemon reporting healthy throughout. Failing loudly is the point
    /// of this function.
    pub fn load_from(path: &Path) -> anyhow::Result<Self> {
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                log::info!(
                    "[config] no config file at {}; using built-in defaults",
                    path.display()
                );
                return Ok(Config::default());
            }
            // Permission denied and friends: the file is there and we were meant
            // to read it. Do not pretend it is absent.
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "config file at {} exists but could not be read: {e}",
                    path.display()
                ));
            }
        };

        let mut config: Config = toml::from_str(&contents).map_err(|e| {
            anyhow::anyhow!("config file at {} could not be parsed: {e}", path.display())
        })?;

        config.warn_unknown_keys();
        config.telemetry.clamp_with_warning();
        config.apply_prometheus_compat();
        Ok(config)
    }

    /// Strict validation for `--check-config`. Returns every problem found,
    /// empty when the file is clean.
    ///
    /// This is where `deny_unknown_fields`-style strictness belongs: failing
    /// here costs nothing, whereas failing at startup would strand a fleet whose
    /// configs still carry a retired key.
    pub fn check(path: &Path) -> Vec<String> {
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return vec![format!("no config file at {}", path.display())];
            }
            Err(e) => return vec![format!("cannot read {}: {e}", path.display())],
        };

        let config: Config = match toml::from_str(&contents) {
            Ok(config) => config,
            Err(e) => return vec![format!("parse error: {e}")],
        };

        let mut problems = Vec::new();
        for key in config.unknown.keys() {
            problems.push(format!(
                "unrecognised top-level section or key `{key}` (not read by the daemon)"
            ));
        }
        for key in config.reasoner.unknown.keys() {
            problems.push(format!(
                "unrecognised key `{key}` in [reasoner] (not read by the daemon)"
            ));
        }
        for key in config.telemetry.unknown.keys() {
            problems.push(format!(
                "unrecognised key `{key}` in [telemetry] (not read by the daemon)"
            ));
        }
        problems.extend(config.telemetry.range_problems());
        problems
    }

    /// Names any `[reasoner]` key that no field matches.
    ///
    /// Deliberately a warning, not an error. `load()` falls back to
    /// `Config::default()` on any parse failure, so `deny_unknown_fields` would
    /// turn a single stray key into a silent, total reset — losing
    /// `api.auth_token` and leaving the HTTP API unauthenticated. That is a
    /// worse failure than the one it would prevent. Warning keeps the lenient
    /// load that `apply_prometheus_compat` was also written to preserve, while
    /// making the orphan visible at startup instead of never.
    fn warn_unknown_keys(&self) {
        if !self.unknown.is_empty() {
            let keys: Vec<&str> = self.unknown.keys().map(String::as_str).collect();
            log::warn!(
                "[config] ignoring unrecognised top-level section(s)/key(s): {}. \
                 These are not read by the daemon and have no effect. \
                 Run `cognitod --check-config` to validate.",
                keys.join(", ")
            );
        }
        if !self.telemetry.unknown.is_empty() {
            let keys: Vec<&str> = self.telemetry.unknown.keys().map(String::as_str).collect();
            log::warn!(
                "[config] ignoring unrecognised key(s) in [telemetry]: {}. \
                 Run `cognitod --check-config` to validate.",
                keys.join(", ")
            );
        }
        if !self.reasoner.unknown.is_empty() {
            let keys: Vec<&str> = self.reasoner.unknown.keys().map(String::as_str).collect();
            log::warn!(
                "[config] ignoring unrecognised key(s) in [reasoner]: {}. \
                 These are not read by the daemon and have no effect. \
                 Run `cognitod --check-config` to validate.",
                keys.join(", ")
            );
        }
    }

    /// Honours the legacy `[prometheus] enabled` spelling.
    ///
    /// Every config this project has shipped — `configs/linnix.toml`, the
    /// Darwin variant, and `k8s/configmap.yaml` — used a `[prometheus]`
    /// section, but the only key the daemon reads is `outputs.prometheus`.
    /// Unknown sections deserialize silently, so those deployments served 404
    /// on `/metrics/prometheus` while their config looked correct. The shipped
    /// files now use the canonical spelling; this keeps already-deployed ones
    /// working instead of silently exporting nothing.
    fn apply_prometheus_compat(&mut self) {
        if let Some(legacy) = &self.prometheus
            && legacy.enabled
            && !self.outputs.prometheus
        {
            log::warn!(
                "[config] `[prometheus] enabled` is deprecated; use `[outputs] prometheus = true`. \
                 Enabling the metrics endpoint from the legacy key."
            );
            self.outputs.prometheus = true;
        }
    }
}

/// The legacy `[prometheus]` section. Retained only so existing configs keep
/// working; `[outputs] prometheus` is the supported spelling.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct LegacyPrometheusConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct RuntimeConfig {
    #[serde(default = "default_offline")]
    pub offline: bool,
    #[serde(default = "default_cpu_target_pct")]
    pub cpu_target_pct: u64,
    #[serde(default = "default_rss_cap_mb")]
    pub rss_cap_mb: u64,
    #[serde(default = "default_events_rate_cap")]
    pub events_rate_cap: u64,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            offline: default_offline(),
            cpu_target_pct: default_cpu_target_pct(),
            rss_cap_mb: default_rss_cap_mb(),
            events_rate_cap: default_events_rate_cap(),
        }
    }
}

fn default_offline() -> bool {
    true
}
fn default_cpu_target_pct() -> u64 {
    25
}
fn default_rss_cap_mb() -> u64 {
    512
}
fn default_events_rate_cap() -> u64 {
    100_000
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct LoggingConfig {
    #[serde(default = "default_alerts_file")]
    pub alerts_file: String,
    #[serde(default = "default_journald")]
    pub journald: bool,
    #[serde(default = "default_insights_file")]
    pub insights_file: String,
    #[serde(default)]
    pub incident_context_file: Option<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            alerts_file: default_alerts_file(),
            journald: default_journald(),
            insights_file: default_insights_file(),
            incident_context_file: None,
        }
    }
}

fn default_alerts_file() -> String {
    "/var/log/linnix/alerts.ndjson".to_string()
}
fn default_journald() -> bool {
    true
}
fn default_insights_file() -> String {
    "/var/log/linnix/insights.ndjson".to_string()
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct RulesFileConfig {
    #[serde(default = "default_rules_file")]
    pub path: String,
}

impl Default for RulesFileConfig {
    fn default() -> Self {
        Self {
            path: default_rules_file(),
        }
    }
}

fn default_rules_file() -> String {
    "/etc/linnix/rules.toml".to_string()
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct ReasonerConfig {
    #[serde(default = "default_reasoner_enabled")]
    pub enabled: bool,
    #[serde(default = "default_reasoner_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_reasoner_model")]
    pub model: String,
    #[serde(default = "default_reasoner_timeout")]
    pub timeout_ms: u64,
    /// Keys present in `[reasoner]` that no field matches. Captured rather than
    /// discarded so `warn_unknown_keys` can name them at startup.
    #[serde(flatten)]
    pub unknown: std::collections::BTreeMap<String, toml::Value>,
}

impl Default for ReasonerConfig {
    fn default() -> Self {
        Self {
            enabled: default_reasoner_enabled(),
            endpoint: default_reasoner_endpoint(),
            model: default_reasoner_model(),
            timeout_ms: default_reasoner_timeout(),
            unknown: Default::default(),
        }
    }
}

fn default_reasoner_enabled() -> bool {
    true
}

fn default_reasoner_endpoint() -> String {
    // Must match the bundled model server, since Config::load() falls back to
    // Config::default() when the file is missing or malformed. Everything that
    // ships — linnix.toml, the systemd unit, docker-compose, k8s/configmap.yaml,
    // quickstart.sh — uses 8090; nothing listens on the 8087 this used to name.
    "http://localhost:8090/v1/chat/completions".to_string()
}

fn default_reasoner_model() -> String {
    // Matches the model name both LLM call sites previously hardcoded, and the
    // `model` key both shipped configs already set.
    "linnix-3b-distilled".to_string()
}

fn default_reasoner_timeout() -> u64 {
    // Milliseconds, and must match the documented default in
    // docs/wiki/Configuration-Guide.md plus the shipped configs, which all say
    // 30000. Was `150` — i.e. 150ms, far below CPU-inference latency — so any
    // install without a config file timed out on every analyzer call.
    30_000
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct OutputConfig {
    #[serde(default)]
    pub slack: bool,
    #[serde(default)]
    pub pagerduty: bool,
    #[serde(default)]
    pub prometheus: bool,
    /// Unauthenticated operational listener for Prometheus and probes. The
    /// main API listener does not serve this endpoint.
    #[serde(default = "default_metrics_listen_addr")]
    pub metrics_listen_addr: String,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            slack: false,
            pagerduty: false,
            prometheus: false,
            metrics_listen_addr: default_metrics_listen_addr(),
        }
    }
}

fn default_metrics_listen_addr() -> String {
    "127.0.0.1:9464".to_string()
}

#[derive(Clone)]
pub struct OfflineGuard {
    offline: bool,
}

impl OfflineGuard {
    pub fn new(offline: bool) -> Self {
        Self { offline }
    }
    pub fn is_offline(&self) -> bool {
        self.offline
    }
    /// Returns true if network operations are allowed.
    #[allow(dead_code)]
    pub fn check(&self, sink: &str) -> bool {
        if self.offline {
            log::warn!("offline mode: blocking {sink} sink");
            false
        } else {
            true
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct PsiConfig {
    /// Duration in seconds of sustained pressure required to trigger attribution
    #[serde(default = "default_psi_sustained_pressure_seconds")]
    pub sustained_pressure_seconds: u64,
    /// Stall attributed to a single offender, in milliseconds, before it is
    /// reported. A large stall split across many neighbours is not a noisy
    /// neighbour, so this is deliberately separate from the threshold that
    /// decides whether the victim is stalling at all.
    #[serde(default = "default_attribution_threshold_ms")]
    pub attribution_threshold_ms: u64,
    /// How long to wait before reporting the same offender/victim pair again.
    /// Pressure lasting an hour would otherwise re-alert every
    /// `sustained_pressure_seconds` for that whole hour. Set to 0 to report
    /// every occurrence. The Prometheus counters are unaffected either way —
    /// they remain the continuous signal.
    #[serde(default = "default_attribution_cooldown_seconds")]
    pub attribution_cooldown_seconds: u64,
}

impl Default for PsiConfig {
    fn default() -> Self {
        Self {
            sustained_pressure_seconds: default_psi_sustained_pressure_seconds(),
            attribution_threshold_ms: default_attribution_threshold_ms(),
            attribution_cooldown_seconds: default_attribution_cooldown_seconds(),
        }
    }
}

fn default_psi_sustained_pressure_seconds() -> u64 {
    15
}

fn default_attribution_threshold_ms() -> u64 {
    100
}

fn default_attribution_cooldown_seconds() -> u64 {
    300
}
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ProbesConfig {
    // Configuration for probe settings (reserved for future use)
}

/// Circuit breaker configuration for automatic remediation based on PSI (Pressure Stall Information)
///
/// PSI measures resource contention (stall time), not just usage.
/// Key insight: 100% CPU + low PSI = efficient worker. 40% CPU + high PSI = disaster.
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct CircuitBreakerConfig {
    /// Enable automatic circuit breaking (disabled by default for safety)
    #[serde(default = "default_circuit_breaker_enabled")]
    pub enabled: bool,

    /// CPU usage threshold (percent). Only trigger if BOTH usage and PSI are high.
    #[serde(default = "default_cpu_usage_threshold")]
    pub cpu_usage_threshold: f32,

    /// CPU PSI threshold (percent). Dual-signal: high usage + high PSI = thrashing.
    #[serde(default = "default_cpu_psi_threshold")]
    pub cpu_psi_threshold: f32,

    /// Memory PSI "full" threshold (percent). All tasks stalled = complete thrashing.
    #[serde(default = "default_memory_psi_full_threshold")]
    pub memory_psi_full_threshold: f32,

    /// I/O PSI "full" threshold (percent). Alert only, don't auto-kill.
    #[serde(default = "default_io_psi_full_threshold")]
    pub io_psi_full_threshold: f32,

    /// Check interval in seconds (aligned with system snapshot updates)
    #[serde(default = "default_check_interval_secs")]
    pub check_interval_secs: u64,

    /// Grace period in seconds - thresholds must be exceeded continuously for this duration
    /// before the circuit breaker will trigger. This prevents transient spikes from causing kills.
    /// Set to 0 to trigger immediately (not recommended).
    #[serde(default = "default_grace_period_secs")]
    pub grace_period_secs: u64,

    /// Require human approval even when circuit breaker triggers (override safety)
    #[serde(default = "default_require_human_approval")]
    pub require_human_approval: bool,

    /// Operation mode: "monitor" (default) or "enforce"
    /// In "monitor" mode, actions are proposed but NEVER executed automatically.
    #[serde(default = "default_circuit_breaker_mode")]
    pub mode: String,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: default_circuit_breaker_enabled(),
            cpu_usage_threshold: default_cpu_usage_threshold(),
            cpu_psi_threshold: default_cpu_psi_threshold(),
            memory_psi_full_threshold: default_memory_psi_full_threshold(),
            io_psi_full_threshold: default_io_psi_full_threshold(),
            check_interval_secs: default_check_interval_secs(),
            grace_period_secs: default_grace_period_secs(),
            require_human_approval: default_require_human_approval(),
            mode: default_circuit_breaker_mode(),
        }
    }
}

fn default_circuit_breaker_enabled() -> bool {
    true // Enabled by default when config present
}

fn default_cpu_usage_threshold() -> f32 {
    90.0 // Only consider high CPU usage
}

fn default_cpu_psi_threshold() -> f32 {
    40.0 // 40% stall time = 4 seconds out of every 10 wasted waiting
}

fn default_memory_psi_full_threshold() -> f32 {
    30.0 // 30% full stalls = entire system thrashing
}

fn default_io_psi_full_threshold() -> f32 {
    50.0 // Alert threshold for I/O saturation (don't auto-kill)
}

fn default_check_interval_secs() -> u64 {
    5 // Aligned with system snapshot update frequency
}

fn default_grace_period_secs() -> u64 {
    15 // Require 15 seconds of sustained breach before triggering
}

fn default_require_human_approval() -> bool {
    true // SAFETY: Always require human approval by default, even if mode is "enforce"
}

fn default_circuit_breaker_mode() -> String {
    "monitor".to_string() // Default to safe mode
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn parse_config_defaults() {
        let toml = r#"[runtime]
offline = true
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.runtime.offline);
        assert_eq!(cfg.api.listen_addr, "127.0.0.1:3000");
        assert!(cfg.api.auth_token.is_none());
    }

    #[test]
    fn the_canonical_spelling_enables_the_metrics_endpoint() {
        let toml = r#"[outputs]
prometheus = true
"#;
        let mut cfg: Config = toml::from_str(toml).unwrap();
        cfg.apply_prometheus_compat();
        assert!(cfg.outputs.prometheus);
    }

    #[test]
    fn the_legacy_prometheus_section_still_enables_the_endpoint() {
        // Every config this project shipped used this spelling while the daemon
        // read only `outputs.prometheus`, so those deployments served 404 on
        // /metrics/prometheus with a config that looked correct. Already-
        // deployed configs must keep working.
        let toml = r#"[prometheus]
enabled = true
"#;
        let mut cfg: Config = toml::from_str(toml).unwrap();
        assert!(
            !cfg.outputs.prometheus,
            "the legacy key alone never set the real field — that was the bug"
        );

        cfg.apply_prometheus_compat();
        assert!(
            cfg.outputs.prometheus,
            "a deployed config using the old spelling must still export metrics"
        );
    }

    #[test]
    fn the_metrics_endpoint_stays_off_when_nothing_asks_for_it() {
        let toml = r#"[runtime]
offline = true
"#;
        let mut cfg: Config = toml::from_str(toml).unwrap();
        cfg.apply_prometheus_compat();
        assert!(!cfg.outputs.prometheus);
    }

    #[test]
    fn the_shipped_configs_enable_the_metrics_endpoint() {
        // Guards the actual regression: a shipped config that looks like it
        // turns metrics on but does not.
        for (path, expected_addr) in [
            ("../configs/linnix.toml", "127.0.0.1:9464"),
            ("../configs/linnix.darwin.toml", "0.0.0.0:9464"),
        ] {
            let contents = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("cannot read {}: {}", path, e));
            let mut cfg: Config = toml::from_str(&contents)
                .unwrap_or_else(|e| panic!("{} does not parse: {}", path, e));
            cfg.apply_prometheus_compat();
            assert!(
                cfg.outputs.prometheus,
                "{} should serve /metrics/prometheus",
                path
            );
            assert_eq!(
                cfg.outputs.metrics_listen_addr, expected_addr,
                "{} should use the dedicated operational port",
                path
            );
        }
    }

    #[test]
    fn the_kubernetes_configmap_enables_the_metrics_endpoint() {
        // The DaemonSet is the deployment path the dashboard depends on, and
        // the one where the wrong spelling went unnoticed longest. Parse the
        // config out of the manifest exactly as the daemon would see it.
        let manifest = std::fs::read_to_string("../k8s/configmap.yaml")
            .expect("cannot read k8s/configmap.yaml");
        let doc: serde_yaml::Value =
            serde_yaml::from_str(&manifest).expect("configmap.yaml is not valid YAML");
        let embedded = doc["data"]["linnix.toml"]
            .as_str()
            .expect("configmap has no data['linnix.toml']");

        let mut cfg: Config =
            toml::from_str(embedded).expect("the embedded linnix.toml does not parse");
        cfg.apply_prometheus_compat();
        assert!(
            cfg.outputs.prometheus,
            "the DaemonSet must serve /metrics/prometheus or the dashboard is empty"
        );
        assert_eq!(
            cfg.outputs.metrics_listen_addr, "0.0.0.0:9464",
            "Kubernetes must expose unauthenticated metrics on the dedicated surface"
        );
    }

    #[test]
    fn the_docker_quickstart_injects_auth_and_probes_the_operational_listener() {
        let compose = std::fs::read_to_string("../docker-compose.yml")
            .expect("cannot read docker-compose.yml");
        let compose: serde_yaml::Value =
            serde_yaml::from_str(&compose).expect("docker-compose.yml is not valid YAML");
        let cognitod = &compose["services"]["cognitod"];
        let environment = cognitod["environment"]
            .as_sequence()
            .expect("cognitod environment must be a sequence");
        assert!(
            environment
                .iter()
                .any(|entry| { entry.as_str() == Some("LINNIX_API_TOKEN=${LINNIX_API_TOKEN:-}") })
        );
        assert!(
            cognitod["healthcheck"]["test"]
                .as_sequence()
                .expect("cognitod healthcheck test must be a sequence")
                .iter()
                .any(|entry| entry.as_str() == Some("http://localhost:9464/readyz"))
        );

        let darwin = std::fs::read_to_string("../docker-compose.darwin.yml")
            .expect("cannot read docker-compose.darwin.yml");
        let darwin: serde_yaml::Value =
            serde_yaml::from_str(&darwin).expect("docker-compose.darwin.yml is not valid YAML");
        assert!(
            darwin["services"]["cognitod"]["ports"]
                .as_sequence()
                .expect("Darwin cognitod ports must be a sequence")
                .iter()
                .any(|entry| entry.as_str() == Some("127.0.0.1:9464:9464"))
        );

        let quickstart =
            std::fs::read_to_string("../quickstart.sh").expect("cannot read quickstart.sh");
        assert!(quickstart.contains("openssl rand -hex 32"));
        assert!(quickstart.contains("http://localhost:9464/healthz"));
    }

    #[test]
    fn the_ec2_deployment_exposes_the_operational_listener() {
        let user_data = std::fs::read_to_string("../terraform/ec2/user-data.sh")
            .expect("cannot read terraform/ec2/user-data.sh");
        assert!(user_data.contains("[outputs]"));
        assert!(user_data.contains("prometheus = true"));
        assert!(user_data.contains("metrics_listen_addr = \"0.0.0.0:9464\""));

        let main = std::fs::read_to_string("../terraform/ec2/main.tf")
            .expect("cannot read terraform/ec2/main.tf");
        assert!(main.contains("from_port   = 9464"));
        assert!(main.contains("to_port     = 9464"));

        let outputs = std::fs::read_to_string("../terraform/ec2/outputs.tf")
            .expect("cannot read terraform/ec2/outputs.tf");
        assert!(outputs.contains(":9464/metrics/prometheus"));
    }

    #[test]
    fn the_kubernetes_daemonset_uses_a_secret_for_the_public_api_token() {
        let manifest = std::fs::read_to_string("../k8s/daemonset.yaml")
            .expect("cannot read k8s/daemonset.yaml");
        let doc: serde_yaml::Value =
            serde_yaml::from_str(&manifest).expect("daemonset.yaml is not valid YAML");
        let container = doc["spec"]["template"]["spec"]["containers"]
            .as_sequence()
            .and_then(|containers| {
                containers
                    .iter()
                    .find(|container| container["name"].as_str() == Some("cognitod"))
            })
            .expect("DaemonSet has no cognitod container");
        let token = container["env"]
            .as_sequence()
            .and_then(|environment| {
                environment
                    .iter()
                    .find(|entry| entry["name"].as_str() == Some("LINNIX_API_TOKEN"))
            })
            .expect("DaemonSet must inject LINNIX_API_TOKEN");

        assert_eq!(
            token["valueFrom"]["secretKeyRef"]["name"].as_str(),
            Some("linnix-api-token")
        );
        assert_eq!(
            token["valueFrom"]["secretKeyRef"]["key"].as_str(),
            Some("token")
        );
        assert_eq!(
            container["livenessProbe"]["httpGet"]["port"].as_str(),
            Some("metrics")
        );
        assert_eq!(
            container["readinessProbe"]["httpGet"]["port"].as_str(),
            Some("metrics")
        );
    }

    #[test]
    fn parse_api_config() {
        let toml = r#"[api]
listen_addr = "0.0.0.0:8080"
auth_token = "secret123"
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.api.listen_addr, "0.0.0.0:8080");
        assert_eq!(cfg.api.auth_token, Some("secret123".to_string()));
    }

    #[test]
    fn env_override() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "[runtime]\noffline = false").unwrap();
        unsafe {
            std::env::set_var(ENV_CONFIG_PATH, file.path());
        }
        let cfg = Config::load(None).expect("valid config must load");
        assert!(!cfg.runtime.offline);
        unsafe {
            std::env::remove_var(ENV_CONFIG_PATH);
        }
    }

    #[test]
    fn an_unrecognised_reasoner_key_is_captured_not_discarded() {
        let cfg: Config = toml::from_str(
            r#"
[reasoner]
endpoint = "http://prod-llm:8090/v1/chat/completions"
window_seconds = 10
min_eps_to_enable = 10
"#,
        )
        .expect("lenient parse still succeeds");

        // The recognised key still lands where it should.
        assert_eq!(
            cfg.reasoner.endpoint,
            "http://prod-llm:8090/v1/chat/completions"
        );
        // The orphans are visible rather than silently dropped.
        let mut keys: Vec<&str> = cfg.reasoner.unknown.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["min_eps_to_enable", "window_seconds"]);
    }

    #[test]
    fn an_unrecognised_key_does_not_discard_the_rest_of_the_config() {
        // The regression `deny_unknown_fields` would have introduced: a parse
        // error sends load() to Config::default(), losing auth_token and
        // leaving the API unauthenticated. Capturing instead of denying keeps
        // every other value intact.
        let cfg: Config = toml::from_str(
            r#"
[api]
listen_addr = "0.0.0.0:9999"
auth_token = "super-secret"

[reasoner]
endpoint = "http://prod-llm:8090/v1/chat/completions"
typo_key = 1
"#,
        )
        .expect("a stray key must not fail the parse");

        assert_eq!(cfg.api.listen_addr, "0.0.0.0:9999");
        assert_eq!(cfg.api.auth_token.as_deref(), Some("super-secret"));
        assert_eq!(
            cfg.reasoner.endpoint,
            "http://prod-llm:8090/v1/chat/completions"
        );
        assert!(cfg.reasoner.unknown.contains_key("typo_key"));
    }

    #[test]
    fn a_clean_reasoner_section_captures_nothing() {
        let cfg: Config = toml::from_str(
            r#"
[reasoner]
enabled = true
endpoint = "http://localhost:8090/v1/chat/completions"
model = "linnix-3b-distilled"
timeout_ms = 30000
"#,
        )
        .unwrap();
        assert!(
            cfg.reasoner.unknown.is_empty(),
            "shipped config must be clean"
        );
    }

    #[test]
    fn an_explicit_path_beats_the_env_var_and_the_default() {
        // `--config` used to be declared and never read. Whatever the
        // environment says, the explicit path wins.
        let explicit = PathBuf::from("/tmp/explicit-linnix.toml");
        assert_eq!(
            resolve_config_path(Some(explicit.clone())),
            explicit,
            "--config must take precedence"
        );
    }

    #[test]
    fn no_config_file_still_yields_defaults() {
        let missing = PathBuf::from("/nonexistent/linnix/does-not-exist.toml");
        let cfg = Config::load_from(&missing).expect("a missing file is not an error");
        assert_eq!(cfg.api.listen_addr, default_listen_addr());
    }

    #[test]
    fn a_malformed_file_is_an_error_rather_than_a_silent_reset() {
        // The regression this whole change exists to prevent: a typo used to
        // swap every setting for a default the operator never chose, announced
        // by one warn! line.
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "[api]\nlisten_addr = = broken").unwrap();

        let err = Config::load_from(file.path()).expect_err("malformed config must fail");
        assert!(
            err.to_string().contains("could not be parsed"),
            "error should name the problem, got: {err}"
        );
    }

    #[test]
    fn a_wrong_type_is_also_fatal() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "[reasoner]\ntimeout_ms = \"thirty seconds\"").unwrap();
        assert!(
            Config::load_from(file.path()).is_err(),
            "a string where u64 is expected must not silently become the default"
        );
    }

    #[test]
    fn check_names_unknown_sections_and_keys() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            "[reasner]\nendpoint = \"typo\"\n\n[reasoner]\nwindow_seconds = 10"
        )
        .unwrap();

        let problems = Config::check(file.path());
        assert_eq!(problems.len(), 2, "got: {problems:?}");
        assert!(problems.iter().any(|p| p.contains("reasner")));
        assert!(problems.iter().any(|p| p.contains("window_seconds")));
    }

    #[test]
    fn check_passes_on_a_clean_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            "[reasoner]\nenabled = true\nmodel = \"linnix-3b-distilled\""
        )
        .unwrap();
        assert!(Config::check(file.path()).is_empty());
    }

    #[test]
    fn the_shipped_configs_pass_their_own_validator() {
        // Guards the bug class directly: if anyone adds a key to a shipped
        // config that no field reads, this fails in CI instead of shipping.
        for name in ["linnix.toml", "linnix.darwin.toml"] {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../configs")
                .join(name);
            let problems = Config::check(&path);
            assert!(problems.is_empty(), "{name} has problems: {problems:?}");
        }
    }

    #[test]
    fn telemetry_defaults_match_the_values_that_were_hardcoded() {
        // The point of wiring these: anyone who does not set them must get
        // exactly the behaviour they had before.
        let t = TelemetrySettings::default();
        assert_eq!(t.sample_interval(), std::time::Duration::from_secs(5));
        assert_eq!(t.retention(), std::time::Duration::from_secs(300));
        assert_eq!(t.min_eps_to_enable, 20);
    }

    #[test]
    fn telemetry_values_are_read_from_the_file() {
        let cfg: Config = toml::from_str(
            r#"
[telemetry]
sample_interval_ms = 2000
retention_seconds = 120
min_eps_to_enable = 5
"#,
        )
        .unwrap();
        assert_eq!(
            cfg.telemetry.sample_interval(),
            std::time::Duration::from_secs(2)
        );
        assert_eq!(
            cfg.telemetry.retention(),
            std::time::Duration::from_secs(120)
        );
        assert_eq!(cfg.telemetry.min_eps_to_enable, 5);
    }

    #[test]
    fn an_absurd_sample_interval_is_clamped_not_obeyed() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "[telemetry]\nsample_interval_ms = 1").unwrap();
        let cfg = Config::load_from(file.path()).unwrap();
        assert_eq!(
            cfg.telemetry.sample_interval_ms, SAMPLE_INTERVAL_MS_BOUNDS.0,
            "a 1ms sample interval would burn CPU on every node"
        );
    }

    #[test]
    fn check_flags_out_of_range_telemetry_values() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            "[telemetry]\nsample_interval_ms = 1\nretention_seconds = 999999"
        )
        .unwrap();
        let problems = Config::check(file.path());
        assert_eq!(problems.len(), 2, "got: {problems:?}");
        assert!(problems.iter().any(|p| p.contains("sample_interval_ms")));
        assert!(problems.iter().any(|p| p.contains("retention_seconds")));
    }
}
