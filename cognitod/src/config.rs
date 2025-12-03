use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const DEFAULT_CONFIG_PATH: &str = "/etc/linnix/linnix.toml";
const ENV_CONFIG_PATH: &str = "LINNIX_CONFIG";

/// API server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default)]
    pub auth_token: Option<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            auth_token: None,
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
    /// Load configuration from file. The path can be overridden
    /// with the `LINNIX_CONFIG` environment variable. If the file
    /// is missing or fails to parse, defaults are returned.
    pub fn load() -> Self {
        let path =
            std::env::var(ENV_CONFIG_PATH).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());
        let path = PathBuf::from(path);
        match fs::read_to_string(&path) {
            Ok(contents) => match toml::from_str(&contents) {
                Ok(config) => config,
                Err(e) => {
                    log::warn!(
                        "Failed to parse config file at {}: {}. Using defaults.",
                        path.display(),
                        e
                    );
                    Config::default()
                }
            },
            Err(_) => Config::default(),
        }
    }
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
    #[serde(default = "default_reasoner_timeout")]
    pub timeout_ms: u64,
}

impl Default for ReasonerConfig {
    fn default() -> Self {
        Self {
            enabled: default_reasoner_enabled(),
            endpoint: default_reasoner_endpoint(),
            timeout_ms: default_reasoner_timeout(),
        }
    }
}

fn default_reasoner_enabled() -> bool {
    true
}

fn default_reasoner_endpoint() -> String {
    "http://127.0.0.1:8087/v1/chat/completions".to_string()
}

fn default_reasoner_timeout() -> u64 {
    150
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct OutputConfig {
    #[serde(default)]
    pub slack: bool,
    #[serde(default)]
    pub pagerduty: bool,
    #[serde(default)]
    pub prometheus: bool,
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
}

impl Default for PsiConfig {
    fn default() -> Self {
        Self {
            sustained_pressure_seconds: default_psi_sustained_pressure_seconds(),
        }
    }
}

fn default_psi_sustained_pressure_seconds() -> u64 {
    15
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
        let cfg = Config::load();
        assert!(!cfg.runtime.offline);
        unsafe {
            std::env::remove_var(ENV_CONFIG_PATH);
        }
    }
}
