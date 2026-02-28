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
    /// Optional Unix domain socket path for local-only connections.
    /// UDS connections bypass token auth (local identity verified by socket credentials).
    /// Default: None (UDS disabled). Set to e.g. "/var/run/linnix/cognitod.sock" to enable.
    #[serde(default)]
    pub unix_socket: Option<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            auth_token: None,
            unix_socket: None,
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
    #[serde(default)]
    pub mandate: MandateConfig,
    #[serde(default)]
    pub spend_limits: SpendLimitsConfig,
    #[serde(default)]
    pub compliance: ComplianceConfig,
    #[serde(default)]
    pub receipt_privacy: ReceiptPrivacyConfig,
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

// =============================================================================
// LINNIX-CLAW: MANDATE CONFIGURATION
// =============================================================================

/// Configuration for the Linnix-Claw mandate enforcement subsystem.
///
/// Added via `[mandate]` section in linnix.toml.
///
/// Example:
/// ```toml
/// [mandate]
/// mode = "monitor"          # "monitor" or "enforce"
/// map_capacity = 65536      # max entries in BPF LRU map
/// allow_commerce_without_lsm = false
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct MandateConfig {
    /// Enforcement mode: "monitor" (log only) or "enforce" (block unauthorized).
    /// Default: "monitor" — safe default that doesn't break existing workflows.
    #[serde(default = "default_mandate_mode")]
    pub mode: String,

    /// Maximum entries in the MANDATE_MAP BPF LRU hash.
    /// Must match the compiled eBPF program's map definition.
    #[serde(default = "default_mandate_map_capacity")]
    pub map_capacity: u32,

    /// If true, mandate API is available even without BPF LSM support.
    /// Mandates are tracked but not kernel-enforced.
    /// Default: false — commerce features require kernel enforcement.
    #[serde(default)]
    pub allow_commerce_without_lsm: bool,

    /// Path to the agent identity key file (Ed25519 + secp256k1 seed).
    /// Default: /var/lib/linnix/identity.key
    #[serde(default = "default_identity_path")]
    pub identity_path: String,
}

impl Default for MandateConfig {
    fn default() -> Self {
        Self {
            mode: default_mandate_mode(),
            map_capacity: default_mandate_map_capacity(),
            allow_commerce_without_lsm: false,
            identity_path: default_identity_path(),
        }
    }
}

fn default_mandate_mode() -> String {
    "monitor".to_string()
}

fn default_mandate_map_capacity() -> u32 {
    65_536
}

fn default_identity_path() -> String {
    "/var/lib/linnix/identity.key".to_string()
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

// =============================================================================
// LINNIX-CLAW PHASE 4: SPEND LIMITS (§9.1)
// =============================================================================

/// Per-agent spending limit override.
///
/// Example TOML:
/// ```toml
/// [mandate.spend_limits.per_agent."did:web:untrusted-agent.io"]
/// daily_cents = 1000
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerAgentLimit {
    pub daily_cents: u64,
}

/// Spend control limits applied by cognitod's `SpendTracker`.
///
/// All amounts in USD cents (§8.5).
///
/// Example TOML:
/// ```toml
/// [spend_limits]
/// per_mandate_cents = 5000
/// daily_cents = 50000
/// monthly_cents = 500000
///
/// [spend_limits.per_agent."did:web:untrusted.io"]
/// daily_cents = 1000
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendLimitsConfig {
    /// Max USD cents per individual mandate. Default: $50.
    #[serde(default = "default_per_mandate_cents")]
    pub per_mandate_cents: u64,

    /// Max aggregate USD cents per hour (rolling). Optional — None = no hourly limit.
    #[serde(default)]
    pub hourly_cents: Option<u64>,

    /// Max aggregate USD cents per day (rolling 24h). Default: $500.
    #[serde(default = "default_daily_cents")]
    pub daily_cents: u64,

    /// Max aggregate USD cents per month (rolling 30d). Default: $5,000.
    #[serde(default = "default_monthly_cents")]
    pub monthly_cents: u64,

    /// Per-agent daily limit overrides. Key is agent DID.
    #[serde(default)]
    pub per_agent: std::collections::HashMap<String, PerAgentLimit>,
}

impl Default for SpendLimitsConfig {
    fn default() -> Self {
        Self {
            per_mandate_cents: default_per_mandate_cents(),
            hourly_cents: None,
            daily_cents: default_daily_cents(),
            monthly_cents: default_monthly_cents(),
            per_agent: std::collections::HashMap::new(),
        }
    }
}

fn default_per_mandate_cents() -> u64 {
    5000 // $50
}
fn default_daily_cents() -> u64 {
    50_000 // $500
}
fn default_monthly_cents() -> u64 {
    500_000 // $5,000
}

// =============================================================================
// LINNIX-CLAW PHASE 4: COMPLIANCE CONTROLS (§10.3)
// =============================================================================

/// Compliance configuration for sanctions screening, KYT, and jurisdiction blocks.
///
/// Feature-gated: compile with `--features compliance` to enable runtime checks.
/// Without the feature, the `ComplianceEngine` operates in permissive mode.
///
/// Example TOML:
/// ```toml
/// [compliance]
/// enabled = true
/// screening_provider = "ofac_sdn"
/// kyt_threshold_cents = 300000
/// blocked_jurisdictions = ["KP", "IR", "CU", "SY"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    /// Master switch. Default: false (opt-in).
    #[serde(default)]
    pub enabled: bool,

    /// Screening provider: "ofac_sdn", "chainalysis", "elliptic", or "none".
    #[serde(default = "default_screening_provider")]
    pub screening_provider: String,

    /// Env var name holding the screening API key.
    #[serde(default)]
    pub screening_api_key_env: String,

    /// Cache TTL for screening results, in hours. Default: 24.
    #[serde(default = "default_screening_cache_ttl")]
    pub screening_cache_ttl_hours: u64,

    /// KYT threshold in USD cents. Default: $3,000 (FATF Travel Rule).
    #[serde(default = "default_kyt_threshold")]
    pub kyt_threshold_cents: u64,

    /// Blocked jurisdictions (ISO 3166 alpha-2).
    #[serde(default = "default_blocked_jurisdictions")]
    pub blocked_jurisdictions: Vec<String>,
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            screening_provider: default_screening_provider(),
            screening_api_key_env: String::new(),
            screening_cache_ttl_hours: default_screening_cache_ttl(),
            kyt_threshold_cents: default_kyt_threshold(),
            blocked_jurisdictions: default_blocked_jurisdictions(),
        }
    }
}

fn default_screening_provider() -> String {
    "none".to_string()
}
fn default_screening_cache_ttl() -> u64 {
    24
}
fn default_kyt_threshold() -> u64 {
    300_000 // $3,000
}
fn default_blocked_jurisdictions() -> Vec<String> {
    vec![
        "KP".to_string(),
        "IR".to_string(),
        "CU".to_string(),
        "SY".to_string(),
    ]
}

// =============================================================================
// LINNIX-CLAW PHASE 4: RECEIPT PRIVACY (§10.4)
// =============================================================================

/// Receipt privacy and redaction configuration.
///
/// Example TOML:
/// ```toml
/// [receipt_privacy]
/// redaction_level = "external"
/// retention_days = 90
/// encrypt_db = false
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptPrivacyConfig {
    /// Redaction level: "none", "external" (default), or "full".
    #[serde(default = "default_redaction_level")]
    pub redaction_level: String,

    /// Days to retain receipts in local SQLite. Default: 90.
    #[serde(default = "default_retention_days")]
    pub retention_days: u64,

    /// Enable SQLCipher encryption for receipt DB.
    #[serde(default)]
    pub encrypt_db: bool,

    /// Path to the database encryption key.
    #[serde(default = "default_db_key_path")]
    pub db_key_path: String,
}

impl Default for ReceiptPrivacyConfig {
    fn default() -> Self {
        Self {
            redaction_level: default_redaction_level(),
            retention_days: default_retention_days(),
            encrypt_db: false,
            db_key_path: default_db_key_path(),
        }
    }
}

fn default_redaction_level() -> String {
    "external".to_string()
}
fn default_retention_days() -> u64 {
    90
}
fn default_db_key_path() -> String {
    "/var/lib/linnix/receipt_db.key".to_string()
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

    #[test]
    fn parse_spend_limits() {
        let toml = r#"
[spend_limits]
per_mandate_cents = 10000
hourly_cents = 25000
daily_cents = 100000
monthly_cents = 1000000

[spend_limits.per_agent."did:web:untrusted.io"]
daily_cents = 500
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.spend_limits.per_mandate_cents, 10000);
        assert_eq!(cfg.spend_limits.hourly_cents, Some(25000));
        assert_eq!(cfg.spend_limits.daily_cents, 100000);
        assert_eq!(cfg.spend_limits.monthly_cents, 1000000);
        assert_eq!(
            cfg.spend_limits
                .per_agent
                .get("did:web:untrusted.io")
                .unwrap()
                .daily_cents,
            500
        );
    }

    #[test]
    fn parse_compliance_config() {
        let toml = r#"
[compliance]
enabled = true
screening_provider = "ofac_sdn"
kyt_threshold_cents = 500000
blocked_jurisdictions = ["KP", "IR"]
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.compliance.enabled);
        assert_eq!(cfg.compliance.screening_provider, "ofac_sdn");
        assert_eq!(cfg.compliance.kyt_threshold_cents, 500000);
        assert_eq!(cfg.compliance.blocked_jurisdictions, vec!["KP", "IR"]);
    }

    #[test]
    fn parse_receipt_privacy_config() {
        let toml = r#"
[receipt_privacy]
redaction_level = "full"
retention_days = 30
encrypt_db = true
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.receipt_privacy.redaction_level, "full");
        assert_eq!(cfg.receipt_privacy.retention_days, 30);
        assert!(cfg.receipt_privacy.encrypt_db);
    }

    #[test]
    fn spend_limits_defaults() {
        let cfg = SpendLimitsConfig::default();
        assert_eq!(cfg.per_mandate_cents, 5000);
        assert_eq!(cfg.hourly_cents, None);
        assert_eq!(cfg.daily_cents, 50000);
        assert_eq!(cfg.monthly_cents, 500000);
        assert!(cfg.per_agent.is_empty());
    }

    #[test]
    fn compliance_defaults() {
        let cfg = ComplianceConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.screening_provider, "none");
        assert_eq!(cfg.kyt_threshold_cents, 300000);
        assert_eq!(cfg.blocked_jurisdictions.len(), 4);
    }

    #[test]
    fn receipt_privacy_defaults() {
        let cfg = ReceiptPrivacyConfig::default();
        assert_eq!(cfg.redaction_level, "external");
        assert_eq!(cfg.retention_days, 90);
        assert!(!cfg.encrypt_db);
    }
}
