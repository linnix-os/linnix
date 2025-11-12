use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const DEFAULT_CONFIG_PATH: &str = "/etc/linnix/linnix.toml";
const ENV_CONFIG_PATH: &str = "LINNIX_CONFIG";

/// Notification configuration for external alerting systems
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationConfig {
    /// Apprise notification configuration (supports 100+ services)
    pub apprise: Option<AppriseConfig>,
}

/// Apprise notification configuration
///
/// Apprise provides a unified interface to send notifications to 100+ services
/// including Slack, Discord, Teams, Telegram, SMS providers, and email.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppriseConfig {
    /// List of Apprise service URLs
    ///
    /// Examples:
    /// - Slack: "slack://xoxb-token/C0123456789"
    /// - Discord: "discord://webhook_id/webhook_token"
    /// - Email: "mailto://user:pass@smtp.gmail.com"
    ///
    /// See https://github.com/caronc/apprise for full list of supported services
    pub urls: Vec<String>,

    /// Minimum severity level to notify (optional)
    ///
    /// Valid values: "info", "low", "medium", "high"
    /// Default: "info" (notify all alerts)
    #[serde(default)]
    pub min_severity: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)]
pub struct Config {
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
            Ok(contents) => toml::from_str(&contents).unwrap_or_default(),
            Err(_) => Config::default(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
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
pub struct ReasonerConfig {
    #[serde(default = "default_reasoner_enabled")]
    pub enabled: bool,
    #[serde(default = "default_reasoner_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_reasoner_window")]
    pub window_seconds: u64,
    #[serde(default = "default_reasoner_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_reasoner_min_eps")]
    pub min_eps_to_enable: u64,
    #[serde(default = "default_reasoner_topk_kb")]
    pub topk_kb: usize,
    #[serde(default = "default_reasoner_tools_enabled")]
    pub tools_enabled: bool,
    #[serde(default)]
    pub kb: ReasonerKbConfig,
}

impl Default for ReasonerConfig {
    fn default() -> Self {
        Self {
            enabled: default_reasoner_enabled(),
            endpoint: default_reasoner_endpoint(),
            window_seconds: default_reasoner_window(),
            timeout_ms: default_reasoner_timeout(),
            min_eps_to_enable: default_reasoner_min_eps(),
            topk_kb: default_reasoner_topk_kb(),
            tools_enabled: default_reasoner_tools_enabled(),
            kb: ReasonerKbConfig::default(),
        }
    }
}

fn default_reasoner_enabled() -> bool {
    true
}

fn default_reasoner_endpoint() -> String {
    "http://127.0.0.1:8087/v1/chat/completions".to_string()
}

fn default_reasoner_window() -> u64 {
    5
}

fn default_reasoner_timeout() -> u64 {
    150
}

fn default_reasoner_min_eps() -> u64 {
    20
}

fn default_reasoner_topk_kb() -> usize {
    3
}

fn default_reasoner_tools_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone)]
pub struct ReasonerKbConfig {
    #[serde(default = "default_reasoner_kb_dir")]
    pub dir: Option<PathBuf>,
    #[serde(default = "default_reasoner_kb_max_docs")]
    pub max_docs: usize,
    #[serde(default = "default_reasoner_kb_max_doc_bytes")]
    pub max_doc_bytes: usize,
}

impl Default for ReasonerKbConfig {
    fn default() -> Self {
        Self {
            dir: default_reasoner_kb_dir(),
            max_docs: default_reasoner_kb_max_docs(),
            max_doc_bytes: default_reasoner_kb_max_doc_bytes(),
        }
    }
}

fn default_reasoner_kb_dir() -> Option<PathBuf> {
    Some(PathBuf::from("/etc/linnix/kb"))
}

fn default_reasoner_kb_max_docs() -> usize {
    200
}

fn default_reasoner_kb_max_doc_bytes() -> usize {
    200_000
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
pub struct ProbesConfig {
    /// Enable page fault tracing (high overhead, for debugging only)
    #[serde(default = "default_enable_page_faults")]
    pub enable_page_faults: bool,
}

impl Default for ProbesConfig {
    fn default() -> Self {
        Self {
            enable_page_faults: default_enable_page_faults(),
        }
    }
}

fn default_enable_page_faults() -> bool {
    false // Disabled by default for production - too high frequency
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
cpu_target_pct = 25
rss_cap_mb = 512
events_rate_cap = 100000
[reasoner]
enabled = true
endpoint = "http://127.0.0.1:8087/v1/chat/completions"
window_seconds = 5
timeout_ms = 150
min_eps_to_enable = 20
[logging]
alerts_file = "/var/log/linnix/alerts.ndjson"
journald = true
[outputs]
slack = false
pagerduty = false
prometheus = false
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.runtime.offline);
        assert_eq!(cfg.runtime.cpu_target_pct, 25);
        assert_eq!(cfg.logging.alerts_file, "/var/log/linnix/alerts.ndjson");
        assert_eq!(cfg.logging.insights_file, "/var/log/linnix/insights.ndjson");
        assert!(!cfg.outputs.slack);
        assert_eq!(cfg.rules.path, "/etc/linnix/rules.toml");
        assert!(cfg.reasoner.enabled);
        assert_eq!(cfg.reasoner.window_seconds, 5);
        assert_eq!(cfg.reasoner.min_eps_to_enable, 20);
        assert_eq!(cfg.reasoner.topk_kb, 3);
        assert!(cfg.reasoner.tools_enabled);
        assert_eq!(cfg.reasoner.kb.max_docs, 200);
        assert_eq!(cfg.reasoner.kb.max_doc_bytes, 200_000);
        assert_eq!(
            cfg.reasoner.kb.dir.as_deref(),
            Some(std::path::Path::new("/etc/linnix/kb"))
        );
        assert!(cfg.logging.incident_context_file.is_none());
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
