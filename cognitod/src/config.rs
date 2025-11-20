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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppriseConfig {
    pub urls: Vec<String>,
    #[serde(default)]
    pub min_severity: Option<String>,
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
    10
}

fn default_reasoner_kb_max_doc_bytes() -> usize {
    5_000
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

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ProbesConfig {
    // Configuration for probe settings (reserved for future use)
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
