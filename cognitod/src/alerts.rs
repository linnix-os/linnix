#[cfg(test)]
use crate::ProcessEventWire;
use crate::handler::Handler;
use crate::metrics::Metrics;
use crate::{ProcessEvent, types::SystemSnapshot};
use anyhow::{Context, anyhow};
use async_trait::async_trait;
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::convert::TryFrom;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use sysinfo::System;
use tokio::sync::{Mutex, broadcast};
use tokio::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            _ => Severity::Info,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

impl<'de> Deserialize<'de> for Severity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Severity::from_str(&value))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub rule: String,
    pub severity: Severity,
    pub message: String,
    pub host: String,
}

impl Alert {
    pub fn incident_context_line(&self) -> String {
        let mut message = self.message.replace(['\n', '\r'], " ");
        if message.len() > 256 {
            message.truncate(256);
        }
        format!(
            "host={host} severity={sev} rule={rule}: {msg}",
            host = self.host,
            sev = self.severity.as_str(),
            rule = self.rule,
            msg = message.trim()
        )
    }
}

#[derive(Debug, Clone)]
pub enum Detector {
    ForksPerSec {
        threshold: u64,
        duration: u64,
    },
    ForkBurst {
        threshold: u64,
        window_seconds: u64,
    },
    #[allow(dead_code)]
    ExecRate {
        #[allow(dead_code)]
        regex: String,
        #[allow(dead_code)]
        rate_per_min: u64,
        #[allow(dead_code)]
        median_lifetime: u64,
    },
    ShortJobFlood {
        threshold: u64,
        window_seconds: u64,
        max_exec_duration_ms: u64,
    },
    RunawayTree {
        threshold: u64,
        window_seconds: u64,
    },
    SubtreeCpuPct {
        threshold: f32,
        duration: u64,
    },
    SubtreeRssMb {
        threshold: u64,
        duration: u64,
    },
    #[allow(dead_code)]
    ZombieCount {
        #[allow(dead_code)]
        threshold: u64,
        #[allow(dead_code)]
        duration: u64,
    },
}

#[derive(Debug, Clone)]
pub struct RuleConfig {
    pub name: String,
    pub severity: Severity,
    pub cooldown: u64,
    pub detector: Detector,
}

struct Rule {
    cfg: RuleConfig,
}

const DEFAULT_COOLDOWN_SECS: u64 = 60;
const DEFAULT_SHORT_JOB_DURATION_MS: u64 = 1000;

#[derive(Debug, Deserialize)]
struct RawRule {
    name: String,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    cooldown: Option<u64>,
    #[serde(flatten)]
    detector: RawDetector,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "detector", rename_all = "snake_case")]
enum RawDetector {
    ForkBurst {
        threshold: u64,
        window_seconds: u64,
    },
    ShortJobFlood {
        threshold: u64,
        window_seconds: u64,
        #[serde(default = "default_short_job_duration_ms")]
        max_exec_duration_ms: u64,
    },
    RunawayTree {
        threshold: u64,
        window_seconds: u64,
    },
    ForksPerSec {
        threshold: u64,
        duration: u64,
    },
    ExecRate {
        regex: String,
        rate_per_min: u64,
        median_lifetime: u64,
    },
    SubtreeCpuPct {
        threshold: f32,
        duration: u64,
    },
    SubtreeRssMb {
        threshold: u64,
        duration: u64,
    },
    ZombieCount {
        threshold: u64,
        duration: u64,
    },
}

fn default_short_job_duration_ms() -> u64 {
    DEFAULT_SHORT_JOB_DURATION_MS
}

impl TryFrom<RawRule> for RuleConfig {
    type Error = anyhow::Error;

    fn try_from(value: RawRule) -> Result<Self, Self::Error> {
        let severity = value
            .severity
            .as_deref()
            .map(Severity::from_str)
            .unwrap_or(Severity::Info);
        let cooldown = value.cooldown.unwrap_or(DEFAULT_COOLDOWN_SECS);

        let detector = match value.detector {
            RawDetector::ForkBurst {
                threshold,
                window_seconds,
            } => Detector::ForkBurst {
                threshold,
                window_seconds,
            },
            RawDetector::ShortJobFlood {
                threshold,
                window_seconds,
                max_exec_duration_ms,
            } => Detector::ShortJobFlood {
                threshold,
                window_seconds,
                max_exec_duration_ms,
            },
            RawDetector::RunawayTree {
                threshold,
                window_seconds,
            } => Detector::RunawayTree {
                threshold,
                window_seconds,
            },
            RawDetector::ForksPerSec {
                threshold,
                duration,
            } => Detector::ForksPerSec {
                threshold,
                duration,
            },
            RawDetector::ExecRate {
                regex,
                rate_per_min,
                median_lifetime,
            } => Detector::ExecRate {
                regex,
                rate_per_min,
                median_lifetime,
            },
            RawDetector::SubtreeCpuPct {
                threshold,
                duration,
            } => Detector::SubtreeCpuPct {
                threshold,
                duration,
            },
            RawDetector::SubtreeRssMb {
                threshold,
                duration,
            } => Detector::SubtreeRssMb {
                threshold,
                duration,
            },
            RawDetector::ZombieCount {
                threshold,
                duration,
            } => Detector::ZombieCount {
                threshold,
                duration,
            },
        };

        Ok(RuleConfig {
            name: value.name,
            severity,
            cooldown,
            detector,
        })
    }
}

struct RuleState {
    fork_events: VecDeque<Instant>,
    exec_events: VecDeque<Instant>,
    exec_start: HashMap<u32, Instant>,
    exec_completions: VecDeque<(Instant, Duration)>,
    forks_by_ppid: HashMap<u32, VecDeque<Instant>>,
    cpu_exceed: HashMap<String, Instant>,
    rss_exceed: HashMap<String, Instant>,
    active: HashMap<String, Instant>,
}

pub struct RuleEngine {
    rules: Vec<Rule>,
    state: Mutex<RuleState>,
    tx: broadcast::Sender<Alert>,
    alerts_file: String,
    journald: bool,
    host: String,
    fork_window_secs: u64,
    exec_window_secs: u64,
    completion_window_secs: u64,
    runaway_window_secs: u64,
    metrics: Arc<Metrics>,
    total_memory_bytes: Option<u64>,
}

impl RuleEngine {
    pub fn from_path(
        path: &str,
        alerts_file: String,
        journald: bool,
        metrics: Arc<Metrics>,
    ) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let hint = Path::new(path).extension().and_then(|ext| ext.to_str());
        let cfgs = parse_rules(&text, hint)?;

        let mut fork_window_secs = 0u64;
        let exec_window_secs = 60u64;
        let mut completion_window_secs = 60u64;
        let mut runaway_window_secs = 0u64;

        for cfg in &cfgs {
            match &cfg.detector {
                Detector::ForksPerSec { duration, .. } => {
                    fork_window_secs = fork_window_secs.max(*duration);
                }
                Detector::ForkBurst { window_seconds, .. } => {
                    fork_window_secs = fork_window_secs.max(*window_seconds);
                }
                Detector::RunawayTree { window_seconds, .. } => {
                    fork_window_secs = fork_window_secs.max(*window_seconds);
                    runaway_window_secs = runaway_window_secs.max(*window_seconds);
                }
                Detector::ShortJobFlood { window_seconds, .. } => {
                    completion_window_secs = completion_window_secs.max(*window_seconds);
                }
                Detector::ExecRate { .. } => {
                    completion_window_secs = completion_window_secs.max(60);
                }
                _ => {}
            }
        }

        if fork_window_secs == 0 {
            fork_window_secs = 5;
        }
        if runaway_window_secs == 0 {
            runaway_window_secs = fork_window_secs;
        }
        if completion_window_secs == 0 {
            completion_window_secs = 60;
        }

        let rules = cfgs.into_iter().map(|cfg| Rule { cfg }).collect();
        let (tx, _rx) = broadcast::channel(128);
        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into());
        let mut sys = System::new_all();
        sys.refresh_memory();
        let total_memory_bytes = match sys.total_memory() {
            0 => None,
            kb => Some(kb.saturating_mul(1024)),
        };
        Ok(Self {
            rules,
            state: Mutex::new(RuleState {
                fork_events: VecDeque::new(),
                exec_events: VecDeque::new(),
                exec_start: HashMap::new(),
                exec_completions: VecDeque::new(),
                forks_by_ppid: HashMap::new(),
                cpu_exceed: HashMap::new(),
                rss_exceed: HashMap::new(),
                active: HashMap::new(),
            }),
            tx,
            alerts_file,
            journald,
            host,
            fork_window_secs,
            exec_window_secs,
            completion_window_secs,
            runaway_window_secs,
            metrics,
            total_memory_bytes,
        })
    }

    pub fn broadcaster(&self) -> broadcast::Sender<Alert> {
        self.tx.clone()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    async fn emit_alert(&self, rule: &RuleConfig, message: String) {
        let key = format!("{}:{}", self.host, rule.name);
        let mut state = self.state.lock().await;
        let now = Instant::now();
        if let Some(until) = state.active.get(&key)
            && now <= *until
        {
            return;
        }
        let cooldown = if rule.cooldown == 0 {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(rule.cooldown)
        };
        state.active.insert(key.clone(), now + cooldown);
        drop(state);

        let alert = Alert {
            rule: rule.name.clone(),
            severity: rule.severity.clone(),
            message,
            host: self.host.clone(),
        };

        log::info!(
            "[rules] emitting alert rule={} severity={} message={}",
            alert.rule,
            alert.severity.as_str(),
            alert.message
        );

        if self.journald {
            let _ = std::process::Command::new("logger")
                .arg(format!("linnix: {} - {}", alert.rule, alert.message))
                .status();
        }

        if let Ok(line) = serde_json::to_string(&alert) {
            if let Some(dir) = std::path::Path::new(&self.alerts_file).parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Ok(mut f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.alerts_file)
            {
                let _ = writeln!(f, "{line}");
            }
        }

        let _ = self.tx.send(alert);
        self.metrics.inc_alerts_emitted();
    }
}

enum RuleFormat {
    Toml,
    Yaml,
}

impl RuleFormat {
    fn as_str(&self) -> &'static str {
        match self {
            RuleFormat::Toml => "toml",
            RuleFormat::Yaml => "yaml",
        }
    }
}

fn parse_rules(text: &str, hint: Option<&str>) -> anyhow::Result<Vec<RuleConfig>> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }

    let preferred = match hint.map(|h| h.to_ascii_lowercase()) {
        Some(ref h) if matches!(h.as_str(), "yaml" | "yml") => {
            vec![RuleFormat::Yaml, RuleFormat::Toml]
        }
        Some(ref h) if h == "toml" => vec![RuleFormat::Toml, RuleFormat::Yaml],
        _ => vec![RuleFormat::Toml, RuleFormat::Yaml],
    };

    let mut errors: Vec<(RuleFormat, anyhow::Error)> = Vec::new();

    for format in preferred {
        match parse_rules_with_format(text, &format) {
            Ok(cfgs) => return Ok(cfgs),
            Err(err) => errors.push((format, err)),
        }
    }

    let joined = errors
        .into_iter()
        .map(|(fmt, err)| format!("{}: {}", fmt.as_str(), err))
        .collect::<Vec<_>>()
        .join("; ");
    Err(anyhow!("failed to parse rules: {joined}"))
}

fn parse_rules_with_format(text: &str, format: &RuleFormat) -> anyhow::Result<Vec<RuleConfig>> {
    let raw = match format {
        RuleFormat::Toml => {
            parse_rules_from_toml(text).with_context(|| "failed to parse rules file as TOML")?
        }
        RuleFormat::Yaml => {
            parse_rules_from_yaml(text).with_context(|| "failed to parse rules file as YAML")?
        }
    };
    raw.into_iter().map(RuleConfig::try_from).collect()
}

fn parse_rules_from_yaml(text: &str) -> Result<Vec<RawRule>, serde_yaml::Error> {
    serde_yaml::from_str(text)
}

fn parse_rules_from_toml(text: &str) -> Result<Vec<RawRule>, toml::de::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RuleDoc {
        Wrapper { rules: Vec<RawRule> },
        Array(Vec<RawRule>),
    }

    let doc: RuleDoc = toml::from_str(text)?;
    Ok(match doc {
        RuleDoc::Wrapper { rules } => rules,
        RuleDoc::Array(rules) => rules,
    })
}

fn trim_instant_queue(queue: &mut VecDeque<Instant>, keep_for: Duration, now: Instant) {
    while let Some(&front) = queue.front() {
        if now.duration_since(front) > keep_for {
            queue.pop_front();
        } else {
            break;
        }
    }
}

fn trim_completion_queue(
    queue: &mut VecDeque<(Instant, Duration)>,
    keep_for: Duration,
    now: Instant,
) {
    while let Some(&(ts, _)) = queue.front() {
        if now.duration_since(ts) > keep_for {
            queue.pop_front();
        } else {
            break;
        }
    }
}

fn count_recent(queue: &VecDeque<Instant>, window: Duration, now: Instant) -> usize {
    queue
        .iter()
        .rev()
        .take_while(|&&ts| now.duration_since(ts) <= window)
        .count()
}

#[async_trait]
impl Handler for RuleEngine {
    fn name(&self) -> &'static str {
        "rules"
    }

    async fn on_event(&self, event: &ProcessEvent) {
        use linnix_ai_ebpf_common::EventType;
        let now = Instant::now();
        let fork_keep = Duration::from_secs(self.fork_window_secs.max(1));
        let exec_keep = Duration::from_secs(self.exec_window_secs.max(1));
        let completion_keep = Duration::from_secs(self.completion_window_secs.max(1));
        let runaway_keep = Duration::from_secs(self.runaway_window_secs.max(1));

        let mut state = self.state.lock().await;

        match event.event_type {
            x if x == EventType::Fork as u32 => {
                state.fork_events.push_back(now);
                trim_instant_queue(&mut state.fork_events, fork_keep, now);

                if self.runaway_window_secs > 0 {
                    let mut remove_entry = false;
                    {
                        let queue = state
                            .forks_by_ppid
                            .entry(event.ppid)
                            .or_insert_with(VecDeque::new);
                        queue.push_back(now);
                        trim_instant_queue(queue, runaway_keep, now);
                        if queue.is_empty() {
                            remove_entry = true;
                        }
                    }
                    if remove_entry {
                        state.forks_by_ppid.remove(&event.ppid);
                    }
                }
            }
            x if x == EventType::Exec as u32 => {
                state.exec_events.push_back(now);
                trim_instant_queue(&mut state.exec_events, exec_keep, now);
                state.exec_start.insert(event.pid, now);
            }
            x if x == EventType::Exit as u32 => {
                if let Some(start) = state.exec_start.remove(&event.pid) {
                    let lifetime = now.saturating_duration_since(start);
                    state.exec_completions.push_back((now, lifetime));
                    trim_completion_queue(&mut state.exec_completions, completion_keep, now);
                }
            }
            _ => {}
        }

        let is_fork_event = event.event_type == EventType::Fork as u32;
        let is_exec_event = event.event_type == EventType::Exec as u32;
        let is_exit_event = event.event_type == EventType::Exit as u32;

        for rule in &self.rules {
            match &rule.cfg.detector {
                Detector::ForksPerSec {
                    threshold,
                    duration,
                } => {
                    if is_fork_event {
                        let duration_secs = *duration;
                        let window = Duration::from_secs(duration_secs);
                        let count = count_recent(&state.fork_events, window, now) as u64;
                        let target = threshold.saturating_mul(duration_secs);
                        if log::log_enabled!(log::Level::Debug) && count > 0 {
                            let rate = if duration_secs > 0 {
                                count as f32 / duration_secs as f32
                            } else {
                                0.0
                            };
                            log::debug!(
                                "[rules] detector=forks_per_sec rule={} count={} target={} window={}s rate_per_sec={:.2} pid={} ppid={}",
                                rule.cfg.name,
                                count,
                                target.max(*threshold),
                                duration_secs,
                                rate,
                                event.pid,
                                event.ppid
                            );
                        }
                        if count >= target.max(*threshold) {
                            drop(state);
                            self.emit_alert(
                                &rule.cfg,
                                format!("fork rate exceeded {} per second", threshold),
                            )
                            .await;
                            state = self.state.lock().await;
                        }
                    }
                }
                Detector::ForkBurst {
                    threshold,
                    window_seconds,
                } => {
                    if is_fork_event {
                        let window_secs = *window_seconds;
                        let window = Duration::from_secs(window_secs);
                        let count = count_recent(&state.fork_events, window, now) as u64;
                        if log::log_enabled!(log::Level::Debug) && count > 0 {
                            log::debug!(
                                "[rules] detector=fork_burst rule={} count={} threshold={} window={}s pid={} ppid={}",
                                rule.cfg.name,
                                count,
                                threshold,
                                window_secs,
                                event.pid,
                                event.ppid
                            );
                        }
                        if count >= *threshold {
                            drop(state);
                            self.emit_alert(
                                &rule.cfg,
                                format!("fork burst: {} forks in {}s", count, window_seconds),
                            )
                            .await;
                            state = self.state.lock().await;
                        }
                    }
                }
                Detector::ExecRate {
                    rate_per_min,
                    median_lifetime,
                    ..
                } => {
                    if is_exec_event && state.exec_events.len() as u64 >= *rate_per_min {
                        let mut durations: Vec<u64> = state
                            .exec_completions
                            .iter()
                            .rev()
                            .take_while(|(ts, _)| {
                                now.duration_since(*ts) <= Duration::from_secs(60)
                            })
                            .map(|(_, lifetime)| lifetime.as_secs())
                            .collect();
                        if !durations.is_empty() {
                            durations.sort_unstable();
                            let median = durations[durations.len() / 2];
                            if median <= *median_lifetime {
                                drop(state);
                                self.emit_alert(
                                    &rule.cfg,
                                    format!("exec rate exceeded {rate_per_min}/min"),
                                )
                                .await;
                                state = self.state.lock().await;
                                state.exec_events.clear();
                                state.exec_completions.clear();
                            }
                        }
                    }
                }
                Detector::ShortJobFlood {
                    threshold,
                    window_seconds,
                    max_exec_duration_ms,
                } => {
                    if is_exit_event {
                        let window_secs = *window_seconds;
                        let window = Duration::from_secs(window_secs);
                        let max_duration = Duration::from_millis(*max_exec_duration_ms);
                        let mut count = 0u64;
                        for (ts, lifetime) in state.exec_completions.iter().rev() {
                            if now.duration_since(*ts) > window {
                                break;
                            }
                            if *lifetime <= max_duration {
                                count += 1;
                                if count >= *threshold {
                                    drop(state);
                                    self.emit_alert(
                                        &rule.cfg,
                                        format!(
                                            "{} short-lived execs (<= {}ms) in {}s",
                                            threshold, max_exec_duration_ms, window_seconds
                                        ),
                                    )
                                    .await;
                                    state = self.state.lock().await;
                                    break;
                                }
                            }
                        }
                        if log::log_enabled!(log::Level::Debug) && count > 0 {
                            log::debug!(
                                "[rules] detector=short_job_flood rule={} count={} threshold={} window={}s max_exec_ms={} pid={}",
                                rule.cfg.name,
                                count,
                                threshold,
                                window_secs,
                                max_exec_duration_ms,
                                event.pid
                            );
                        }
                    }
                }
                Detector::RunawayTree {
                    threshold,
                    window_seconds,
                } => {
                    if is_fork_event && let Some(queue) = state.forks_by_ppid.get(&event.ppid) {
                        let window_secs = *window_seconds;
                        let window = Duration::from_secs(window_secs);
                        let count = queue
                            .iter()
                            .rev()
                            .take_while(|ts| now.duration_since(**ts) <= window)
                            .count() as u64;
                        if log::log_enabled!(log::Level::Debug) && count > 0 {
                            log::debug!(
                                "[rules] detector=runaway_tree rule={} ppid={} count={} threshold={} window={}s",
                                rule.cfg.name,
                                event.ppid,
                                count,
                                threshold,
                                window_secs
                            );
                        }
                        if count >= *threshold {
                            drop(state);
                            self.emit_alert(
                                &rule.cfg,
                                format!(
                                    "ppid {} spawned {} forks in {}s",
                                    event.ppid, count, window_seconds
                                ),
                            )
                            .await;
                            state = self.state.lock().await;
                        }
                    }
                }
                Detector::SubtreeCpuPct {
                    threshold,
                    duration,
                } => {
                    if let Some(cpu) = event.cpu_percent() {
                        if log::log_enabled!(log::Level::Debug) {
                            log::debug!(
                                "[rules] detector=subtree_cpu rule={} cpu={:.2}% threshold={} duration={}s pid={}",
                                rule.cfg.name,
                                cpu,
                                threshold,
                                duration,
                                event.pid
                            );
                        }
                        if cpu > *threshold {
                            let entry =
                                state.cpu_exceed.entry(rule.cfg.name.clone()).or_insert(now);
                            if now.duration_since(*entry) > Duration::from_secs(*duration) {
                                state.cpu_exceed.remove(&rule.cfg.name);
                                drop(state);
                                self.emit_alert(
                                    &rule.cfg,
                                    format!("cpu pct {threshold} over {duration}s"),
                                )
                                .await;
                                state = self.state.lock().await;
                            }
                        } else {
                            state.cpu_exceed.remove(&rule.cfg.name);
                        }
                    }
                }
                Detector::SubtreeRssMb {
                    threshold,
                    duration,
                } => {
                    if let Some(mem_pct) = event.mem_percent() {
                        let used_mb = if let Some(total_bytes) = self.total_memory_bytes {
                            let used_bytes = (mem_pct as f64 / 100.0) * total_bytes as f64;
                            let mb = used_bytes / (1024.0 * 1024.0);
                            mb.clamp(0.0, u64::MAX as f64).round() as u64
                        } else {
                            mem_pct.round() as u64
                        };
                        if log::log_enabled!(log::Level::Debug) {
                            log::debug!(
                                "[rules] detector=subtree_rss rule={} mem_pct={:.2}% approx_mb={} threshold={} duration={}s pid={}",
                                rule.cfg.name,
                                mem_pct,
                                used_mb,
                                threshold,
                                duration,
                                event.pid
                            );
                        }
                        if used_mb > *threshold {
                            let entry =
                                state.rss_exceed.entry(rule.cfg.name.clone()).or_insert(now);
                            if now.duration_since(*entry) > Duration::from_secs(*duration) {
                                state.rss_exceed.remove(&rule.cfg.name);
                                drop(state);
                                self.emit_alert(
                                    &rule.cfg,
                                    format!("rss mb {threshold} over {duration}s"),
                                )
                                .await;
                                state = self.state.lock().await;
                            }
                        } else {
                            state.rss_exceed.remove(&rule.cfg.name);
                        }
                    }
                }
                Detector::ZombieCount { .. } => {}
            }
        }
    }

    async fn on_snapshot(&self, _snapshot: &SystemSnapshot) {
        // placeholder for detectors needing snapshots
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PERCENT_MILLI_UNKNOWN;
    use tokio::time::{self, Duration};

    fn test_engine(cooldown: u64) -> RuleEngine {
        let cfg = RuleConfig {
            name: "test".into(),
            severity: Severity::Low,
            cooldown,
            detector: Detector::ForksPerSec {
                threshold: 1,
                duration: 1,
            },
        };
        let (tx, _rx) = broadcast::channel(16);
        RuleEngine {
            rules: vec![Rule { cfg }],
            state: Mutex::new(RuleState {
                fork_events: VecDeque::new(),
                exec_events: VecDeque::new(),
                exec_start: HashMap::new(),
                exec_completions: VecDeque::new(),
                forks_by_ppid: HashMap::new(),
                cpu_exceed: HashMap::new(),
                rss_exceed: HashMap::new(),
                active: HashMap::new(),
            }),
            tx,
            alerts_file: "/dev/null".into(),
            journald: false,
            host: "test-host".into(),
            fork_window_secs: 1,
            exec_window_secs: 60,
            completion_window_secs: 60,
            runaway_window_secs: 1,
            metrics: Arc::new(Metrics::new()),
            total_memory_bytes: Some(16 * 1024 * 1024 * 1024),
        }
    }

    #[tokio::test]
    async fn cooldown_suppresses_alerts() {
        time::pause();
        let engine = test_engine(60);
        let mut rx = engine.tx.subscribe();
        let base = ProcessEventWire {
            pid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            event_type: linnix_ai_ebpf_common::EventType::Fork as u32,
            ts_ns: 0,
            seq: 0,
            comm: [0; 16],
            exit_time_ns: 0,
            cpu_pct_milli: PERCENT_MILLI_UNKNOWN,
            mem_pct_milli: PERCENT_MILLI_UNKNOWN,
            data: 0,
            data2: 0,
            aux: 0,
            aux2: 0,
        };
        let event = ProcessEvent::new(base);
        engine.on_event(&event).await;
        engine.on_event(&event).await;
        let _first = rx.recv().await.unwrap();
        assert!(
            rx.try_recv().is_err(),
            "second alert suppressed by cooldown"
        );
        time::advance(Duration::from_secs(61)).await;
        engine.on_event(&event).await;
        assert!(rx.recv().await.is_ok(), "alert after cooldown");
    }

    #[tokio::test]
    async fn dedupe_prevents_duplicates() {
        let engine = test_engine(0);
        let mut rx = engine.tx.subscribe();
        let base = ProcessEventWire {
            pid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            event_type: linnix_ai_ebpf_common::EventType::Fork as u32,
            ts_ns: 0,
            seq: 0,
            comm: [0; 16],
            exit_time_ns: 0,
            cpu_pct_milli: PERCENT_MILLI_UNKNOWN,
            mem_pct_milli: PERCENT_MILLI_UNKNOWN,
            data: 0,
            data2: 0,
            aux: 0,
            aux2: 0,
        };
        let event = ProcessEvent::new(base);
        let f1 = engine.on_event(&event);
        let f2 = engine.on_event(&event);
        futures_util::join!(f1, f2);
        let _first = rx.recv().await.unwrap();
        assert!(rx.try_recv().is_err(), "duplicate alert suppressed");
    }

    #[test]
    fn parses_rules_from_yaml_and_toml() {
        let yaml = r#"- name: fork_storm
  detector: forks_per_sec
  threshold: 5
  duration: 1
  severity: high
  cooldown: 10
- name: cpu_spin
  detector: subtree_cpu_pct
  threshold: 90.0
  duration: 15
  severity: medium
"#;
        let toml = r#"
[[rules]]
name = "fork_storm"
detector = "forks_per_sec"
threshold = 5
duration = 1
severity = "high"
cooldown = 10

[[rules]]
name = "cpu_spin"
detector = "subtree_cpu_pct"
threshold = 90.0
duration = 15
severity = "medium"
"#;

        let yaml_rules = parse_rules(yaml, Some("yaml")).expect("yaml parses");
        let toml_rules = parse_rules(toml, Some("toml")).expect("toml parses");
        assert_eq!(yaml_rules.len(), 2, "yaml rule count");
        assert_eq!(toml_rules.len(), 2, "toml rule count");
        assert_eq!(yaml_rules[0].name, "fork_storm");
        assert_eq!(toml_rules[0].name, "fork_storm");
        assert_eq!(yaml_rules[1].name, "cpu_spin");
        assert_eq!(toml_rules[1].name, "cpu_spin");
    }
}
