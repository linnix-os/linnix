//! The stall-attribution emit seam.
//!
//! `PsiMonitor` detects that a pod is stalling and works out which neighbours
//! are to blame. Everything downstream of that conclusion funnels through
//! [`AttributionSink`]: a structured JSON log line for log-based tooling, an
//! [`Alert`] on the usual broadcast channel, and counters that
//! `/metrics/prometheus` renders.
//!
//! Attribution is a *split* of one victim's stall across several offenders, so
//! each offender is credited with its share of the stall rather than the whole
//! thing. Emitting the victim's total against every offender would make the
//! counters sum to several times the stall that actually happened.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use log::{info, warn};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::alerts::{Alert, Severity};
use crate::collectors::psi::BlameAttribution;

/// Minimum stall attributed to a *single* offender before we emit a JSON event
/// or an alert for it. Distinct from the threshold that decides whether the
/// victim is stalling at all: one 500ms stall split across six neighbours is
/// not six noisy neighbours.
pub const DEFAULT_ATTRIBUTED_STALL_THRESHOLD_US: u64 = 100_000; // 100ms

/// Upper bound on distinct series held per counter family. Generous on purpose:
/// eviction breaks `rate()` continuity for the evicted series, so the cap is a
/// backstop against unbounded growth, not a sampling strategy.
pub const DEFAULT_MAX_SERIES: usize = 4096;

/// Why an offender was blamed, derived from whichever signal dominated its
/// blame score. Surfaced in the JSON event so logs can be faceted by cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlameReason {
    HighCpuContention,
    ForkStorm,
    ShortJobChurn,
}

impl BlameReason {
    /// Picks the dominant factor using the same normalisation the blame score
    /// itself uses, so the reason always names the term that contributed most.
    pub fn classify(cpu_share: f64, fork_count: u64, short_job_count: u64) -> Self {
        let fork_score = (fork_count as f64 / 100.0).min(1.0);
        let short_job_score = (short_job_count as f64 / 50.0).min(1.0);

        if cpu_share >= fork_score && cpu_share >= short_job_score {
            BlameReason::HighCpuContention
        } else if fork_score >= short_job_score {
            BlameReason::ForkStorm
        } else {
            BlameReason::ShortJobChurn
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            BlameReason::HighCpuContention => "high_cpu_contention",
            BlameReason::ForkStorm => "fork_storm",
            BlameReason::ShortJobChurn => "short_job_churn",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VictimRef {
    pub pod: String,
    pub namespace: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffenderRef {
    pub pod: String,
    pub namespace: String,
    pub reason: BlameReason,
}

/// One machine-readable stall attribution, serialised as a single JSON line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttributionEvent {
    pub event_type: String,
    pub severity: String,
    /// Stall attributed to *this* offender, in milliseconds.
    pub stall_ms: u64,
    /// Same figure at microsecond resolution, which is how PSI reports it.
    pub attributed_stall_us: u64,
    /// The victim's total stall for this window, across all offenders.
    pub victim_stall_us: u64,
    pub blame_score: f64,
    pub timestamp: u64,
    pub victim: VictimRef,
    pub offender: OffenderRef,
}

impl AttributionEvent {
    pub const EVENT_TYPE: &'static str = "linnix.stall_attribution";

    fn from_attribution(attr: &BlameAttribution) -> Self {
        Self {
            event_type: Self::EVENT_TYPE.to_string(),
            severity: "warn".to_string(),
            stall_ms: attr.attributed_stall_us / 1_000,
            attributed_stall_us: attr.attributed_stall_us,
            victim_stall_us: attr.stall_us,
            blame_score: attr.blame_score,
            timestamp: attr.timestamp,
            victim: VictimRef {
                pod: attr.victim_pod.clone(),
                namespace: attr.victim_namespace.clone(),
            },
            offender: OffenderRef {
                pod: attr.offender_pod.clone(),
                namespace: attr.offender_namespace.clone(),
                reason: BlameReason::classify(
                    attr.cpu_share,
                    attr.fork_count,
                    attr.short_job_count,
                ),
            },
        }
    }

    fn alert_message(&self) -> String {
        format!(
            "{}/{} stalled {}ms attributed to {}/{} ({})",
            self.victim.namespace,
            self.victim.pod,
            self.stall_ms,
            self.offender.namespace,
            self.offender.pod,
            self.offender.reason.as_str()
        )
    }
}

/// A counter map with a hard series cap.
///
/// When the cap is hit the smallest counter is evicted, and its value is kept
/// aside so that if the same key shows up again it resumes rather than
/// restarting at zero — a restart reads as a counter reset to Prometheus and
/// silently loses the history. The carry map is capped the same way.
struct CappedCounters {
    values: HashMap<String, u64>,
    carry: HashMap<String, u64>,
    cap: usize,
}

impl CappedCounters {
    fn new(cap: usize) -> Self {
        Self {
            values: HashMap::new(),
            carry: HashMap::new(),
            cap: cap.max(1),
        }
    }

    /// Evicts the lowest-valued entry, parking its value in `carry`.
    fn evict_one(&mut self) -> Option<String> {
        let victim = self
            .values
            .iter()
            .min_by_key(|(_, v)| **v)
            .map(|(k, v)| (k.clone(), *v))?;

        self.values.remove(&victim.0);

        if self.carry.len() >= self.cap
            && let Some(drop_key) = self
                .carry
                .iter()
                .min_by_key(|(_, v)| **v)
                .map(|(k, _)| k.clone())
        {
            self.carry.remove(&drop_key);
        }
        self.carry.insert(victim.0.clone(), victim.1);

        Some(victim.0)
    }

    /// Returns true if an eviction was needed to make room.
    fn ensure_room_for(&mut self, key: &str) -> bool {
        if self.values.contains_key(key) || self.values.len() < self.cap {
            return false;
        }
        self.evict_one().is_some()
    }

    fn add(&mut self, key: &str, delta: u64) -> bool {
        let evicted = self.ensure_room_for(key);
        if let Some(existing) = self.values.get_mut(key) {
            *existing = existing.saturating_add(delta);
        } else {
            let resumed = self.carry.remove(key).unwrap_or(0);
            self.values.insert(key.to_string(), resumed + delta);
        }
        evicted
    }

    fn len(&self) -> usize {
        self.values.len()
    }
}

/// Last cumulative PSI reading seen for each container cgroup, so that the
/// per-pod counter can be advanced by deltas.
///
/// Bounded like the counter maps. Losing an entry costs one over-count when
/// that container is next seen — the same cost as a genuine cgroup replacement,
/// which is the conservative direction.
struct LastSeen {
    values: HashMap<String, u64>,
    cap: usize,
}

impl LastSeen {
    fn new(cap: usize) -> Self {
        Self {
            values: HashMap::new(),
            cap: cap.max(1),
        }
    }

    /// Returns how much this container's stall counter advanced since the last
    /// reading. A counter that moved backwards means the cgroup was replaced
    /// (container restart), in which case the whole new value is the advance.
    fn advance(&mut self, container_id: &str, cumulative: u64) -> u64 {
        let delta = match self.values.get(container_id) {
            Some(&previous) if cumulative >= previous => cumulative - previous,
            Some(_) => cumulative,
            None => cumulative,
        };

        if !self.values.contains_key(container_id)
            && self.values.len() >= self.cap
            && let Some(drop_key) = self
                .values
                .iter()
                .min_by_key(|(_, v)| **v)
                .map(|(k, _)| k.clone())
        {
            self.values.remove(&drop_key);
        }
        self.values.insert(container_id.to_string(), cumulative);

        delta
    }
}

/// Per-pod and per-offender/victim-pair counters backing the "noisy neighbour"
/// metrics. Keys are pre-rendered Prometheus label sets so rendering a scrape
/// is a string concatenation and never touches the incident database.
pub struct BlameMetrics {
    /// `linnix_pod_psi_pressure_total` — PSI stall accumulated per victim pod.
    victims: Mutex<CappedCounters>,
    /// Per-container cursors feeding `victims`. A pod's cgroups are per
    /// *container instance*: a sidecar means several, and a restart replaces
    /// one with a counter that starts back at zero. Both are folded into a
    /// single per-pod series by accumulating deltas here rather than exporting
    /// the kernel's figure directly.
    last_seen: Mutex<LastSeen>,
    /// `linnix_stall_induced_seconds_total` — stall microseconds attributed to
    /// an (offender, victim) pair.
    pairs: Mutex<CappedCounters>,
    evictions: AtomicU64,
    node: String,
}

impl BlameMetrics {
    pub fn new(node: impl Into<String>) -> Self {
        Self::with_cap(node, DEFAULT_MAX_SERIES)
    }

    pub fn with_cap(node: impl Into<String>, cap: usize) -> Self {
        Self {
            victims: Mutex::new(CappedCounters::new(cap)),
            last_seen: Mutex::new(LastSeen::new(cap)),
            pairs: Mutex::new(CappedCounters::new(cap)),
            evictions: AtomicU64::new(0),
            node: node.into(),
        }
    }

    fn note_eviction(&self, family: &str) {
        let total = self.evictions.fetch_add(1, Ordering::Relaxed) + 1;
        // Loud on the first eviction, then every 1000th: the cap being reached
        // at all usually means it is set wrong for this cluster.
        if total == 1 || total.is_multiple_of(1000) {
            warn!(
                "[attribution] {} series cap reached, evicting lowest counter \
                 (total evictions: {}); rate() continuity is lost for evicted series",
                family, total
            );
        }
    }

    /// Records one container cgroup's cumulative PSI stall, advancing the
    /// owning pod's counter by however much it moved since the last reading.
    pub fn record_victim_pressure(
        &self,
        namespace: &str,
        pod: &str,
        container_id: &str,
        some_total_us: u64,
    ) {
        let delta = match self.last_seen.lock() {
            Ok(mut seen) => seen.advance(container_id, some_total_us),
            Err(_) => return,
        };
        if delta == 0 {
            return;
        }

        let key = format!(
            "namespace=\"{}\",pod=\"{}\",node=\"{}\"",
            escape_label(namespace),
            escape_label(pod),
            escape_label(&self.node)
        );
        let evicted = self
            .victims
            .lock()
            .map(|mut m| m.add(&key, delta))
            .unwrap_or(false);
        if evicted {
            self.note_eviction("linnix_pod_psi_pressure_total");
        }
    }

    /// Credits an offender with its share of a victim's stall.
    pub fn record_attribution(&self, attr: &BlameAttribution) {
        if attr.attributed_stall_us == 0 {
            return;
        }
        let key = format!(
            "offender_pod=\"{}\",offender_namespace=\"{}\",victim_pod=\"{}\",victim_namespace=\"{}\"",
            escape_label(&attr.offender_pod),
            escape_label(&attr.offender_namespace),
            escape_label(&attr.victim_pod),
            escape_label(&attr.victim_namespace)
        );
        let evicted = self
            .pairs
            .lock()
            .map(|mut m| m.add(&key, attr.attributed_stall_us))
            .unwrap_or(false);
        if evicted {
            self.note_eviction("linnix_stall_induced_seconds_total");
        }
    }

    /// Appends both metric families in Prometheus text exposition format.
    pub fn render_prometheus(&self, body: &mut String) {
        let _ = writeln!(
            body,
            "# HELP linnix_pod_psi_pressure_total Cumulative CPU pressure stall time per pod, in microseconds."
        );
        let _ = writeln!(body, "# TYPE linnix_pod_psi_pressure_total counter");
        if let Ok(victims) = self.victims.lock() {
            for (labels, value) in victims.values.iter() {
                let _ = writeln!(
                    body,
                    "linnix_pod_psi_pressure_total{{{}}} {}",
                    labels, value
                );
            }
        }

        let _ = writeln!(
            body,
            "# HELP linnix_stall_induced_seconds_total Stall time attributed to an offending pod, in seconds."
        );
        let _ = writeln!(body, "# TYPE linnix_stall_induced_seconds_total counter");
        if let Ok(pairs) = self.pairs.lock() {
            for (labels, value) in pairs.values.iter() {
                let _ = writeln!(
                    body,
                    "linnix_stall_induced_seconds_total{{{}}} {:.6}",
                    labels,
                    *value as f64 / 1_000_000.0
                );
            }
        }

        let _ = writeln!(
            body,
            "# HELP linnix_blame_series_evicted_total Blame series dropped because the series cap was reached."
        );
        let _ = writeln!(body, "# TYPE linnix_blame_series_evicted_total counter");
        let _ = writeln!(
            body,
            "linnix_blame_series_evicted_total {}",
            self.evictions.load(Ordering::Relaxed)
        );
    }

    pub fn victim_series(&self) -> usize {
        self.victims.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn pair_series(&self) -> usize {
        self.pairs.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// The single point where a completed attribution fans out to logs, alerts and
/// metrics. Callers hand it the attributions for one stall event; it decides
/// what crosses the reporting threshold.
pub struct AttributionSink {
    metrics: std::sync::Arc<BlameMetrics>,
    alerts: Option<broadcast::Sender<Alert>>,
    host: String,
    threshold_us: u64,
}

impl AttributionSink {
    pub fn new(
        metrics: std::sync::Arc<BlameMetrics>,
        alerts: Option<broadcast::Sender<Alert>>,
        host: impl Into<String>,
    ) -> Self {
        Self {
            metrics,
            alerts,
            host: host.into(),
            threshold_us: DEFAULT_ATTRIBUTED_STALL_THRESHOLD_US,
        }
    }

    pub fn with_threshold_us(mut self, threshold_us: u64) -> Self {
        self.threshold_us = threshold_us;
        self
    }

    pub fn metrics(&self) -> &std::sync::Arc<BlameMetrics> {
        &self.metrics
    }

    /// Every attribution updates the counters; only those over the threshold
    /// produce a JSON line and an alert. Returns the events that were emitted
    /// so callers (and tests) can see exactly what a user would observe.
    pub fn emit(&self, attributions: &[BlameAttribution]) -> Vec<AttributionEvent> {
        let mut emitted = Vec::new();

        for attr in attributions {
            self.metrics.record_attribution(attr);

            if attr.attributed_stall_us < self.threshold_us {
                continue;
            }

            let event = AttributionEvent::from_attribution(attr);

            match serde_json::to_string(&event) {
                Ok(line) => info!("{}", line),
                Err(e) => warn!("[attribution] failed to serialize attribution event: {}", e),
            }

            if let Some(tx) = &self.alerts {
                let _ = tx.send(Alert {
                    rule: "stall_attribution".to_string(),
                    severity: Severity::Medium,
                    message: event.alert_message(),
                    host: self.host.clone(),
                });
            }

            emitted.push(event);
        }

        emitted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attribution(offender: &str, attributed_us: u64) -> BlameAttribution {
        BlameAttribution {
            victim_pod: "payment-api".to_string(),
            victim_namespace: "prod".to_string(),
            offender_pod: offender.to_string(),
            offender_namespace: "prod".to_string(),
            blame_score: 1.0,
            stall_us: 1_000_000,
            attributed_stall_us: attributed_us,
            timestamp: 1_700_000_000,
            cpu_share: 0.9,
            fork_count: 0,
            short_job_count: 0,
        }
    }

    #[test]
    fn blame_reason_picks_dominant_factor() {
        assert_eq!(
            BlameReason::classify(0.9, 10, 5),
            BlameReason::HighCpuContention
        );
        assert_eq!(BlameReason::classify(0.1, 200, 5), BlameReason::ForkStorm);
        assert_eq!(
            BlameReason::classify(0.1, 0, 100),
            BlameReason::ShortJobChurn
        );
    }

    #[test]
    fn counters_resume_after_eviction_instead_of_resetting() {
        let mut counters = CappedCounters::new(2);
        counters.add("a", 500);
        counters.add("b", 10);
        // "b" is the smallest, so adding "c" evicts it.
        assert!(counters.add("c", 300));
        assert_eq!(counters.len(), 2);
        assert!(!counters.values.contains_key("b"));

        // "b" comes back and resumes from where it left off rather than zero.
        counters.add("b", 5);
        assert_eq!(counters.values.get("b"), Some(&15));
    }

    #[test]
    fn a_replaced_cgroup_contributes_its_whole_counter() {
        let mut seen = LastSeen::new(8);
        assert_eq!(seen.advance("c1", 1_000), 1_000);
        assert_eq!(seen.advance("c1", 1_500), 500);
        // Container restarted: the kernel counter starts over, so the reading
        // is itself the advance rather than a negative delta.
        assert_eq!(seen.advance("c1", 200), 200);
    }

    #[test]
    fn label_values_are_escaped() {
        let metrics = BlameMetrics::new("node-1");
        metrics.record_victim_pressure("prod", "we\"ird\\pod", "container-1", 42);
        let mut body = String::new();
        metrics.render_prometheus(&mut body);
        assert!(body.contains(r#"pod="we\"ird\\pod""#), "body was: {}", body);
    }

    #[test]
    fn sink_counts_everything_but_only_reports_over_threshold() {
        let metrics = std::sync::Arc::new(BlameMetrics::new("node-1"));
        let sink = AttributionSink::new(metrics.clone(), None, "node-1");

        let emitted = sink.emit(&[attribution("loud", 250_000), attribution("quiet", 1_000)]);

        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].offender.pod, "loud");
        assert_eq!(emitted[0].stall_ms, 250);
        // Both still contribute to the counters.
        assert_eq!(metrics.pair_series(), 2);
    }
}
