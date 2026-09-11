//! Cloud export loop.
//!
//! One tick (every [`SEAL_INTERVAL_SECS`]) pulls new incidents from the
//! store in row-ID order behind a persisted watermark, converts them to
//! schema-v1 detection events (scrubbed of secrets and, by default, process
//! identity), adds heartbeats and degradation-state events, seals batches,
//! spools them durably, and drains the spool through the sender.
//!
//! Failure isolation: every fallible step logs and continues. The exporter
//! never panics, never blocks monitoring, and never touches the local API
//! path.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use log::{debug, error, info, warn};
use serde_json::Value;
use tokio::task::JoinHandle;

use crate::attribution::BlameMetrics;
use crate::incidents::{Incident, IncidentStore};

use super::identity::IdentityStore;
use super::model::{
    AgentStatus, AttributionQuality, DegradationStatePayload, DetailLevel, DetectionAction,
    DetectionPayload, Event, EventPayload, EventType, FallbackMode, HeartbeatPayload, Severity,
    TimeRange, Transport, detection_type_for, rfc3339,
};
use super::scrub::{ScrubPolicy, scrub_snapshot};
use super::seal::{BatchSealer, PushOutcome, SealContext, SealIdentity, SealedBatch};
use super::sender::{SendDecision, Sender, backoff_delay};
use super::spool::{Spool, SpoolPriority};
use super::{EXPORT_PULL_LIMIT, HEARTBEAT_INTERVAL_SECS, SEAL_INTERVAL_SECS};

/// Everything the exporter needs, with secrets already resolved from config
/// and environment. Deliberately has no `Debug` impl: it carries the token.
pub struct ExporterConfig {
    pub endpoint: String,
    pub token: String,
    pub tenant_id: String,
    pub cluster_id_override: Option<String>,
    pub node_id_override: Option<String>,
    pub export_process_identity: bool,
    pub state_dir: PathBuf,
    pub quality: QualitySnapshot,
}

/// Attribution-quality inputs captured at startup.
#[derive(Debug, Clone)]
pub struct QualitySnapshot {
    /// `"perf"` when kernel instrumentation is live; anything else means the
    /// userspace fallback.
    pub transport: String,
    pub btf_available: bool,
    /// `"measured"` / `"inferred"` / `"unavailable"` — echoed in
    /// degradation events.
    pub rss_probe: String,
}

impl QualitySnapshot {
    pub fn quality(&self) -> AttributionQuality {
        if self.transport == "perf" {
            AttributionQuality::Full
        } else {
            AttributionQuality::PsiOnly
        }
    }
}

/// Spawn the exporter on the current Tokio runtime. The task runs until the
/// process exits; initialization failures are logged and the task ends, so
/// cloud export can never take monitoring down with it.
pub fn spawn_exporter(
    config: ExporterConfig,
    store: Arc<IncidentStore>,
    blame: Arc<BlameMetrics>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        match Exporter::new(config, store, blame).await {
            Ok(exporter) => exporter.run().await,
            Err(e) => error!("[cloud] exporter failed to initialize ({e}); cloud export disabled"),
        }
    })
}

/// Build a batch sealer bound to the exporter's identity. The sealer needs
/// the identity fields at construction time for its exact prospective
/// envelope-size accounting — it must see the same strings that
/// [`SealContext`] will carry at seal time.
fn new_sealer(
    quality: AttributionQuality,
    tenant_id: &str,
    identity: &IdentityStore,
) -> BatchSealer {
    BatchSealer::new(
        quality,
        SealIdentity {
            tenant_id: tenant_id.to_string(),
            cluster_id: identity.cluster_id().to_string(),
            node_id: identity.node_id().to_string(),
            agent_instance_id: identity.agent_instance_id().to_string(),
        },
    )
}

pub struct Exporter {
    config: ExporterConfig,
    identity: IdentityStore,
    spool: Spool,
    sender: Sender,
    sealer: BatchSealer,
    /// Highest incident row ID converted into the in-memory sealer. Persisted
    /// to the identity file only once the batch holding those events is
    /// durably spooled, so a crash replays unsealed rows (the idempotency
    /// key makes the replay harmless downstream).
    pushed_watermark: i64,
    /// Lowest drop priority among the events currently buffered; a batch is
    /// spooled at its most important event's priority.
    pending_priority: SpoolPriority,
    store: Arc<IncidentStore>,
    blame: Arc<BlameMetrics>,
    start: Instant,
    state_since: String,
    last_heartbeat: Instant,
    consecutive_failures: u32,
    last_evictions: u64,
    /// Events deliberately dropped as individually oversized (the edge
    /// would quarantine an oversized batch, so one pathological snapshot
    /// must not wedge the pipeline). Counted in the heartbeat's dropped
    /// total; the watermark advances past them on purpose.
    oversize_dropped: u64,
    policy: ScrubPolicy,
    backoff: fn(u32) -> Duration,
}

impl Exporter {
    pub async fn new(
        config: ExporterConfig,
        store: Arc<IncidentStore>,
        blame: Arc<BlameMetrics>,
    ) -> Result<Self, String> {
        let identity = IdentityStore::load_or_create(
            &config.state_dir,
            config.cluster_id_override.as_deref(),
            config.node_id_override.as_deref(),
        )
        .map_err(|e| format!("identity: {e}"))?;
        let spool = Spool::open(&config.state_dir).map_err(|e| format!("spool: {e}"))?;
        let sender = Sender::new(config.endpoint.clone(), config.token.clone())
            .map_err(|e| format!("sender: {e}"))?;
        let quality = config.quality.quality();
        let policy = ScrubPolicy::from_opt_in(config.export_process_identity);
        let watermark = identity.export_watermark();
        let last_evictions = blame.evictions();
        let sealer = new_sealer(quality, &config.tenant_id, &identity);
        let mut exporter = Self {
            config,
            identity,
            spool,
            sender,
            sealer,
            pushed_watermark: watermark,
            pending_priority: SpoolPriority::Heartbeat,
            store,
            blame,
            start: Instant::now(),
            state_since: rfc3339(Utc::now().timestamp()),
            last_heartbeat: Instant::now() - Duration::from_secs(HEARTBEAT_INTERVAL_SECS),
            consecutive_failures: 0,
            last_evictions,
            oversize_dropped: 0,
            policy,
            backoff: backoff_delay,
        };
        // The first batch always opens with the current degradation state so
        // the edge learns the quality before the first heartbeat arrives.
        let degradation = exporter.degradation_event();
        exporter
            .push_event(degradation, SpoolPriority::DegradationState)
            .await;
        info!(
            "[cloud] exporter initialized (node {}, cluster {}, quality {:?})",
            exporter.identity.node_id(),
            exporter.identity.cluster_id(),
            quality
        );
        Ok(exporter)
    }

    /// One export iteration: pull, heartbeat, seal, drain.
    pub async fn tick(&mut self) {
        // Quality transitions seal the old batch immediately and open a new
        // one — a batch never mixes quality states (schema §2).
        let quality = self.config.quality.quality();
        if quality != self.sealer.quality() {
            self.seal_and_spool().await;
            self.sealer = new_sealer(quality, &self.config.tenant_id, &self.identity);
            let degradation = self.degradation_event();
            self.push_event(degradation, SpoolPriority::DegradationState)
                .await;
            info!("[cloud] attribution quality changed to {quality:?}; emitted degradation_state");
        }

        match self
            .store
            .export_batch(self.pushed_watermark, EXPORT_PULL_LIMIT)
            .await
        {
            Ok(incidents) => {
                for incident in &incidents {
                    let buffered = match self.detection_event(incident) {
                        Some(event) => self.push_event(event, SpoolPriority::Detection).await,
                        None => {
                            debug!(
                                "[cloud] skipping incident {:?} (unmapped type {:?})",
                                incident.id, incident.event_type
                            );
                            // Deliberate skip: don't re-pull it forever.
                            true
                        }
                    };
                    if !buffered {
                        // The batch is full and the spool is failing: stop
                        // the pull with the watermark behind this incident so
                        // it's retried next tick instead of being skipped.
                        warn!(
                            "[cloud] could not buffer incident {:?}; pausing pull until the spool recovers",
                            incident.id
                        );
                        break;
                    }
                    if let Some(id) = incident.id {
                        self.pushed_watermark = self.pushed_watermark.max(id);
                    }
                }
            }
            Err(e) => warn!("[cloud] incident pull failed: {e}; will retry next tick"),
        }

        if self.last_heartbeat.elapsed() >= Duration::from_secs(HEARTBEAT_INTERVAL_SECS)
            && let Some(heartbeat) = self.heartbeat_event()
        {
            self.push_event(heartbeat, SpoolPriority::Heartbeat).await;
            self.last_heartbeat = Instant::now();
        }

        if self.sealer.seal_due(Instant::now()) {
            self.seal_and_spool().await;
        }

        self.drain().await;
    }

    /// Run ticks forever on the seal cadence.
    pub async fn run(mut self) {
        let mut interval = tokio::time::interval(Duration::from_secs(SEAL_INTERVAL_SECS));
        loop {
            interval.tick().await;
            self.tick().await;
        }
    }

    /// Buffer an event, sealing the current batch first when the next
    /// event wouldn't fit. Returns `true` when the event was buffered or
    /// deliberately dropped (oversize); `false` when the batch is full and
    /// the spool is failing, in which case the caller must NOT advance the
    /// watermark past the event.
    async fn push_event(&mut self, event: Event, priority: SpoolPriority) -> bool {
        match self.sealer.try_push(event) {
            PushOutcome::Accepted => {
                self.pending_priority = self.pending_priority.min(priority);
                true
            }
            PushOutcome::BatchFull(event) => {
                // Mid-pull seal: make the full batch durable, then buffer
                // into a fresh batch and continue.
                let was_empty = self.sealer.is_empty();
                self.seal_and_spool().await;
                if !was_empty && !self.sealer.is_empty() {
                    // seal_and_spool failed and the buffer is still full.
                    return false;
                }
                match self.sealer.try_push(*event) {
                    PushOutcome::Accepted => {
                        self.pending_priority = self.pending_priority.min(priority);
                        true
                    }
                    // try_push filters oversize before the BatchFull check,
                    // so a drained sealer always accepts — this is a bug.
                    other => {
                        error!("[cloud] event rejected by fresh sealer ({other:?}); dropping");
                        self.oversize_dropped = self.oversize_dropped.saturating_add(1);
                        true
                    }
                }
            }
            PushOutcome::DroppedOversize { bytes } => {
                // Deliberate: the edge would quarantine an oversized batch,
                // so one pathological snapshot must not wedge the pipeline.
                // The watermark advances past it on purpose.
                warn!("[cloud] dropping oversized event ({bytes} bytes > batch cap)");
                self.oversize_dropped = self.oversize_dropped.saturating_add(1);
                true
            }
        }
    }

    /// Seal the buffered events and spool the batch. The buffer is cleared
    /// and the watermark advances only after the batch is durable on disk —
    /// a failed spool leaves the events buffered for retry, so a later
    /// successful batch can never advance the watermark past them.
    async fn seal_and_spool(&mut self) {
        if self.sealer.is_empty() {
            return;
        }
        let sequence = match self.identity.next_sequence() {
            Ok(s) => s,
            Err(e) => {
                error!("[cloud] cannot advance batch sequence: {e}; events stay buffered");
                return;
            }
        };
        let ctx = SealContext {
            tenant_id: &self.config.tenant_id,
            cluster_id: self.identity.cluster_id(),
            node_id: self.identity.node_id(),
            agent_instance_id: self.identity.agent_instance_id(),
            sequence,
        };
        let batch: Option<SealedBatch> = self.sealer.seal(&ctx);
        let Some(batch) = batch else { return };
        let priority = self.pending_priority;
        match self.spool.store(&batch, priority) {
            Ok(()) => {
                self.sealer.clear();
                if let Err(e) = self.identity.set_export_watermark(self.pushed_watermark) {
                    error!("[cloud] spooled batch {sequence} but failed to persist watermark: {e}");
                }
                self.pending_priority = SpoolPriority::Heartbeat;
            }
            Err(e) => error!(
                "[cloud] spool store failed for batch {sequence}: {e}; events stay buffered for retry"
            ),
        }
    }

    /// POST spooled batches oldest-first until acked, quarantined, or told
    /// to back off.
    async fn drain(&mut self) {
        while let Some(view) = self.spool.oldest() {
            let sequence = view.sequence();
            let bytes = match self.spool.read(sequence) {
                Ok(b) => b,
                Err(e) => {
                    warn!("[cloud] spooled batch {sequence} unreadable ({e}); dropping");
                    if let Err(remove_err) = self.spool.remove(sequence) {
                        error!(
                            "[cloud] failed to remove unreadable batch {sequence}: {remove_err}; \
                             will retry next drain"
                        );
                    }
                    continue;
                }
            };
            match self.sender.post_batch(&bytes).await {
                SendDecision::Acked => {
                    if let Err(e) = self.spool.remove(sequence) {
                        error!(
                            "[cloud] edge acked batch {sequence} but spool removal failed: {e}; \
                             will retry the ack next drain"
                        );
                    }
                    self.consecutive_failures = 0;
                }
                SendDecision::Quarantine { reason } => {
                    if let Err(e) = self.spool.quarantine(sequence, &reason) {
                        error!(
                            "[cloud] failed to quarantine refused batch {sequence}: {e}; \
                             will retry next drain"
                        );
                    }
                    self.consecutive_failures = 0;
                }
                SendDecision::Retry { retry_after } => {
                    self.consecutive_failures += 1;
                    let delay = retry_after.max((self.backoff)(self.consecutive_failures));
                    warn!(
                        "[cloud] edge unavailable; backing off for {delay:?} ({} consecutive)",
                        self.consecutive_failures
                    );
                    tokio::time::sleep(delay).await;
                    break;
                }
            }
        }
    }

    fn heartbeat_event(&mut self) -> Option<Event> {
        // The idempotency key must never repeat with a different body —
        // including across daemon restarts, where in-memory counters reset.
        // The counter is persisted in the identity file for exactly this.
        let n = match self.identity.next_heartbeat_seq() {
            Ok(n) => n,
            Err(e) => {
                error!(
                    "[cloud] cannot persist heartbeat sequence: {e}; skipping heartbeat this tick"
                );
                return None;
            }
        };
        let node_id = self.identity.node_id();
        let instance = self.identity.agent_instance_id();
        let quality = self.sealer.quality();
        let evicted_total = self.blame.evictions();
        let evicted_delta = evicted_total.saturating_sub(self.last_evictions);
        self.last_evictions = evicted_total;
        Some(Event {
            event_id: format!("hb-{node_id}-{n}"),
            event_idempotency_key: format!("e:hb:{instance}:{n}"),
            event_type: EventType::Heartbeat,
            occurred_at: rfc3339(Utc::now().timestamp()),
            detail_level: DetailLevel::Summary,
            payload: EventPayload::Heartbeat(HeartbeatPayload {
                interval_seconds: HEARTBEAT_INTERVAL_SECS as u32,
                uptime_seconds: self.start.elapsed().as_secs(),
                agent_status: match quality {
                    AttributionQuality::Full => AgentStatus::Healthy,
                    AttributionQuality::PsiOnly => AgentStatus::Degraded,
                },
                transport: match quality {
                    AttributionQuality::Full => Transport::Perf,
                    AttributionQuality::PsiOnly => Transport::Userspace,
                },
                ebpf_attached: quality == AttributionQuality::Full,
                btf_available: self.config.quality.btf_available,
                active_node: true,
                events_buffered: self.spool.pending_events(),
                events_dropped_total: self
                    .spool
                    .dropped_total()
                    .saturating_add(self.oversize_dropped),
                blame_series_active: self
                    .blame
                    .victim_series()
                    .saturating_add(self.blame.pair_series())
                    as u32,
                blame_series_evicted_total: evicted_total,
                blame_series_evicted_delta: evicted_delta,
            }),
        })
    }

    fn degradation_event(&self) -> Event {
        let node_id = self.identity.node_id();
        let now = Utc::now().timestamp();
        let quality = self.sealer.quality();
        let (reason_code, reason, lost) = match quality {
            AttributionQuality::Full => (
                "none",
                "all required kernel probes are attached",
                Vec::new(),
            ),
            AttributionQuality::PsiOnly => (
                "probe_attach_failed",
                "eBPF probes are not attached; running userspace-only — PSI signals remain available but process-level offender attribution is unavailable",
                vec![
                    "process_attribution".to_string(),
                    "offender_identity".to_string(),
                    "process_tree".to_string(),
                ],
            ),
        };
        Event {
            event_id: format!("deg-{node_id}-{}-{now}", quality.as_str()),
            event_idempotency_key: format!("e:deg:{node_id}:{}:{now}", quality.as_str()),
            event_type: EventType::DegradationState,
            occurred_at: rfc3339(now),
            detail_level: DetailLevel::Evidence,
            payload: EventPayload::DegradationState(DegradationStatePayload {
                attribution_quality: quality,
                ebpf_attached: quality == AttributionQuality::Full,
                fallback_mode: match quality {
                    AttributionQuality::Full => FallbackMode::None,
                    AttributionQuality::PsiOnly => FallbackMode::ProcPressureOnly,
                },
                transport: match quality {
                    AttributionQuality::Full => Transport::Perf,
                    AttributionQuality::PsiOnly => Transport::Userspace,
                },
                btf_available: self.config.quality.btf_available,
                rss_probe: self.config.quality.rss_probe.clone(),
                lost_capabilities: lost,
                reason_code: reason_code.to_string(),
                reason: reason.to_string(),
                state_since: self.state_since.clone(),
            }),
        }
    }

    fn detection_event(&self, incident: &Incident) -> Option<Event> {
        let id = incident.id?;
        let detection_type = detection_type_for(&incident.event_type)?.to_string();
        let occurred = incident.timestamp;
        let (window_start, window_end) = detection_window(incident);
        let details = scrub_snapshot(incident.system_snapshot.as_deref(), self.policy)
            .unwrap_or_else(|| Value::Object(Default::default()));
        let instance = self.identity.agent_instance_id();
        Some(Event {
            event_id: format!("incident-{id}"),
            event_idempotency_key: format!("e:det:{instance}:{id}"),
            event_type: EventType::Detection,
            occurred_at: rfc3339(occurred),
            detail_level: DetailLevel::Evidence,
            payload: EventPayload::Detection(DetectionPayload {
                detection_type: detection_type.clone(),
                severity: severity_for(incident),
                // v1: we don't resolve incidents to pod/namespace workload
                // identity; workload attribution is a follow-up.
                subject: None,
                window: TimeRange {
                    start: rfc3339(window_start),
                    end: rfc3339(window_end),
                },
                rule_name: detection_type,
                action: DetectionAction::Observe,
                details,
            }),
        })
    }
}

/// Detection window from the snapshot's `window_secs` when present,
/// otherwise a 60s window ending at the incident timestamp.
fn detection_window(incident: &Incident) -> (i64, i64) {
    let end = incident.timestamp;
    let secs = incident
        .system_snapshot
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.get("window_secs").and_then(Value::as_f64))
        .unwrap_or(60.0)
        .max(1.0) as i64;
    (end.saturating_sub(secs), end)
}

fn snapshot_string(incident: &Incident, key: &str) -> Option<String> {
    incident
        .system_snapshot
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.get(key).and_then(Value::as_str).map(str::to_string))
}

/// Critical verdicts stay critical; everything else ships as a warning.
fn severity_for(incident: &Incident) -> Severity {
    let critical = snapshot_string(incident, "verdict")
        .map(|v| v.contains("Critical"))
        .unwrap_or(false);
    if critical {
        Severity::Critical
    } else {
        Severity::Warning
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    fn sample_incident(id: Option<i64>, event_type: &str, snapshot: Option<&str>) -> Incident {
        Incident {
            id,
            timestamp: 1_700_000_000,
            event_type: event_type.to_string(),
            psi_cpu: 0.0,
            psi_memory: 0.0,
            cpu_percent: 0.0,
            load_avg: "0.10,0.10,0.10".to_string(),
            action: "alert".to_string(),
            target_pid: None,
            target_name: None,
            system_snapshot: snapshot.map(str::to_string),
            llm_analysis: None,
            llm_analyzed_at: None,
            investigation: None,
            recovery_time_ms: None,
            psi_after: None,
        }
    }

    struct TestHarness {
        exporter: Exporter,
        store: Arc<IncidentStore>,
        dir: tempfile::TempDir,
    }

    async fn build_exporter(
        state_dir: &std::path::Path,
        endpoint: &str,
        store: Arc<IncidentStore>,
    ) -> Exporter {
        let blame = Arc::new(BlameMetrics::new("test-node"));
        let config = ExporterConfig {
            endpoint: endpoint.to_string(),
            token: "test-token".to_string(),
            tenant_id: "tn_test".to_string(),
            cluster_id_override: Some("clu_test".to_string()),
            node_id_override: Some("node_test".to_string()),
            export_process_identity: false,
            state_dir: state_dir.to_path_buf(),
            quality: QualitySnapshot {
                transport: "userspace".to_string(),
                btf_available: false,
                rss_probe: "unavailable".to_string(),
            },
        };
        let mut exporter = Exporter::new(config, store, blame).await.unwrap();
        // Keep retry-path tests fast; production uses exponential backoff.
        exporter.backoff = |_| Duration::from_millis(1);
        exporter
    }

    async fn harness(endpoint: &str) -> TestHarness {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            IncidentStore::new(dir.path().join("incidents.db"))
                .await
                .unwrap(),
        );
        let exporter = build_exporter(dir.path(), endpoint, store.clone()).await;
        TestHarness {
            exporter,
            store,
            dir,
        }
    }

    fn gunzip(bytes: &[u8]) -> Vec<u8> {
        use std::io::Read as _;
        let mut dec = flate2::read::GzDecoder::new(bytes);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        out
    }

    #[tokio::test]
    async fn detection_event_maps_all_types_and_scrubs() {
        let h = harness("http://127.0.0.1:9/unused").await;
        let cases = [
            ("fork_storm", "fork_storm"),
            ("memory_leak", "memory_leak"),
            ("cpu_starvation", "cpu_starvation"),
            ("blkio_stall", "blkio_stall"),
            ("cgroup_pressure", "cgroup_pressure"),
            ("oom_kill", "oom_kill"),
            ("circuit_breaker", "circuit_breaker"),
            // Recorded circuit-breaker variants normalize instead of
            // skipping (their rows still advance the watermark).
            ("circuit_breaker_cpu", "circuit_breaker"),
            ("circuit_breaker_memory", "circuit_breaker"),
        ];
        for (local, cloud) in cases {
            let incident = sample_incident(
                Some(1),
                local,
                Some(
                    r#"{"verdict":"ForkStormCritical","window_secs":10,"comm":"evil","api_token":"sekrit"}"#,
                ),
            );
            let event = h.exporter.detection_event(&incident).expect("must map");
            let EventPayload::Detection(payload) = event.payload else {
                panic!("expected detection payload");
            };
            assert_eq!(payload.detection_type, cloud);
            assert_eq!(
                event.event_idempotency_key,
                format!("e:det:{}:1", h.exporter.identity.agent_instance_id())
            );
            assert_eq!(payload.window.start, rfc3339(1_700_000_000 - 10));
            assert_eq!(payload.window.end, rfc3339(1_700_000_000));
            // Privacy: process identity and secrets are scrubbed by default.
            assert!(payload.details.get("comm").is_none(), "{local}");
            assert!(payload.details.get("api_token").is_none(), "{local}");
            // Non-identity facts survive.
            assert_eq!(payload.details["verdict"], "ForkStormCritical");
        }
        // Unknown local types are skipped, never coerced into a wrong enum.
        let bogus = sample_incident(Some(2), "bogus_type", None);
        assert!(h.exporter.detection_event(&bogus).is_none());
    }

    #[tokio::test]
    async fn severity_and_window_defaults() {
        let h = harness("http://127.0.0.1:9/unused").await;
        let warning = sample_incident(Some(1), "memory_leak", Some(r#"{"verdict":"LeakWarning"}"#));
        let event = h.exporter.detection_event(&warning).unwrap();
        let EventPayload::Detection(payload) = event.payload else {
            panic!("expected detection payload");
        };
        assert_eq!(payload.severity, Severity::Warning);
        // No window_secs in the snapshot: 60s window ending at the incident.
        assert_eq!(payload.window.start, rfc3339(1_700_000_000 - 60));
        assert_eq!(payload.window.end, rfc3339(1_700_000_000));
        // Invalid snapshots export as empty details, never invented ones.
        let broken = sample_incident(Some(2), "memory_leak", Some("not json"));
        let event = h.exporter.detection_event(&broken).unwrap();
        let EventPayload::Detection(payload) = event.payload else {
            panic!("expected detection payload");
        };
        assert_eq!(payload.details, Value::Object(Default::default()));
    }

    #[tokio::test]
    async fn watermark_advances_only_after_durable_spool() {
        let h = harness("http://127.0.0.1:9/unused").await;
        h.store
            .insert(&sample_incident(None, "fork_storm", None))
            .await
            .unwrap();
        h.store
            .insert(&sample_incident(None, "oom_kill", None))
            .await
            .unwrap();
        let mut exporter = h.exporter;
        exporter.tick().await;
        // Pulled into the in-memory sealer but not yet sealed: the persisted
        // watermark is unchanged, so a crash here replays both rows.
        assert_eq!(exporter.identity.export_watermark(), 0);
        assert_eq!(exporter.pushed_watermark, 2);
        exporter.seal_and_spool().await;
        assert_eq!(exporter.identity.export_watermark(), 2);
        // The next tick pulls nothing new — no duplicate events buffered.
        exporter.tick().await;
        assert_eq!(exporter.pushed_watermark, 2);
    }

    #[tokio::test]
    async fn oversized_pull_seals_mid_tick_without_watermark_loss() {
        let h = harness("http://127.0.0.1:9/unused").await;
        for _ in 0..600 {
            h.store
                .insert(&sample_incident(None, "fork_storm", None))
                .await
                .unwrap();
        }
        let mut exporter = h.exporter;
        // Tick 1 pulls 500 rows (EXPORT_PULL_LIMIT). The sealer already
        // holds the startup degradation event, so the 500th detection
        // doesn't fit: the batch seals mid-pull and the pull continues
        // into a fresh batch.
        exporter.tick().await;
        assert_eq!(exporter.spool.batch_count(), 1);
        // The mid-pull seal persisted the watermark for the 499 incidents
        // in the sealed batch; the 500th is buffered but not yet sealed.
        assert_eq!(exporter.identity.export_watermark(), 499);
        assert_eq!(exporter.pushed_watermark, 500);

        // Tick 2 pulls the remaining 100 rows. (Tick 1's drain backoff
        // sleeps 5s, so the time-based seal fires here too — the point is
        // the watermark accounting, not which tick sealed.)
        exporter.tick().await;
        assert_eq!(exporter.pushed_watermark, 600);
        exporter.seal_and_spool().await; // no-op if tick 2 already sealed
        assert_eq!(exporter.spool.batch_count(), 2);
        assert_eq!(exporter.identity.export_watermark(), 600);

        // All 600 detections made it into exactly two batches, in order,
        // with no gaps and no duplicates.
        let mut detection_ids: Vec<i64> = Vec::new();
        let mut batch_sizes = Vec::new();
        for seq in [0, 1] {
            let bytes = exporter.spool.read(seq as u64).unwrap();
            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let events = v["events"].as_array().unwrap();
            batch_sizes.push(events.len());
            for e in events {
                if e["event_type"] == "detection" {
                    let id: i64 = e["event_id"]
                        .as_str()
                        .unwrap()
                        .strip_prefix("incident-")
                        .unwrap()
                        .parse()
                        .unwrap();
                    detection_ids.push(id);
                }
            }
        }
        assert_eq!(batch_sizes, [500, 102]); // degradation + 499 detections, then 101 detections + heartbeat
        detection_ids.sort_unstable();
        assert_eq!(detection_ids, (1..=600).collect::<Vec<_>>());
        // The next tick pulls nothing new.
        exporter.tick().await;
        assert_eq!(exporter.pushed_watermark, 600);
    }

    #[tokio::test]
    async fn failed_spool_store_preserves_events_for_retry() {
        let h = harness("http://127.0.0.1:9/unused").await;
        h.store
            .insert(&sample_incident(None, "fork_storm", None))
            .await
            .unwrap();
        h.store
            .insert(&sample_incident(None, "oom_kill", None))
            .await
            .unwrap();
        let mut exporter = h.exporter;
        exporter.tick().await;
        assert_eq!(exporter.pushed_watermark, 2);

        // Sabotage the next spool store: the batch file for sequence 0
        // already exists, so create_new fails (disk-full/permission
        // failures behave the same — store returns Err).
        let spool_dir = h.dir.path().join(super::super::spool::SPOOL_DIR_NAME);
        std::fs::write(spool_dir.join("0.json"), b"sabotage").unwrap();
        exporter.seal_and_spool().await;
        // The events are still buffered — not lost — and the watermark did
        // not advance past them.
        assert!(!exporter.sealer.is_empty());
        assert_eq!(exporter.spool.batch_count(), 0);
        assert_eq!(exporter.identity.export_watermark(), 0);

        // Remove the sabotage: the retry spools everything (on the next
        // sequence — claimed sequences are never reused), the watermark
        // advances, and no incident is skipped or duplicated.
        std::fs::remove_file(spool_dir.join("0.json")).unwrap();
        exporter.seal_and_spool().await;
        assert!(exporter.sealer.is_empty());
        assert_eq!(exporter.spool.batch_count(), 1);
        assert_eq!(exporter.identity.export_watermark(), 2);
        let bytes = exporter.spool.read(1).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let detections = v["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["event_type"] == "detection")
            .count();
        assert_eq!(detections, 2);
        exporter.tick().await;
        assert_eq!(exporter.pushed_watermark, 2);
    }

    #[tokio::test]
    async fn heartbeat_idempotency_keys_survive_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            IncidentStore::new(dir.path().join("incidents.db"))
                .await
                .unwrap(),
        );
        let key_before_restart =
            build_exporter(dir.path(), "http://127.0.0.1:9/unused", store.clone())
                .await
                .heartbeat_event()
                .unwrap()
                .event_idempotency_key;
        // Simulated restart: same state dir, fresh process state (the
        // in-memory counter is gone, but the persisted one is not).
        let mut restarted =
            build_exporter(dir.path(), "http://127.0.0.1:9/unused", store.clone()).await;
        let key_after_restart = restarted.heartbeat_event().unwrap().event_idempotency_key;
        let key_next = restarted.heartbeat_event().unwrap().event_idempotency_key;
        assert_ne!(
            key_before_restart, key_after_restart,
            "a restart must not reuse a heartbeat idempotency key with a different body"
        );
        assert_ne!(key_after_restart, key_next);
        assert!(
            key_after_restart.contains(restarted.identity.agent_instance_id()),
            "key carries the stable instance id: {key_after_restart}"
        );
    }

    #[tokio::test]
    async fn quality_transition_seals_and_emits_degradation() {
        let h = harness("http://127.0.0.1:9/unused").await;
        let mut exporter = h.exporter;
        // Simulate kernel instrumentation coming online.
        exporter.config.quality.transport = "perf".to_string();
        exporter.tick().await;
        // Old (psi_only) batch sealed, new sealer carries the transition.
        assert_eq!(exporter.sealer.quality(), AttributionQuality::Full);
        let EventPayload::DegradationState(payload) = &exporter
            .sealer
            .buffered_events()
            .iter()
            .find(|e| e.event_type == EventType::DegradationState)
            .expect("degradation event buffered")
            .payload
        else {
            panic!("expected degradation payload");
        };
        assert_eq!(payload.attribution_quality, AttributionQuality::Full);
        assert_eq!(payload.fallback_mode, FallbackMode::None);
        assert!(payload.ebpf_attached);
    }

    // --- Mock edge integration tests -------------------------------------

    struct RecordedRequest {
        authorization: Option<String>,
        content_encoding: Option<String>,
        body: Vec<u8>,
    }

    struct MockEdge {
        /// Scripted (status, retry_after) responses, one per request.
        script: Mutex<VecDeque<(u16, Option<String>)>>,
        requests: Mutex<Vec<RecordedRequest>>,
    }

    async fn spawn_mock_edge() -> (String, Arc<MockEdge>) {
        let edge = Arc::new(MockEdge {
            script: Mutex::new(VecDeque::new()),
            requests: Mutex::new(Vec::new()),
        });
        let handler_edge = edge.clone();
        let app = axum::Router::new().route(
            "/v1/event-batches",
            axum::routing::post(move |req: axum::extract::Request| {
                let edge = handler_edge.clone();
                async move {
                    let (parts, body) = req.into_parts();
                    let bytes = axum::body::to_bytes(body, 16 * 1024 * 1024).await.unwrap();
                    let (status, retry_after) = edge
                        .script
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or((202, None));
                    edge.requests.lock().unwrap().push(RecordedRequest {
                        authorization: parts
                            .headers
                            .get(axum::http::header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string),
                        content_encoding: parts
                            .headers
                            .get(axum::http::header::CONTENT_ENCODING)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string),
                        body: bytes.to_vec(),
                    });
                    let mut response = axum::http::Response::builder().status(status);
                    if let Some(ra) = retry_after {
                        response = response.header(axum::http::header::RETRY_AFTER, ra);
                    }
                    response.body(axum::body::Body::empty()).unwrap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/v1/event-batches"), edge)
    }

    #[tokio::test]
    async fn mock_edge_happy_path_posts_gzip_batch_with_auth() {
        let (url, edge) = spawn_mock_edge().await;
        edge.script.lock().unwrap().push_back((202, None));
        let mut h = harness(&url).await;
        h.store
            .insert(&sample_incident(
                None,
                "fork_storm",
                Some(r#"{"verdict":"ForkStormWarning","comm":"x"}"#),
            ))
            .await
            .unwrap();
        h.store
            .insert(&sample_incident(None, "oom_kill", None))
            .await
            .unwrap();
        h.exporter.tick().await;
        h.exporter.seal_and_spool().await;
        assert_eq!(h.exporter.spool.batch_count(), 1);
        h.exporter.drain().await;
        assert_eq!(h.exporter.spool.batch_count(), 0);

        let requests = edge.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let req = &requests[0];
        assert_eq!(req.authorization.as_deref(), Some("Bearer test-token"));
        assert_eq!(req.content_encoding.as_deref(), Some("gzip"));
        let envelope: Value = serde_json::from_slice(&gunzip(&req.body)).unwrap();
        assert_eq!(envelope["schema_version"], "1.0.0");
        assert_eq!(envelope["tenant_id"], "tn_test");
        assert_eq!(envelope["cluster_id"], "clu_test");
        assert_eq!(envelope["node_id"], "node_test");
        assert_eq!(envelope["attribution_quality"], "psi_only");
        assert_eq!(
            envelope["batch_idempotency_key"],
            format!("b:node_test:{}", envelope["sequence"].as_u64().unwrap())
        );
        let types: Vec<&str> = envelope["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["event_type"].as_str().unwrap())
            .collect();
        assert_eq!(
            types,
            ["degradation_state", "detection", "detection", "heartbeat"]
        );
        assert!(
            envelope["events"][1]["payload"]["details"]
                .get("comm")
                .is_none()
        );
    }

    #[tokio::test]
    async fn mock_edge_429_then_202_retries_same_bytes() {
        let (url, edge) = spawn_mock_edge().await;
        edge.script
            .lock()
            .unwrap()
            .push_back((429, Some("0".to_string())));
        edge.script.lock().unwrap().push_back((202, None));
        let mut h = harness(&url).await;
        h.store
            .insert(&sample_incident(None, "fork_storm", None))
            .await
            .unwrap();
        h.exporter.tick().await;
        h.exporter.seal_and_spool().await;
        h.exporter.drain().await; // 429: batch stays spooled
        assert_eq!(h.exporter.spool.batch_count(), 1);
        h.exporter.drain().await; // 202: acked
        assert_eq!(h.exporter.spool.batch_count(), 0);

        let requests = edge.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        // Retries preserve bytes and identity (schema §10).
        assert_eq!(gunzip(&requests[0].body), gunzip(&requests[1].body));
    }

    #[tokio::test]
    async fn mock_edge_409_quarantines_without_retry() {
        let (url, edge) = spawn_mock_edge().await;
        edge.script.lock().unwrap().push_back((409, None));
        let mut h = harness(&url).await;
        h.store
            .insert(&sample_incident(None, "fork_storm", None))
            .await
            .unwrap();
        h.exporter.tick().await;
        h.exporter.seal_and_spool().await;
        h.exporter.drain().await;
        assert_eq!(h.exporter.spool.batch_count(), 0);
        assert_eq!(
            edge.requests.lock().unwrap().len(),
            1,
            "409 must quarantine, never retry"
        );
        let note = std::fs::read_to_string(
            h.dir
                .path()
                .join(super::super::spool::SPOOL_DIR_NAME)
                .join("quarantine")
                .join("0.note"),
        )
        .unwrap();
        assert!(note.contains("409"), "quarantine note explains why: {note}");
    }
}
