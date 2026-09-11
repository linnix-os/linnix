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
use super::seal::{BatchSealer, SealContext, SealedBatch};
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
    heartbeat_count: u64,
    last_heartbeat: Instant,
    consecutive_failures: u32,
    last_evictions: u64,
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
        let mut exporter = Self {
            config,
            identity,
            spool,
            sender,
            sealer: BatchSealer::new(quality),
            pushed_watermark: watermark,
            pending_priority: SpoolPriority::Heartbeat,
            store,
            blame,
            start: Instant::now(),
            state_since: rfc3339(Utc::now().timestamp()),
            heartbeat_count: 0,
            last_heartbeat: Instant::now() - Duration::from_secs(HEARTBEAT_INTERVAL_SECS),
            consecutive_failures: 0,
            last_evictions,
            policy,
            backoff: backoff_delay,
        };
        // The first batch always opens with the current degradation state so
        // the edge learns the quality before the first heartbeat arrives.
        let degradation = exporter.degradation_event();
        exporter.push_event(degradation, SpoolPriority::DegradationState);
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
            self.sealer = BatchSealer::new(quality);
            let degradation = self.degradation_event();
            self.push_event(degradation, SpoolPriority::DegradationState);
            info!("[cloud] attribution quality changed to {quality:?}; emitted degradation_state");
        }

        match self
            .store
            .export_batch(self.pushed_watermark, EXPORT_PULL_LIMIT)
            .await
        {
            Ok(incidents) => {
                for incident in &incidents {
                    if let Some(id) = incident.id {
                        self.pushed_watermark = self.pushed_watermark.max(id);
                    }
                    match self.detection_event(incident) {
                        Some(event) => self.push_event(event, SpoolPriority::Detection),
                        None => debug!(
                            "[cloud] skipping incident {:?} (unmapped type {:?})",
                            incident.id, incident.event_type
                        ),
                    }
                }
            }
            Err(e) => warn!("[cloud] incident pull failed: {e}; will retry next tick"),
        }

        if self.last_heartbeat.elapsed() >= Duration::from_secs(HEARTBEAT_INTERVAL_SECS) {
            self.heartbeat_count += 1;
            let heartbeat = self.heartbeat_event();
            self.push_event(heartbeat, SpoolPriority::Heartbeat);
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

    fn push_event(&mut self, event: Event, priority: SpoolPriority) {
        self.pending_priority = self.pending_priority.min(priority);
        self.sealer.push(event);
    }

    /// Seal the buffered events and spool the batch. The watermark advances
    /// only after the batch is durable on disk.
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
                if let Err(e) = self.identity.set_export_watermark(self.pushed_watermark) {
                    error!("[cloud] spooled batch {sequence} but failed to persist watermark: {e}");
                }
                self.pending_priority = SpoolPriority::Heartbeat;
            }
            Err(e) => error!("[cloud] spool store failed for batch {sequence}: {e}"),
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
                    let _ = self.spool.remove(sequence);
                    continue;
                }
            };
            match self.sender.post_batch(&bytes).await {
                SendDecision::Acked => {
                    let _ = self.spool.remove(sequence);
                    self.consecutive_failures = 0;
                }
                SendDecision::Quarantine { reason } => {
                    let _ = self.spool.quarantine(sequence, &reason);
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

    fn heartbeat_event(&mut self) -> Event {
        let n = self.heartbeat_count;
        let node_id = self.identity.node_id();
        let quality = self.sealer.quality();
        let evicted_total = self.blame.evictions();
        let evicted_delta = evicted_total.saturating_sub(self.last_evictions);
        self.last_evictions = evicted_total;
        Event {
            event_id: format!("hb-{node_id}-{n}"),
            event_idempotency_key: format!("e:hb:{node_id}:{n}"),
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
                events_dropped_total: self.spool.dropped_total(),
                blame_series_active: self
                    .blame
                    .victim_series()
                    .saturating_add(self.blame.pair_series())
                    as u32,
                blame_series_evicted_total: evicted_total,
                blame_series_evicted_delta: evicted_delta,
            }),
        }
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

    async fn harness(endpoint: &str) -> TestHarness {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            IncidentStore::new(dir.path().join("incidents.db"))
                .await
                .unwrap(),
        );
        let blame = Arc::new(BlameMetrics::new("test-node"));
        let config = ExporterConfig {
            endpoint: endpoint.to_string(),
            token: "test-token".to_string(),
            tenant_id: "tn_test".to_string(),
            cluster_id_override: Some("clu_test".to_string()),
            node_id_override: Some("node_test".to_string()),
            export_process_identity: false,
            state_dir: dir.path().to_path_buf(),
            quality: QualitySnapshot {
                transport: "userspace".to_string(),
                btf_available: false,
                rss_probe: "unavailable".to_string(),
            },
        };
        let mut exporter = Exporter::new(config, store.clone(), blame).await.unwrap();
        // Keep retry-path tests fast; production uses exponential backoff.
        exporter.backoff = |_| Duration::from_millis(1);
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
