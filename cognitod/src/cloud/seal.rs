//! Batch assembly with the schema's seal triggers.
//!
//! Events are serialized once, at push time, to measure them; the sealed
//! batch bytes are then immutable — retries resend the exact same bytes with
//! the same idempotency key (schema §10: "Retries preserve bytes and
//! identity").
//!
//! Seal triggers (schema §10): 500 events, 1 MiB uncompressed, or 5 seconds
//! since the first buffered event. A change in attribution quality seals
//! immediately too, but that's handled by the exporter (seal the old batch,
//! rotate to a new sealer) because a batch must never mix quality states.

use std::time::Instant;

use log::warn;
use sha2::{Digest, Sha256};

use super::model::{AttributionQuality, BatchEnvelope, Event, SCHEMA_VERSION};
use super::{MAX_BATCH_BYTES, MAX_EVENTS_PER_BATCH, SEAL_INTERVAL_SECS};

/// Fixed overhead fudge for the envelope around the events when deciding
/// whether the next push would breach the 1 MiB cap. The real envelope is a
/// few hundred bytes; overestimating slightly is safe.
const ENVELOPE_OVERHEAD: usize = 512;

/// Context needed once per sealed batch.
pub struct SealContext<'a> {
    pub tenant_id: &'a str,
    pub cluster_id: &'a str,
    pub node_id: &'a str,
    pub agent_instance_id: &'a str,
    pub sequence: u64,
}

/// A sealed, immutable batch: the exact bytes to POST, with their digest.
pub struct SealedBatch {
    pub sequence: u64,
    pub quality: AttributionQuality,
    pub event_count: usize,
    pub bytes: Vec<u8>,
    /// sha256 hex of `bytes`, recorded so the spool can verify integrity.
    pub digest: String,
}

pub struct BatchSealer {
    quality: AttributionQuality,
    events: Vec<Event>,
    event_bytes: usize,
    first_push: Option<Instant>,
}

/// Outcome of attempting to buffer an event. The byte cap is enforced
/// *before* appending, so a sealed batch can never exceed the edge's body
/// limit: the caller seals the current batch first when the next event
/// doesn't fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// The event was buffered.
    Accepted,
    /// The event doesn't fit in this batch: the caller should seal the
    /// current batch, then push the event into a fresh sealer.
    BatchFull,
    /// The event alone exceeds the byte cap, so it was dropped (with a
    /// warning). The edge would quarantine an oversized batch anyway;
    /// dropping keeps one pathological snapshot from blocking the pipeline.
    /// Callers should count these in their dropped-events total.
    DroppedOversize { bytes: usize },
}

impl BatchSealer {
    pub fn new(quality: AttributionQuality) -> Self {
        Self {
            quality,
            events: Vec::new(),
            event_bytes: 0,
            first_push: None,
        }
    }

    pub fn quality(&self) -> AttributionQuality {
        self.quality
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Buffer an event, enforcing the count and byte caps *before* the
    /// append. The caller must only push events whose batch-level
    /// attribution quality matches this sealer's — a batch never mixes
    /// quality states (schema §2).
    pub fn try_push(&mut self, event: Event) -> PushOutcome {
        // Size is best-effort: serialization of our own types can't fail.
        let size = serde_json::to_vec(&event).map(|b| b.len()).unwrap_or(0);
        if size + ENVELOPE_OVERHEAD > MAX_BATCH_BYTES {
            warn!(
                "[cloud] dropping oversized event ({} bytes > {} byte batch cap); \
                 the edge would quarantine an oversized batch",
                size, MAX_BATCH_BYTES
            );
            return PushOutcome::DroppedOversize { bytes: size };
        }
        if !self.events.is_empty() && self.would_breach(size) {
            return PushOutcome::BatchFull;
        }
        if self.first_push.is_none() {
            self.first_push = Some(Instant::now());
        }
        self.event_bytes += size;
        self.events.push(event);
        PushOutcome::Accepted
    }

    /// True if buffering an event of `size` bytes would breach a cap.
    fn would_breach(&self, size: usize) -> bool {
        self.events.len() + 1 > MAX_EVENTS_PER_BATCH
            || self.event_bytes + size + ENVELOPE_OVERHEAD > MAX_BATCH_BYTES
    }

    /// True when any seal trigger has fired.
    pub fn seal_due(&self, now: Instant) -> bool {
        if self.events.is_empty() {
            return false;
        }
        if self.events.len() >= MAX_EVENTS_PER_BATCH {
            return true;
        }
        if self.event_bytes + ENVELOPE_OVERHEAD >= MAX_BATCH_BYTES {
            return true;
        }
        if let Some(first) = self.first_push
            && now.duration_since(first).as_secs() >= SEAL_INTERVAL_SECS
        {
            return true;
        }
        false
    }

    /// Test hook: inspect the currently buffered events.
    #[cfg(test)]
    pub fn buffered_events(&self) -> &[Event] {
        &self.events
    }

    /// Seal the buffered events into an immutable batch. Returns `None`
    /// when there's nothing to seal (the schema requires 1–500 events).
    pub fn seal(&mut self, ctx: &SealContext<'_>) -> Option<SealedBatch> {
        if self.events.is_empty() {
            return None;
        }
        let events = std::mem::take(&mut self.events);
        self.event_bytes = 0;
        self.first_push = None;
        let event_count = events.len();

        let envelope = BatchEnvelope {
            schema_version: SCHEMA_VERSION.to_string(),
            tenant_id: ctx.tenant_id.to_string(),
            cluster_id: ctx.cluster_id.to_string(),
            node_id: ctx.node_id.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            sent_at: super::model::rfc3339(chrono::Utc::now().timestamp()),
            batch_idempotency_key: BatchEnvelope::idempotency_key(ctx.node_id, ctx.sequence),
            sequence: ctx.sequence,
            agent_instance_id: ctx.agent_instance_id.to_string(),
            attribution_quality: self.quality,
            events,
        };
        // Same inputs → same bytes: idempotency keys are stable across retries.
        let bytes = serde_json::to_vec(&envelope).expect("envelope serialization cannot fail");
        let digest = hex::encode(Sha256::digest(&bytes));
        Some(SealedBatch {
            sequence: ctx.sequence,
            quality: self.quality,
            event_count,
            bytes,
            digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::*;
    use super::*;

    fn heartbeat_event(id: &str) -> Event {
        Event {
            event_id: id.to_string(),
            event_idempotency_key: format!("k:{id}"),
            event_type: EventType::Heartbeat,
            occurred_at: rfc3339(1_700_000_000),
            detail_level: DetailLevel::Summary,
            payload: EventPayload::Heartbeat(HeartbeatPayload {
                interval_seconds: 60,
                uptime_seconds: 1,
                agent_status: AgentStatus::Healthy,
                transport: Transport::Perf,
                ebpf_attached: true,
                btf_available: true,
                active_node: true,
                events_buffered: 0,
                events_dropped_total: 0,
                blame_series_active: 0,
                blame_series_evicted_total: 0,
                blame_series_evicted_delta: 0,
            }),
        }
    }

    fn ctx<'a>() -> SealContext<'a> {
        SealContext {
            tenant_id: "tn_1",
            cluster_id: "clu_1",
            node_id: "node_1",
            agent_instance_id: "instance-1",
            sequence: 7,
        }
    }

    fn big_event(id: &str, blob_len: usize) -> Event {
        Event {
            event_id: id.to_string(),
            event_idempotency_key: format!("k:{id}"),
            event_type: EventType::Detection,
            occurred_at: rfc3339(1_700_000_000),
            detail_level: DetailLevel::Evidence,
            payload: EventPayload::Detection(DetectionPayload {
                detection_type: "fork_storm".to_string(),
                severity: Severity::Warning,
                subject: None,
                window: TimeRange {
                    start: rfc3339(1_700_000_000 - 10),
                    end: rfc3339(1_700_000_000),
                },
                rule_name: "fork_storm".to_string(),
                action: DetectionAction::Observe,
                details: serde_json::json!({"blob": "x".repeat(blob_len)}),
            }),
        }
    }

    #[test]
    fn try_push_reports_batch_full_before_breaching_caps() {
        let mut sealer = BatchSealer::new(AttributionQuality::Full);
        for i in 0..MAX_EVENTS_PER_BATCH {
            assert_eq!(
                sealer.try_push(heartbeat_event(&format!("e{i}"))),
                PushOutcome::Accepted
            );
        }
        // The next event would breach the 500-event cap: seal first.
        assert_eq!(
            sealer.try_push(heartbeat_event("overflow")),
            PushOutcome::BatchFull
        );
        // Nothing was appended by the refused push.
        assert_eq!(sealer.len(), MAX_EVENTS_PER_BATCH);

        // A fresh sealer accepts it.
        let mut fresh = BatchSealer::new(AttributionQuality::Full);
        assert_eq!(
            fresh.try_push(heartbeat_event("overflow")),
            PushOutcome::Accepted
        );
    }

    #[test]
    fn try_push_never_lets_a_batch_exceed_the_byte_cap() {
        let mut sealer = BatchSealer::new(AttributionQuality::Full);
        assert_eq!(
            sealer.try_push(big_event("fill", 512 * 1024)),
            PushOutcome::Accepted
        );
        // Keep pushing until the cap trips; the refused event must not be
        // appended, and the sealed batch must respect the cap.
        let mut pushed = 1usize;
        let refused_at = loop {
            match sealer.try_push(heartbeat_event(&format!("e{pushed}"))) {
                PushOutcome::Accepted => pushed += 1,
                PushOutcome::BatchFull => break pushed,
                PushOutcome::DroppedOversize { .. } => panic!("a heartbeat is tiny"),
            }
        };
        assert!(refused_at > 1, "the cap should trip before seal_due alone");
        assert_eq!(sealer.len(), refused_at);
        let batch = sealer.seal(&ctx()).unwrap();
        assert!(
            batch.bytes.len() < MAX_BATCH_BYTES,
            "sealed batch ({} bytes) must respect the cap",
            batch.bytes.len()
        );
        // The refused event goes into a fresh batch cleanly.
        let mut fresh = BatchSealer::new(AttributionQuality::Full);
        assert_eq!(
            fresh.try_push(heartbeat_event("next")),
            PushOutcome::Accepted
        );
    }

    #[test]
    fn oversized_single_event_is_dropped_with_outcome() {
        let mut sealer = BatchSealer::new(AttributionQuality::Full);
        let outcome = sealer.try_push(big_event("huge", MAX_BATCH_BYTES));
        assert!(matches!(
            outcome,
            PushOutcome::DroppedOversize { bytes } if bytes > MAX_BATCH_BYTES
        ));
        // The sealer is untouched: the drop can't poison the batch.
        assert!(sealer.is_empty());
        assert!(!sealer.seal_due(Instant::now()));
    }

    #[test]
    fn seals_on_event_count() {
        let mut sealer = BatchSealer::new(AttributionQuality::Full);
        for i in 0..MAX_EVENTS_PER_BATCH {
            sealer.try_push(heartbeat_event(&format!("e{i}")));
            assert_eq!(
                sealer.seal_due(Instant::now()),
                i + 1 >= MAX_EVENTS_PER_BATCH
            );
        }
        let batch = sealer.seal(&ctx()).unwrap();
        assert_eq!(batch.event_count, MAX_EVENTS_PER_BATCH);
        assert_eq!(batch.sequence, 7);
        assert!(sealer.is_empty());
    }

    #[test]
    fn seals_on_time() {
        let mut sealer = BatchSealer::new(AttributionQuality::PsiOnly);
        sealer.try_push(heartbeat_event("e1"));
        assert!(!sealer.seal_due(Instant::now()));
        let later = Instant::now() + std::time::Duration::from_secs(SEAL_INTERVAL_SECS);
        assert!(sealer.seal_due(later));
        let batch = sealer.seal(&ctx()).unwrap();
        assert_eq!(batch.quality, AttributionQuality::PsiOnly);
        // Empty sealer seals to nothing: the schema requires ≥1 event.
        assert!(sealer.seal(&ctx()).is_none());
    }

    #[test]
    fn idempotency_inputs_are_stable_across_retries() {
        // sent_at varies per seal, but everything the edge dedupes on —
        // idempotency key, sequence, event payloads — is stable, so a retry
        // of the same logical batch is recognized as the same batch.
        let build = || {
            let mut sealer = BatchSealer::new(AttributionQuality::Full);
            sealer.try_push(heartbeat_event("e1"));
            sealer.seal(&ctx()).unwrap()
        };
        let a = build();
        let b = build();
        let va: serde_json::Value = serde_json::from_slice(&a.bytes).unwrap();
        let vb: serde_json::Value = serde_json::from_slice(&b.bytes).unwrap();
        assert_eq!(va["batch_idempotency_key"], "b:node_1:7");
        assert_eq!(va["batch_idempotency_key"], vb["batch_idempotency_key"]);
        assert_eq!(va["events"], vb["events"]);
        // Digest is sha256 over the sealed bytes.
        use sha2::Digest as _;
        assert_eq!(a.digest, hex::encode(sha2::Sha256::digest(&a.bytes)));
    }

    #[test]
    fn envelope_shape_matches_schema() {
        let mut sealer = BatchSealer::new(AttributionQuality::Full);
        sealer.try_push(heartbeat_event("e1"));
        let batch = sealer.seal(&ctx()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&batch.bytes).unwrap();
        assert_eq!(v["schema_version"], "1.0.0");
        assert_eq!(v["tenant_id"], "tn_1");
        assert_eq!(v["cluster_id"], "clu_1");
        assert_eq!(v["node_id"], "node_1");
        assert_eq!(v["sequence"], 7);
        assert_eq!(v["agent_instance_id"], "instance-1");
        assert_eq!(v["attribution_quality"], "full");
        assert_eq!(v["events"].as_array().unwrap().len(), 1);
        assert_eq!(v["events"][0]["event_type"], "heartbeat");
    }
}
