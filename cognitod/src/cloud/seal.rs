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
//!
//! Byte accounting is exact, not estimated: the sealer is built with the
//! identity fields that go into every envelope and precomputes the
//! serialized size of the envelope around the events. A fixed overhead fudge
//! can't account for variable-length identity strings, JSON escaping, or
//! the commas between events — underestimating lets sealed batches exceed
//! the 1 MiB cap the edge enforces (and then quarantines).

use std::time::Instant;

use log::warn;
use sha2::{Digest, Sha256};

use super::model::{AttributionQuality, BatchEnvelope, Event, SCHEMA_VERSION};
use super::{MAX_BATCH_BYTES, MAX_EVENTS_PER_BATCH, SEAL_INTERVAL_SECS};

/// Identity fields baked into every batch envelope. The sealer needs them at
/// construction time (not just at seal time) so the prospective size check
/// in [`try_push`] measures the real envelope instead of guessing.
#[derive(Debug, Clone)]
pub struct SealIdentity {
    pub tenant_id: String,
    pub cluster_id: String,
    pub node_id: String,
    pub agent_instance_id: String,
}

/// `sent_at` always serializes to exactly 24 bytes (`YYYY-MM-DDTHH:MM:SS.sssZ`
/// via [`rfc3339`]); the size template uses a placeholder of the same length
/// so its math stays exact. A test pins this length.
const SENT_AT_PLACEHOLDER: &str = "1970-01-01T00:00:00.000Z";

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
    identity: SealIdentity,
    /// Serialized length of the envelope with zero events, built with
    /// `sequence = u64::MAX` (20 digits) and a 24-byte `sent_at`. The real
    /// sequence is always shorter, so this can only *over*estimate — by at
    /// most 2 × (20 − digits) bytes across `sequence` and the idempotency
    /// key — which fails safe: a batch may seal a few bytes early, but never
    /// over the cap.
    empty_envelope_len: usize,
    events: Vec<Event>,
    event_bytes: usize,
    first_push: Option<Instant>,
}

/// Outcome of attempting to buffer an event. The byte cap is enforced
/// *before* appending, so a sealed batch can never exceed the edge's body
/// limit: the caller seals the current batch first when the next event
/// doesn't fit.
#[derive(Debug, Clone)]
pub enum PushOutcome {
    /// The event was buffered.
    Accepted,
    /// The event doesn't fit in this batch. The event is handed back (not
    /// consumed) so the caller can seal the current batch and push it into
    /// a fresh sealer without cloning beforehand.
    BatchFull(Box<Event>),
    /// The event alone exceeds the byte cap, so it was dropped (with a
    /// warning). The edge would quarantine an oversized batch anyway;
    /// dropping keeps one pathological snapshot from blocking the pipeline.
    /// Callers should count these in their dropped-events total.
    DroppedOversize { bytes: usize },
}

impl BatchSealer {
    pub fn new(quality: AttributionQuality, identity: SealIdentity) -> Self {
        debug_assert_eq!(
            SENT_AT_PLACEHOLDER.len(),
            24,
            "sent_at placeholder must match the 24-byte rfc3339 format"
        );
        // Serialize the envelope with zero events: the exact fixed cost of
        // every batch this sealer produces. `events` serializes last (struct
        // field order), so the template ends with `"events":[]` and the
        // prospective size of n events is
        // `empty_envelope_len + sum(event_bytes) + (n - 1)` commas.
        let template = BatchEnvelope {
            schema_version: SCHEMA_VERSION.to_string(),
            tenant_id: identity.tenant_id.clone(),
            cluster_id: identity.cluster_id.clone(),
            node_id: identity.node_id.clone(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            sent_at: SENT_AT_PLACEHOLDER.to_string(),
            batch_idempotency_key: BatchEnvelope::idempotency_key(&identity.node_id, u64::MAX),
            sequence: u64::MAX,
            agent_instance_id: identity.agent_instance_id.clone(),
            attribution_quality: quality,
            events: Vec::new(),
        };
        let template_bytes =
            serde_json::to_vec(&template).expect("template envelope serialization cannot fail");
        debug_assert!(
            template_bytes.ends_with(br#""events":[]}"#),
            "size math assumes `events` serializes last; BatchEnvelope field order changed?"
        );
        Self {
            quality,
            identity,
            empty_envelope_len: template_bytes.len(),
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

    /// Exact serialized size of the batch if `event_bytes_total` event bytes
    /// were spread over `event_count` events. Derivation: the template is
    /// `{...,"events":[]}`; replacing `[]` with `[e1,…,en]` adds the event
    /// bytes plus (n−1) comma separators.
    fn prospective_len(&self, event_bytes_total: usize, event_count: usize) -> usize {
        self.empty_envelope_len + event_bytes_total + event_count.saturating_sub(1)
    }

    /// Buffer an event, enforcing the count and byte caps *before* the
    /// append. The caller must only push events whose batch-level
    /// attribution quality matches this sealer's — a batch never mixes
    /// quality states (schema §2).
    pub fn try_push(&mut self, event: Event) -> PushOutcome {
        // Size is best-effort: serialization of our own types can't fail.
        let size = serde_json::to_vec(&event).map(|b| b.len()).unwrap_or(0);
        // An event that doesn't fit even alone is dropped, not batched:
        // the edge would quarantine the oversized batch.
        if self.prospective_len(size, 1) > MAX_BATCH_BYTES {
            warn!(
                "[cloud] dropping oversized event ({} bytes > {} byte batch cap); \
                 the edge would quarantine an oversized batch",
                size, MAX_BATCH_BYTES
            );
            return PushOutcome::DroppedOversize { bytes: size };
        }
        if !self.events.is_empty() && self.would_breach(size) {
            return PushOutcome::BatchFull(Box::new(event));
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
            || self.prospective_len(self.event_bytes + size, self.events.len() + 1)
                > MAX_BATCH_BYTES
    }

    /// True when any seal trigger has fired.
    pub fn seal_due(&self, now: Instant) -> bool {
        if self.events.is_empty() {
            return false;
        }
        if self.events.len() >= MAX_EVENTS_PER_BATCH {
            return true;
        }
        // Backstop: try_push already refuses anything that would breach, so
        // this should never fire — but if the accounting ever drifts, seal
        // rather than emit an oversized batch.
        if self.prospective_len(self.event_bytes, self.events.len()) >= MAX_BATCH_BYTES {
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
        // The size accounting was computed from this identity; a caller
        // sealing with different identity fields would invalidate it.
        debug_assert_eq!(ctx.tenant_id, self.identity.tenant_id);
        debug_assert_eq!(ctx.cluster_id, self.identity.cluster_id);
        debug_assert_eq!(ctx.node_id, self.identity.node_id);
        debug_assert_eq!(ctx.agent_instance_id, self.identity.agent_instance_id);
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
        // Backstop for the prospective accounting: a sealed batch must never
        // exceed the cap. (The template overestimates via u64::MAX digits,
        // so this holds with room to spare.)
        debug_assert!(
            bytes.len() <= MAX_BATCH_BYTES,
            "sealed batch ({} bytes) exceeds the {MAX_BATCH_BYTES} byte cap: \
             prospective size accounting is wrong",
            bytes.len(),
        );
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

    fn test_identity() -> SealIdentity {
        SealIdentity {
            tenant_id: "tn_1".to_string(),
            cluster_id: "clu_1".to_string(),
            node_id: "node_1".to_string(),
            agent_instance_id: "instance-1".to_string(),
        }
    }

    /// Production-shaped identity: UUID-length fields, the case the fixed
    /// fudge factor got wrong (commas + escaping + long IDs).
    fn uuid_identity() -> SealIdentity {
        SealIdentity {
            tenant_id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
            cluster_id: "123e4567-e89b-12d3-a456-426614174001".to_string(),
            node_id: "123e4567-e89b-12d3-a456-426614174002".to_string(),
            agent_instance_id: "123e4567-e89b-12d3-a456-426614174003".to_string(),
        }
    }

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
    fn sent_at_is_always_24_bytes() {
        // The template's size math depends on this; rfc3339 with millis is
        // fixed-width by construction.
        assert_eq!(SENT_AT_PLACEHOLDER.len(), 24);
        assert_eq!(rfc3339(1_700_000_000).len(), 24);
        assert_eq!(rfc3339(0).len(), 24);
    }

    #[test]
    fn batch_full_hands_the_event_back() {
        let mut sealer = BatchSealer::new(AttributionQuality::Full, test_identity());
        for i in 0..MAX_EVENTS_PER_BATCH {
            assert!(matches!(
                sealer.try_push(heartbeat_event(&format!("e{i}"))),
                PushOutcome::Accepted
            ));
        }
        // The next event would breach the 500-event cap: it comes back in
        // the outcome — no clone needed before pushing.
        let returned = match sealer.try_push(heartbeat_event("overflow")) {
            PushOutcome::BatchFull(event) => event,
            other => panic!("expected BatchFull, got {other:?}"),
        };
        assert_eq!(returned.event_id, "overflow");
        // Nothing was appended by the refused push.
        assert_eq!(sealer.len(), MAX_EVENTS_PER_BATCH);

        // The returned event goes into a fresh sealer cleanly.
        let mut fresh = BatchSealer::new(AttributionQuality::Full, test_identity());
        assert!(matches!(fresh.try_push(*returned), PushOutcome::Accepted));
        assert_eq!(fresh.len(), 1);
    }

    #[test]
    fn try_push_never_lets_a_batch_exceed_the_byte_cap() {
        let mut sealer = BatchSealer::new(AttributionQuality::Full, test_identity());
        assert!(matches!(
            sealer.try_push(big_event("fill", 512 * 1024)),
            PushOutcome::Accepted
        ));
        // Keep pushing until the cap trips; the refused event must not be
        // appended, and the sealed batch must respect the cap.
        let mut pushed = 1usize;
        let refused_event = loop {
            match sealer.try_push(heartbeat_event(&format!("e{pushed}"))) {
                PushOutcome::Accepted => pushed += 1,
                PushOutcome::BatchFull(event) => break event,
                PushOutcome::DroppedOversize { .. } => panic!("a heartbeat is tiny"),
            }
        };
        assert!(pushed > 1, "the cap should trip before seal_due alone");
        assert_eq!(sealer.len(), pushed);
        let batch = sealer.seal(&ctx()).unwrap();
        assert!(
            batch.bytes.len() <= MAX_BATCH_BYTES,
            "sealed batch ({} bytes) must respect the cap",
            batch.bytes.len()
        );
        // The refused event is reusable without cloning.
        let mut fresh = BatchSealer::new(AttributionQuality::Full, test_identity());
        assert!(matches!(
            fresh.try_push(*refused_event),
            PushOutcome::Accepted
        ));
        assert_eq!(fresh.len(), 1);
    }

    #[test]
    fn byte_accounting_is_exact_at_the_boundary() {
        // Fill a batch with ~100 KiB events until the byte cap (not the
        // count cap) trips, then assert the sealed batch lands just under
        // the cap: exact accounting fills close to the boundary instead of
        // leaving a fudge-sized gap.
        let mut sealer = BatchSealer::new(AttributionQuality::Full, uuid_identity());
        let mut count = 0usize;
        loop {
            match sealer.try_push(big_event(&format!("b{count}"), 100 * 1024)) {
                PushOutcome::Accepted => count += 1,
                PushOutcome::BatchFull(_) => break,
                PushOutcome::DroppedOversize { .. } => panic!("100 KiB fits alone"),
            }
        }
        assert!(count >= 9, "expected ~10 events near the cap, got {count}");
        let batch = sealer
            .seal(&SealContext {
                tenant_id: "123e4567-e89b-12d3-a456-426614174000",
                cluster_id: "123e4567-e89b-12d3-a456-426614174001",
                node_id: "123e4567-e89b-12d3-a456-426614174002",
                agent_instance_id: "123e4567-e89b-12d3-a456-426614174003",
                sequence: 3,
            })
            .unwrap();
        assert!(
            batch.bytes.len() <= MAX_BATCH_BYTES,
            "sealed batch ({} bytes) must respect the cap",
            batch.bytes.len()
        );
        // Near-boundary fill: the next ~100 KiB event didn't fit, so the
        // batch must be within one event of the cap (plus the tiny
        // sequence-digit overestimate) — not a fudge-factor short.
        let event_size = serde_json::to_vec(&big_event("probe", 100 * 1024))
            .unwrap()
            .len();
        assert!(
            batch.bytes.len() + event_size > MAX_BATCH_BYTES,
            "batch ({} bytes) should be within one event ({event_size} bytes) of the cap",
            batch.bytes.len()
        );
    }

    #[test]
    fn full_event_count_batch_with_uuid_identity_stays_under_cap() {
        // 500 events with production-length identity strings: the old
        // fixed-fudge accounting could overshoot here (499 commas alone
        // nearly exhaust a 512-byte fudge).
        let mut sealer = BatchSealer::new(AttributionQuality::Full, uuid_identity());
        let mut accepted = 0;
        for i in 0..MAX_EVENTS_PER_BATCH {
            match sealer.try_push(heartbeat_event(&format!("e{i}"))) {
                PushOutcome::Accepted => accepted += 1,
                PushOutcome::BatchFull(_) => break,
                PushOutcome::DroppedOversize { .. } => panic!("heartbeat is tiny"),
            }
        }
        assert_eq!(accepted, MAX_EVENTS_PER_BATCH);
        let batch = sealer
            .seal(&SealContext {
                tenant_id: "123e4567-e89b-12d3-a456-426614174000",
                cluster_id: "123e4567-e89b-12d3-a456-426614174001",
                node_id: "123e4567-e89b-12d3-a456-426614174002",
                agent_instance_id: "123e4567-e89b-12d3-a456-426614174003",
                sequence: 3,
            })
            .unwrap();
        assert_eq!(batch.event_count, MAX_EVENTS_PER_BATCH);
        assert!(
            batch.bytes.len() <= MAX_BATCH_BYTES,
            "500-event batch ({} bytes) must respect the cap",
            batch.bytes.len()
        );
    }

    #[test]
    fn oversized_single_event_is_dropped_with_outcome() {
        let mut sealer = BatchSealer::new(AttributionQuality::Full, test_identity());
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
        let mut sealer = BatchSealer::new(AttributionQuality::Full, test_identity());
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
        let mut sealer = BatchSealer::new(AttributionQuality::PsiOnly, test_identity());
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
            let mut sealer = BatchSealer::new(AttributionQuality::Full, test_identity());
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
        let mut sealer = BatchSealer::new(AttributionQuality::Full, test_identity());
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
