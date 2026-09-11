//! v1.0.0 event-schema wire types.
//!
//! Field names and shapes follow `linnix-cloud-event-schema` exactly; the
//! two deliberate deviations are documented on the types that carry them:
//! - [`DETECTION_CPU_STARVATION`] etc.: the schema's `detection_type` enum
//!   only defines `fork_storm`, `memory_leak`, `short_lived_jobs`, and
//!   `circuit_breaker`. Our other four incident types are emitted as
//!   extended values — a proposed minor schema extension.
//! - `pressure_sample` is omitted in v1 (the schema permits omission until
//!   the agent reads avg60/avg300 and cumulative PSI totals).

use serde::Serialize;

/// The wire contract version this exporter speaks.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Attribution quality of a batch: `full` (eBPF attached) or `psi_only`.
/// Serializes exactly as the schema's enum values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionQuality {
    Full,
    PsiOnly,
}

impl AttributionQuality {
    pub fn as_str(self) -> &'static str {
        match self {
            AttributionQuality::Full => "full",
            AttributionQuality::PsiOnly => "psi_only",
        }
    }
}

/// Detail level of an event. Default export is `evidence`; `raw` requires
/// explicit opt-in the agent does not currently offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetailLevel {
    Summary,
    Evidence,
    Raw,
}

/// Event discriminator. Serializes as the schema's `event_type` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Heartbeat,
    Detection,
    DegradationState,
}

/// Schema-defined detection types.
pub const DETECTION_FORK_STORM: &str = "fork_storm";
pub const DETECTION_MEMORY_LEAK: &str = "memory_leak";
pub const DETECTION_CIRCUIT_BREAKER: &str = "circuit_breaker";
/// Proposed minor extension: our userspace detectors have no schema enum
/// value yet. Emitted as-is so the edge can store them; a strict v1 reader
/// should treat unknown `detection_type` values as opaque rather than
/// rejecting the batch (schema §11: store unknown values, do not coerce).
pub const DETECTION_CPU_STARVATION: &str = "cpu_starvation";
pub const DETECTION_BLKIO_STALL: &str = "blkio_stall";
pub const DETECTION_CGROUP_PRESSURE: &str = "cgroup_pressure";
pub const DETECTION_OOM_KILL: &str = "oom_kill";

/// Map a local incident `event_type` to a cloud `detection_type`.
/// Returns `None` for incident kinds the v1 contract cannot describe —
/// callers skip those rather than shipping an event the edge can't validate.
///
/// The daemon records `circuit_breaker_cpu` (and the API recognizes
/// `circuit_breaker_memory`); both normalize to the schema's
/// `circuit_breaker` rather than being skipped.
pub fn detection_type_for(incident_event_type: &str) -> Option<&'static str> {
    match incident_event_type {
        "fork_storm" => Some(DETECTION_FORK_STORM),
        "memory_leak" => Some(DETECTION_MEMORY_LEAK),
        "cpu_starvation" => Some(DETECTION_CPU_STARVATION),
        "blkio_stall" => Some(DETECTION_BLKIO_STALL),
        "cgroup_pressure" => Some(DETECTION_CGROUP_PRESSURE),
        "oom_kill" => Some(DETECTION_OOM_KILL),
        "circuit_breaker" => Some(DETECTION_CIRCUIT_BREAKER),
        t if t.starts_with("circuit_breaker_") => Some(DETECTION_CIRCUIT_BREAKER),
        _ => None,
    }
}

/// Severity of a detection event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// Inclusive-start, exclusive-end evidence window (RFC 3339 UTC).
#[derive(Debug, Clone, Serialize)]
pub struct TimeRange {
    pub start: String,
    pub end: String,
}

/// Workload identity. `None` (v1) — resolving incidents to pod/namespace is
/// a follow-up; we don't ship process names as workload identity.
#[derive(Debug, Clone, Serialize)]
pub struct WorkloadRef {
    pub namespace: String,
    pub pod: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeartbeatPayload {
    pub interval_seconds: u32,
    pub uptime_seconds: u64,
    pub agent_status: AgentStatus,
    pub transport: Transport,
    pub ebpf_attached: bool,
    pub btf_available: bool,
    pub active_node: bool,
    pub events_buffered: u64,
    pub events_dropped_total: u64,
    pub blame_series_active: u32,
    pub blame_series_evicted_total: u64,
    pub blame_series_evicted_delta: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Healthy,
    Degraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Perf,
    Userspace,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionPayload {
    pub detection_type: String,
    pub severity: Severity,
    pub subject: Option<WorkloadRef>,
    pub window: TimeRange,
    pub rule_name: String,
    pub action: DetectionAction,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionAction {
    Observe,
}

#[derive(Debug, Clone, Serialize)]
pub struct DegradationStatePayload {
    pub attribution_quality: AttributionQuality,
    pub ebpf_attached: bool,
    pub fallback_mode: FallbackMode,
    pub transport: Transport,
    pub btf_available: bool,
    pub rss_probe: String,
    pub lost_capabilities: Vec<String>,
    pub reason_code: String,
    pub reason: String,
    pub state_since: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackMode {
    None,
    ProcPressureOnly,
}

/// Event payload, serialized untagged so the JSON shape matches the schema
/// (no extra discriminator object around the payload).
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum EventPayload {
    Heartbeat(HeartbeatPayload),
    Detection(DetectionPayload),
    DegradationState(DegradationStatePayload),
}

impl EventPayload {
    pub fn event_type(&self) -> EventType {
        match self {
            EventPayload::Heartbeat(_) => EventType::Heartbeat,
            EventPayload::Detection(_) => EventType::Detection,
            EventPayload::DegradationState(_) => EventType::DegradationState,
        }
    }
}

/// One event in a batch: the schema's EVENTBASE.
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub event_id: String,
    pub event_idempotency_key: String,
    pub event_type: EventType,
    pub occurred_at: String,
    pub detail_level: DetailLevel,
    pub payload: EventPayload,
}

/// The batch envelope (schema §2).
#[derive(Debug, Clone, Serialize)]
pub struct BatchEnvelope {
    pub schema_version: String,
    pub tenant_id: String,
    pub cluster_id: String,
    pub node_id: String,
    pub agent_version: String,
    pub sent_at: String,
    pub batch_idempotency_key: String,
    pub sequence: u64,
    pub agent_instance_id: String,
    pub attribution_quality: AttributionQuality,
    pub events: Vec<Event>,
}

impl BatchEnvelope {
    /// `b:{node_id}:{sequence}` — stable across retries (schema §2).
    pub fn idempotency_key(node_id: &str, sequence: u64) -> String {
        format!("b:{node_id}:{sequence}")
    }
}

/// Format a Unix timestamp as RFC 3339 UTC (`occurred_at`/`sent_at`).
pub fn rfc3339(unix_secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix_secs, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_serializes_as_schema_values() {
        assert_eq!(
            serde_json::to_string(&AttributionQuality::Full).unwrap(),
            "\"full\""
        );
        assert_eq!(
            serde_json::to_string(&AttributionQuality::PsiOnly).unwrap(),
            "\"psi_only\""
        );
    }

    #[test]
    fn event_type_serializes_as_schema_values() {
        assert_eq!(
            serde_json::to_string(&EventType::DegradationState).unwrap(),
            "\"degradation_state\""
        );
        assert_eq!(
            serde_json::to_string(&EventType::Heartbeat).unwrap(),
            "\"heartbeat\""
        );
    }

    #[test]
    fn detection_type_mapping_covers_all_six_incident_types() {
        for t in [
            "fork_storm",
            "memory_leak",
            "cpu_starvation",
            "blkio_stall",
            "cgroup_pressure",
            "oom_kill",
        ] {
            assert!(detection_type_for(t).is_some(), "{t} must map");
        }
        assert_eq!(
            detection_type_for("circuit_breaker"),
            Some("circuit_breaker")
        );
        // Recorded circuit-breaker variants normalize instead of skipping.
        assert_eq!(
            detection_type_for("circuit_breaker_cpu"),
            Some("circuit_breaker")
        );
        assert_eq!(
            detection_type_for("circuit_breaker_memory"),
            Some("circuit_breaker")
        );
        assert_eq!(detection_type_for("bogus"), None);
    }

    #[test]
    fn payload_is_untagged() {
        let event = Event {
            event_id: "e1".to_string(),
            event_idempotency_key: "k1".to_string(),
            event_type: EventType::Heartbeat,
            occurred_at: rfc3339(0),
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
        };
        let v: serde_json::Value = serde_json::to_value(&event).unwrap();
        // No wrapper object: heartbeat fields sit directly under "payload".
        assert_eq!(v["payload"]["interval_seconds"], 60);
        assert!(v["payload"].get("heartbeat").is_none());
    }

    #[test]
    fn batch_idempotency_key_format_matches_schema_example() {
        assert_eq!(
            BatchEnvelope::idempotency_key("node_7f89b0", 18421),
            "b:node_7f89b0:18421"
        );
    }
}
