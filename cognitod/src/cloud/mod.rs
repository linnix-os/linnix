//! Agent-side Linnix Cloud exporter.
//!
//! Ships evidence batches to the hosted evidence plane per the v1.0.0 event
//! schema (`linnix-cloud-event-schema`). Strictly opt-in: nothing here runs
//! unless `[cloud] enabled = true` with an endpoint, tenant, and token, and
//! even then a failure can only log — it can never break the monitoring loop
//! or the local API.
//!
//! Layout:
//! - [`model`] — the v1 wire types (envelope, heartbeat, detection,
//!   degradation_state).
//! - [`identity`] — stable agent identity persisted next to the incident DB.
//! - [`scrub`] — privacy enforcement: process identity and secrets never
//!   leave the node unless explicitly opted in.
//! - [`seal`] — batch assembly with the schema's seal triggers.
//! - [`spool`] — crash-safe on-disk spool with caps and drop priorities.

pub mod identity;
pub mod model;
pub mod scrub;
pub mod seal;
pub mod spool;

/// Seconds between heartbeat events (schema §10: 60s cadence).
pub const HEARTBEAT_INTERVAL_SECS: u64 = 60;
/// Normal batch flush cadence (schema §10: seal at 5 seconds).
pub const SEAL_INTERVAL_SECS: u64 = 5;
/// Max events per batch (schema §10).
pub const MAX_EVENTS_PER_BATCH: usize = 500;
/// Max uncompressed batch body (schema §10: 1 MiB).
pub const MAX_BATCH_BYTES: usize = 1024 * 1024;
/// Local spool caps (schema §10: 256 MiB / 24h, whichever first).
pub const SPOOL_MAX_BYTES: u64 = 256 * 1024 * 1024;
pub const SPOOL_MAX_AGE_SECS: u64 = 24 * 60 * 60;
/// How many incidents to pull from the store per exporter tick.
pub const EXPORT_PULL_LIMIT: i64 = 500;
