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
//! - [`sender`] — HTTPS POST with the schema's retry/quarantine semantics.
//! - [`exporter`] — the background loop wiring it all together.

pub mod exporter;
pub mod identity;
pub mod model;
pub mod scrub;
pub mod seal;
pub mod sender;
pub mod spool;

pub use exporter::{ExporterConfig, QualitySnapshot, spawn_exporter};

use std::io;
use std::path::Path;

/// Durably write `bytes` to `path`: create/truncate a temp file, write all
/// bytes, `sync_all` the temp file, atomically rename over `path`, then
/// fsync the parent directory so the rename itself survives a power loss.
///
/// A bare write-then-rename is only crash-safe against *process* crashes.
/// Without the two syncs, a host or power loss can roll the rename back
/// (silently losing the write) or drop the directory entry for a file the
/// manifest already references. This holds on filesystems that honor sync
/// (ext4, xfs, btrfs); exotic setups (NFS without sync, some FUSE layers)
/// may weaken the guarantee. Used for every metadata write whose loss would
/// corrupt sequence/watermark/accounting state: `cloud_identity.json`,
/// `spool.json`, and quarantine notes.
pub(crate) fn persist_durable(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        use std::io::Write as _;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    sync_dir(path.parent().unwrap_or(Path::new(".")))
}

/// fsync a directory so a newly created file inside it (or a rename into
/// it) is durable against host/power loss, not just process crashes.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    let f = std::fs::File::open(dir)?;
    f.sync_all()
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persist_durable_round_trips_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        persist_durable(&path, b"{\"a\":1}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"a\":1}");
        // No temp file left behind.
        assert!(!dir.path().join("state.json.tmp").exists());
        // Overwriting an existing file is durable too.
        persist_durable(&path, b"{\"a\":2}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"a\":2}");
        assert!(!dir.path().join("state.json.tmp").exists());
    }

    #[test]
    fn persist_durable_fails_loudly_on_missing_parent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope").join("state.json");
        assert!(persist_durable(&path, b"x").is_err());
    }

    #[test]
    fn sync_dir_works_on_a_real_directory() {
        let dir = tempfile::tempdir().unwrap();
        sync_dir(dir.path()).unwrap();
    }
}
