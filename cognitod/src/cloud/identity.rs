//! Stable agent identity, persisted next to the incident database.
//!
//! The schema needs identifiers that survive daemon restarts:
//! - `cluster_id`: stable installation ID (operator override, else generated
//!   once — every node then gets its own, which the config docs call out).
//! - `node_id`: operator override, else `NODE_NAME` → `HOSTNAME` → OS
//!   hostname (the same order `k8s.rs` uses). The first resolved value is
//!   persisted, so a later rename doesn't fork the node's identity.
//! - `agent_instance_id`: UUID v4, generated once. Changes only when the
//!   state directory is recreated, per schema §2.
//! - `next_sequence`: the batch sequence counter, monotonic per
//!   `agent_instance_id` (schema §2: gap detector).
//! - `export_watermark`: the last incident row id sealed into a batch, so a
//!   restart resumes export without re-sending or skipping.
//!
//! Writes go through [`super::persist_durable`]: temp file, `sync_all` the
//! temp file, atomic rename, then a parent-directory fsync. That covers
//! process crashes *and* host/power loss (on filesystems that honor sync),
//! so a torn or rolled-back identity file can never fork the node's
//! sequence, watermark, or agent instance ID.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// File name inside the state directory.
pub const IDENTITY_FILE_NAME: &str = "cloud_identity.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdentityFile {
    cluster_id: String,
    node_id: String,
    agent_instance_id: String,
    next_sequence: u64,
    export_watermark: i64,
}

/// Resolve the node identity: explicit config override wins, then the
/// `NODE_NAME` downward-API variable, then `HOSTNAME`, then the OS hostname.
/// Mirrors the order `k8s.rs` uses for its node name.
pub fn resolve_node_id(override_id: Option<&str>) -> String {
    if let Some(id) = override_id.filter(|s| !s.trim().is_empty()) {
        return id.trim().to_string();
    }
    if let Ok(name) = std::env::var("NODE_NAME")
        && !name.trim().is_empty()
    {
        return name;
    }
    if let Ok(name) = std::env::var("HOSTNAME")
        && !name.trim().is_empty()
    {
        return name;
    }
    sysinfo::System::host_name().unwrap_or_else(|| "unknown-host".to_string())
}

#[derive(Debug)]
pub struct IdentityStore {
    path: PathBuf,
    identity: IdentityFile,
}

impl IdentityStore {
    /// Load the identity from `state_dir/cloud_identity.json`, creating it
    /// (with fresh generated IDs) when absent. `node_id_override` and
    /// `cluster_id_override` are honored only at creation time — afterwards
    /// the persisted values win, keeping the identity stable.
    pub fn load_or_create(
        state_dir: &Path,
        cluster_id_override: Option<&str>,
        node_id_override: Option<&str>,
    ) -> io::Result<Self> {
        std::fs::create_dir_all(state_dir)?;
        let path = state_dir.join(IDENTITY_FILE_NAME);
        let identity = match std::fs::read_to_string(&path) {
            Ok(contents) => serde_json::from_str::<IdentityFile>(&contents).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} is corrupt: {e}", path.display()),
                )
            })?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let fresh = IdentityFile {
                    cluster_id: cluster_id_override
                        .filter(|s| !s.trim().is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                    node_id: resolve_node_id(node_id_override),
                    agent_instance_id: uuid::Uuid::new_v4().to_string(),
                    next_sequence: 0,
                    export_watermark: 0,
                };
                let store = Self {
                    path: path.clone(),
                    identity: fresh,
                };
                store.persist()?;
                return Ok(store);
            }
            Err(e) => return Err(e),
        };
        Ok(Self { path, identity })
    }

    fn persist(&self) -> io::Result<()> {
        let bytes = serde_json::to_string_pretty(&self.identity).unwrap();
        super::persist_durable(&self.path, bytes.as_bytes())
    }

    pub fn cluster_id(&self) -> &str {
        &self.identity.cluster_id
    }

    pub fn node_id(&self) -> &str {
        &self.identity.node_id
    }

    pub fn agent_instance_id(&self) -> &str {
        &self.identity.agent_instance_id
    }

    /// Claim the next batch sequence number (persisted immediately, so a
    /// crash between seal and send can't reuse it).
    pub fn next_sequence(&mut self) -> io::Result<u64> {
        let seq = self.identity.next_sequence;
        self.identity.next_sequence = seq.saturating_add(1);
        self.persist()?;
        Ok(seq)
    }

    pub fn export_watermark(&self) -> i64 {
        self.identity.export_watermark
    }

    /// Advance the export watermark past the incidents sealed into a batch.
    /// Call only once the batch is durably spooled — the spool redrives
    /// after a crash, so advancing here is at-least-once safe.
    pub fn set_export_watermark(&mut self, last_id: i64) -> io::Result<()> {
        if last_id > self.identity.export_watermark {
            self.identity.export_watermark = last_id;
            self.persist()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_store(dir: &Path) -> IdentityStore {
        IdentityStore::load_or_create(dir, None, Some("test-node")).unwrap()
    }

    #[test]
    fn identity_is_stable_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let first = fresh_store(dir.path());
        let (cluster, node, instance) = (
            first.cluster_id().to_string(),
            first.node_id().to_string(),
            first.agent_instance_id().to_string(),
        );
        drop(first);
        // Overrides are ignored once an identity exists.
        let second =
            IdentityStore::load_or_create(dir.path(), Some("other-cluster"), Some("other-node"))
                .unwrap();
        assert_eq!(second.cluster_id(), cluster);
        assert_eq!(second.node_id(), node);
        assert_eq!(second.agent_instance_id(), instance);
        assert_eq!(second.node_id(), "test-node");
    }

    #[test]
    fn sequence_is_monotonic_and_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = fresh_store(dir.path());
        assert_eq!(store.next_sequence().unwrap(), 0);
        assert_eq!(store.next_sequence().unwrap(), 1);
        drop(store);
        let mut reopened = fresh_store(dir.path());
        assert_eq!(reopened.next_sequence().unwrap(), 2);
    }

    #[test]
    fn watermark_only_moves_forward() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = fresh_store(dir.path());
        assert_eq!(store.export_watermark(), 0);
        store.set_export_watermark(42).unwrap();
        assert_eq!(store.export_watermark(), 42);
        store.set_export_watermark(7).unwrap();
        assert_eq!(store.export_watermark(), 42);
        drop(store);
        let reopened = fresh_store(dir.path());
        assert_eq!(reopened.export_watermark(), 42);
    }

    #[test]
    fn corrupt_identity_is_an_error_not_a_reset() {
        // Silently minting a new agent_instance_id on corrupt state would
        // fork the node's identity; fail loudly instead.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(IDENTITY_FILE_NAME), "not json").unwrap();
        let err = IdentityStore::load_or_create(dir.path(), None, None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
