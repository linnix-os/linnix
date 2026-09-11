//! Crash-safe on-disk spool for sealed batches.
//!
//! Layout inside the state directory (`cloud_spool/`):
//! - `{sequence}.json` — the immutable sealed batch bytes.
//! - `spool.json` — manifest: entries (sequence, priority, digest, bytes,
//!   event count, sealed-at) plus the cumulative `dropped_total`.
//! - `quarantine/` — batches the edge refused (409/413/422) with a `.note`
//!   explaining why; never retried, kept for operator inspection.
//!
//! Caps (schema §10): 256 MiB total or 24h age, whichever first. When a cap
//! is hit the oldest lowest-priority batches are dropped first:
//! heartbeat, then detection. `degradation_state` is never dropped —
//! losing the quality signal would let the cloud mistake silence for health.
//! Every drop increments `dropped_total`, which the heartbeat reports.

use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::seal::SealedBatch;
use super::{SPOOL_MAX_AGE_SECS, SPOOL_MAX_BYTES};

pub const SPOOL_DIR_NAME: &str = "cloud_spool";
const MANIFEST_NAME: &str = "spool.json";
const QUARANTINE_DIR: &str = "quarantine";

/// Drop priority: lower value = more important = dropped later.
/// Mirrors schema §10 ("Never drop degradation_state, then retain
/// stall_attribution and detection, then heartbeat, and drop oldest
/// pressure_sample first" — pressure_sample isn't emitted in v1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SpoolPriority {
    DegradationState = 0,
    Detection = 1,
    Heartbeat = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpoolEntry {
    sequence: u64,
    priority: SpoolPriority,
    digest: String,
    bytes: u64,
    events: usize,
    sealed_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Manifest {
    entries: Vec<SpoolEntry>,
    dropped_total: u64,
}

pub struct Spool {
    dir: PathBuf,
    manifest_path: PathBuf,
    quarantine_dir: PathBuf,
    entries: VecDeque<SpoolEntry>,
    total_bytes: u64,
    dropped_total: u64,
}

impl Spool {
    /// Open (or create) the spool in `state_dir/cloud_spool`, rebuilding the
    /// index from the manifest and dropping entries whose batch file is
    /// missing (e.g. torn write before the manifest fsync).
    pub fn open(state_dir: &Path) -> io::Result<Self> {
        let dir = state_dir.join(SPOOL_DIR_NAME);
        std::fs::create_dir_all(&dir)?;
        let quarantine_dir = dir.join(QUARANTINE_DIR);
        std::fs::create_dir_all(&quarantine_dir)?;
        let manifest_path = dir.join(MANIFEST_NAME);

        let mut manifest: Manifest = match std::fs::read_to_string(&manifest_path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Manifest::default(),
            Err(e) => return Err(e),
        };
        // Drop index entries whose payload didn't survive.
        manifest
            .entries
            .retain(|e| dir.join(batch_file_name(e.sequence)).exists());

        let total_bytes = manifest.entries.iter().map(|e| e.bytes).sum();
        let entries = manifest.entries.into_iter().collect();
        Ok(Self {
            dir,
            manifest_path,
            quarantine_dir,
            entries,
            total_bytes,
            dropped_total: manifest.dropped_total,
        })
    }

    fn persist(&self) -> io::Result<()> {
        let manifest = Manifest {
            entries: self.entries.iter().cloned().collect(),
            dropped_total: self.dropped_total,
        };
        let tmp = self.manifest_path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&manifest).unwrap())?;
        std::fs::rename(&tmp, &self.manifest_path)?;
        Ok(())
    }

    fn batch_path(&self, sequence: u64) -> PathBuf {
        self.dir.join(batch_file_name(sequence))
    }

    /// Durably store a sealed batch, then enforce the caps.
    pub fn store(&mut self, batch: &SealedBatch, priority: SpoolPriority) -> io::Result<()> {
        let path = self.batch_path(batch.sequence);
        // create_new: a sequence is never reused, so an existing file means
        // a bug — fail loudly rather than silently overwriting evidence.
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        let mut file = opts.open(&path)?;
        use std::io::Write as _;
        file.write_all(&batch.bytes)?;
        file.sync_all()?;

        // Keep newest-first ordering simple: entries are appended in
        // sequence order; the drain end is the front.
        self.entries.push_back(SpoolEntry {
            sequence: batch.sequence,
            priority,
            digest: batch.digest.clone(),
            bytes: batch.bytes.len() as u64,
            events: batch.event_count,
            sealed_at_unix: now_unix(),
        });
        self.total_bytes += batch.bytes.len() as u64;
        self.enforce_caps()?;
        self.persist()
    }

    /// Drop oldest-lowest-priority batches until both caps hold.
    /// Degradation-state batches are never dropped.
    fn enforce_caps(&mut self) -> io::Result<()> {
        while let Some(i) = select_victim(&self.entries, self.total_bytes, now_unix()) {
            let entry = self.entries.remove(i).expect("index from live iter");
            let _ = std::fs::remove_file(self.batch_path(entry.sequence));
            self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
            self.dropped_total = self.dropped_total.saturating_add(entry.events as u64);
            log::warn!(
                "[cloud] spool cap hit: dropped {} event(s) from batch {} (priority {:?})",
                entry.events,
                entry.sequence,
                entry.priority
            );
        }
        Ok(())
    }

    /// Oldest batch first (FIFO within the spool).
    pub fn oldest(&self) -> Option<SpoolEntryView<'_>> {
        self.entries.front().map(|e| SpoolEntryView {
            entry: e,
            path: self.batch_path(e.sequence),
        })
    }

    /// Remove a batch after the edge acknowledged it (200/202).
    pub fn remove(&mut self, sequence: u64) -> io::Result<()> {
        if let Some(i) = self.entries.iter().position(|e| e.sequence == sequence) {
            let entry = self.entries.remove(i).expect("position from live iter");
            let _ = std::fs::remove_file(self.batch_path(entry.sequence));
            self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
            self.persist()?;
        }
        Ok(())
    }

    /// Move a refused batch to quarantine with a note. Never retried.
    pub fn quarantine(&mut self, sequence: u64, reason: &str) -> io::Result<()> {
        let Some(i) = self.entries.iter().position(|e| e.sequence == sequence) else {
            return Ok(());
        };
        let entry = self.entries.remove(i).expect("position from live iter");
        let dest = self.quarantine_dir.join(batch_file_name(entry.sequence));
        let _ = std::fs::rename(self.batch_path(entry.sequence), &dest);
        let _ = std::fs::write(
            self.quarantine_dir.join(format!("{}.note", entry.sequence)),
            format!(
                "sequence: {}\ndigest: {}\nquarantined_at_unix: {}\nreason: {reason}\n",
                entry.sequence,
                entry.digest,
                now_unix()
            ),
        );
        self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
        self.persist()?;
        log::error!(
            "[cloud] batch {} quarantined ({} event(s)): {reason}; kept at {}",
            entry.sequence,
            entry.events,
            dest.display()
        );
        Ok(())
    }

    /// Pending event count across all spooled batches (heartbeat field).
    pub fn pending_events(&self) -> u64 {
        self.entries.iter().map(|e| e.events as u64).sum()
    }

    /// Cumulative locally-dropped events (heartbeat field).
    pub fn dropped_total(&self) -> u64 {
        self.dropped_total
    }

    pub fn batch_count(&self) -> usize {
        self.entries.len()
    }

    /// Read a spooled batch's bytes, verifying the digest.
    pub fn read(&self, sequence: u64) -> io::Result<Vec<u8>> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.sequence == sequence)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "batch not spooled"))?;
        let bytes = std::fs::read(self.batch_path(sequence))?;
        use sha2::Digest as _;
        let digest = hex::encode(sha2::Sha256::digest(&bytes));
        if digest != entry.digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("batch {sequence} failed digest check"),
            ));
        }
        Ok(bytes)
    }
}

/// A borrowed view of the oldest spooled batch for the sender.
pub struct SpoolEntryView<'a> {
    entry: &'a SpoolEntry,
    path: PathBuf,
}

impl SpoolEntryView<'_> {
    pub fn sequence(&self) -> u64 {
        self.entry.sequence
    }

    pub fn priority(&self) -> SpoolPriority {
        self.entry.priority
    }

    pub fn bytes_path(&self) -> &Path {
        &self.path
    }
}

fn batch_file_name(sequence: u64) -> String {
    format!("{sequence}.json")
}

/// Pick the next batch to drop when a cap is hit: lowest priority (highest
/// discriminant) first, then oldest — with the monotonic sequence as the
/// final tie-break so same-second seals are still deterministic.
/// Degradation-state batches are never candidates. Pure for testing.
fn select_victim(
    entries: &VecDeque<SpoolEntry>,
    total_bytes: u64,
    now_unix_secs: u64,
) -> Option<usize> {
    entries
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            e.priority != SpoolPriority::DegradationState
                && (total_bytes > SPOOL_MAX_BYTES
                    || now_unix_secs.saturating_sub(e.sealed_at_unix) > SPOOL_MAX_AGE_SECS)
        })
        .max_by(|(_, a), (_, b)| {
            a.priority
                .cmp(&b.priority)
                .then(b.sealed_at_unix.cmp(&a.sealed_at_unix))
                .then(b.sequence.cmp(&a.sequence))
        })
        .map(|(i, _)| i)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::super::model::{AttributionQuality, BatchEnvelope};
    use super::*;

    fn sealed(sequence: u64, event_count: usize) -> SealedBatch {
        let bytes = vec![b'x'; 64];
        SealedBatch {
            sequence,
            quality: AttributionQuality::Full,
            event_count,
            bytes,
            digest: {
                use sha2::Digest as _;
                hex::encode(sha2::Sha256::digest(vec![b'x'; 64]))
            },
        }
    }

    #[test]
    fn round_trip_and_digest_check() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = Spool::open(dir.path()).unwrap();
        let batch = sealed(3, 10);
        spool.store(&batch, SpoolPriority::Detection).unwrap();
        assert_eq!(spool.batch_count(), 1);
        assert_eq!(spool.pending_events(), 10);
        let read = spool.read(3).unwrap();
        assert_eq!(read, batch.bytes);
        spool.remove(3).unwrap();
        assert_eq!(spool.batch_count(), 0);
        assert_eq!(spool.pending_events(), 0);
    }

    #[test]
    fn spool_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut spool = Spool::open(dir.path()).unwrap();
            spool
                .store(&sealed(1, 5), SpoolPriority::Heartbeat)
                .unwrap();
            spool
                .store(&sealed(2, 7), SpoolPriority::Detection)
                .unwrap();
        }
        let spool = Spool::open(dir.path()).unwrap();
        assert_eq!(spool.batch_count(), 2);
        assert_eq!(spool.pending_events(), 12);
        assert_eq!(spool.oldest().unwrap().sequence(), 1);
    }

    fn entry(sequence: u64, priority: SpoolPriority, sealed_at_unix: u64) -> SpoolEntry {
        SpoolEntry {
            sequence,
            priority,
            digest: "d".to_string(),
            bytes: 64,
            events: 1,
            sealed_at_unix,
        }
    }

    #[test]
    fn victim_selection_prefers_low_priority_then_oldest() {
        let now = 1_700_000_000;
        let entries: VecDeque<SpoolEntry> = [
            entry(0, SpoolPriority::DegradationState, now),
            entry(1, SpoolPriority::Detection, now),
            entry(2, SpoolPriority::Heartbeat, now),
            entry(3, SpoolPriority::Heartbeat, now),
        ]
        .into_iter()
        .collect();
        // Over the size cap: oldest heartbeat first, never degradation.
        let over = SPOOL_MAX_BYTES + 1;
        assert_eq!(select_victim(&entries, over, now), Some(2));
        let mut without_oldest: VecDeque<SpoolEntry> = entries.clone().into_iter().collect();
        without_oldest.remove(2);
        // Detection outranks the remaining heartbeat... no: heartbeat is
        // lower priority, so the newer heartbeat still goes first.
        assert_eq!(select_victim(&without_oldest, over, now), Some(2)); // seq 3 now at index 2
        // Under the size cap but with an aged-out heartbeat: age cap fires.
        let aged: VecDeque<SpoolEntry> = [
            entry(0, SpoolPriority::DegradationState, now),
            entry(1, SpoolPriority::Detection, now),
            entry(2, SpoolPriority::Heartbeat, now - SPOOL_MAX_AGE_SECS - 1),
        ]
        .into_iter()
        .collect();
        assert_eq!(select_victim(&aged, 100, now), Some(2));
        // Nothing over any cap: no victim.
        let fresh: VecDeque<SpoolEntry> = [
            entry(
                0,
                SpoolPriority::DegradationState,
                now - SPOOL_MAX_AGE_SECS - 1,
            ),
            entry(1, SpoolPriority::Detection, now),
        ]
        .into_iter()
        .collect();
        assert_eq!(select_victim(&fresh, 100, now), None);
    }

    #[test]
    fn quarantine_moves_batch_out_of_the_drain_path() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = Spool::open(dir.path()).unwrap();
        spool
            .store(&sealed(9, 4), SpoolPriority::Detection)
            .unwrap();
        spool.quarantine(9, "409 conflict").unwrap();
        assert_eq!(spool.batch_count(), 0);
        assert!(spool.oldest().is_none());
        let note = std::fs::read_to_string(
            dir.path()
                .join(SPOOL_DIR_NAME)
                .join(QUARANTINE_DIR)
                .join("9.note"),
        )
        .unwrap();
        assert!(note.contains("409 conflict"));
    }

    #[test]
    fn batch_envelope_idempotency_key_uses_node_and_sequence() {
        assert_eq!(BatchEnvelope::idempotency_key("node_1", 42), "b:node_1:42");
    }
}
