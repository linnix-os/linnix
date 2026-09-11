//! Crash-safe on-disk spool for sealed batches.
//!
//! Durability model: every metadata write (manifest, quarantine notes) goes
//! through [`super::persist_durable`] — temp file, `sync_all`, atomic
//! rename, parent-directory fsync — so it survives process crashes *and*
//! host/power loss on filesystems that honor sync. Payload files are
//! written with `create_new` + `sync_all`, plus a directory fsync so the
//! directory entry is durable too. A crash between syncing a payload and
//! persisting the manifest can't strand evidence: every open reconciles
//! the manifest against the batch files on disk (orphans are re-admitted
//! after verification).
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
//!
//! Quarantine is bounded by the same envelope: quarantined bytes count
//! toward the 256 MiB cap, and quarantined batches older than 24h are
//! evicted oldest-first (with a diagnostic log; their `.note` is the
//! operator's record and is never deleted while the batch exists). Spool
//! batches are always evicted before quarantined ones — refused evidence is
//! more valuable for debugging than unsent heartbeats.
//!
//! A corrupt `spool.json` doesn't silently orphan evidence: the manifest is
//! rebuilt from the batch files on disk (each payload verified before
//! re-admission; files that fail verification are moved to quarantine with
//! a note explaining why).

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

/// A quarantined batch, indexed from the files on disk at open (the
/// quarantine directory itself is the source of truth, so a crash between
/// the file move and the manifest write can't lose the index).
#[derive(Debug, Clone)]
struct QuarantineEntry {
    sequence: u64,
    bytes: u64,
    events: usize,
    quarantined_at_unix: u64,
}

pub struct Spool {
    dir: PathBuf,
    manifest_path: PathBuf,
    quarantine_dir: PathBuf,
    entries: VecDeque<SpoolEntry>,
    total_bytes: u64,
    dropped_total: u64,
    quarantine_entries: VecDeque<QuarantineEntry>,
    quarantine_bytes: u64,
}

impl Spool {
    /// Open (or create) the spool in `state_dir/cloud_spool`, rebuilding the
    /// index from the manifest and dropping entries whose batch file is
    /// missing (e.g. torn write before the manifest fsync). A corrupt
    /// manifest is rebuilt from the batch files on disk instead of silently
    /// opening empty (which would orphan evidence the watermark may already
    /// have advanced past).
    pub fn open(state_dir: &Path) -> io::Result<Self> {
        let dir = state_dir.join(SPOOL_DIR_NAME);
        std::fs::create_dir_all(&dir)?;
        let quarantine_dir = dir.join(QUARANTINE_DIR);
        std::fs::create_dir_all(&quarantine_dir)?;
        let manifest_path = dir.join(MANIFEST_NAME);

        let mut manifest: Manifest = match std::fs::read_to_string(&manifest_path) {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(m) => m,
                Err(e) => {
                    log::error!(
                        "[cloud] spool manifest is corrupt ({e}); rebuilding from batch files on disk"
                    );
                    Self::rebuild_from_disk(&dir, &quarantine_dir)?
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => Manifest::default(),
            Err(e) => return Err(e),
        };
        // Reconcile the manifest against the batch files on disk on *every*
        // open, not just after a corrupt manifest: a crash between syncing
        // a payload and persisting the manifest leaves a valid manifest
        // plus an orphaned batch that would otherwise never be uploaded,
        // removed, or counted. Listed entries whose file is missing,
        // resized, or digest-drifted are dropped, repaired, or quarantined.
        Self::reconcile_with_disk(&mut manifest, &dir, &quarantine_dir)?;

        let quarantine_entries = Self::scan_quarantine(&quarantine_dir)?;
        let quarantine_bytes = quarantine_entries.iter().map(|e| e.bytes).sum();

        let total_bytes = manifest.entries.iter().map(|e| e.bytes).sum();
        let entries = manifest.entries.into_iter().collect();
        let mut spool = Self {
            dir,
            manifest_path,
            quarantine_dir,
            entries,
            total_bytes,
            dropped_total: manifest.dropped_total,
            quarantine_entries,
            quarantine_bytes,
        };
        // Enforce the caps on recovered state before the sender ever drains
        // it: an over-age or over-size spool from a previous run must be
        // evicted, not served. Then persist the reconciled, cap-enforced
        // manifest so the next open takes the fast path.
        spool.enforce_caps()?;
        spool.persist()?;
        Ok(spool)
    }

    /// Move an unverifiable batch file into quarantine with a note. A
    /// missing source is already-done (idempotent); anything else
    /// propagates — the caller must not index a file whose disposition is
    /// unknown.
    fn quarantine_file(
        path: &Path,
        quarantine_dir: &Path,
        seq: u64,
        reason: &str,
    ) -> io::Result<()> {
        let dest = quarantine_dir.join(batch_file_name(seq));
        match std::fs::rename(path, &dest) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                log::warn!("[cloud] spool: batch file {seq} vanished before quarantine; skipping");
                return Ok(());
            }
            Err(e) => return Err(e),
        }
        // The rename already succeeded, so the batch IS quarantined on
        // disk; a note-write failure propagates, but the next open's scan
        // recreates the note — the batch is never left un-noted.
        let note = format!(
            "sequence: {seq}\nquarantined_at_unix: {}\nreason: {reason}\n",
            now_unix()
        );
        super::persist_durable(&quarantine_dir.join(format!("{seq}.note")), note.as_bytes())?;
        log::warn!("[cloud] spool: quarantined batch file {seq} ({reason})");
        Ok(())
    }

    /// Reconcile a manifest against the batch files on disk.
    ///
    /// - Payload files not listed in the manifest (the crash window: payload
    ///   synced, manifest never persisted) are verified and re-admitted, or
    ///   quarantined with a note when they fail verification.
    /// - Listed entries whose file is missing are dropped.
    /// - Listed entries whose size or digest no longer matches the file are
    ///   re-verified: repaired from disk when the file is a valid batch,
    ///   quarantined with a note when it isn't.
    fn reconcile_with_disk(
        manifest: &mut Manifest,
        dir: &Path,
        quarantine_dir: &Path,
    ) -> io::Result<()> {
        let mut indexed: HashMap<u64, usize> = HashMap::new();
        for (i, e) in manifest.entries.iter().enumerate() {
            indexed.entry(e.sequence).or_insert(i);
        }
        let mut on_disk: Vec<(u64, PathBuf)> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let seq: u64 = name.strip_suffix(".json")?.parse().ok()?;
                Some((seq, e.path()))
            })
            .collect();
        on_disk.sort_by_key(|(seq, _)| *seq);

        // Sequences whose manifest entry survives this pass.
        let mut confirmed: HashSet<u64> = HashSet::new();
        for (seq, path) in on_disk {
            let survives = match indexed.get(&seq) {
                Some(&i) => {
                    let entry = &manifest.entries[i];
                    // Read once: size and digest are both checked against
                    // the manifest. Any drift means the file changed under
                    // us — re-verify before trusting it.
                    let disk = std::fs::read(&path);
                    let matches = match &disk {
                        Ok(bytes) => {
                            bytes.len() as u64 == entry.bytes
                                && hex::encode(Sha256::digest(bytes)) == entry.digest
                        }
                        Err(_) => false,
                    };
                    if matches {
                        true
                    } else {
                        match disk.map_err(|e| e.to_string()).and_then(|bytes| {
                            verify_batch_bytes(&bytes).map(|info| {
                                let digest = hex::encode(Sha256::digest(&bytes));
                                (bytes.len() as u64, digest, info)
                            })
                        }) {
                            Ok((actual_bytes, actual_digest, info)) => {
                                log::warn!(
                                    "[cloud] spool reconcile: repaired manifest entry for batch \
                                     {seq} (size/digest drifted on disk)"
                                );
                                let e = &mut manifest.entries[i];
                                e.bytes = actual_bytes;
                                e.digest = actual_digest;
                                e.events = info.events;
                                e.priority = info.priority;
                                true
                            }
                            Err(reason) => {
                                let claimed_events = manifest.entries[i].events;
                                Self::quarantine_file(
                                    &path,
                                    quarantine_dir,
                                    seq,
                                    &format!(
                                        "spool reconcile: listed batch failed re-verification: {reason}"
                                    ),
                                )?;
                                manifest.dropped_total =
                                    manifest.dropped_total.saturating_add(claimed_events as u64);
                                false
                            }
                        }
                    }
                }
                None => {
                    // Orphaned batch: the payload was synced but the
                    // manifest persist never landed.
                    match std::fs::read(&path)
                        .map_err(|e| e.to_string())
                        .and_then(|bytes| {
                            verify_batch_bytes(&bytes).map(|info| (bytes.len() as u64, info))
                        }) {
                        Ok((actual_bytes, info)) => {
                            log::warn!(
                                "[cloud] spool reconcile: re-admitting orphaned batch {seq} \
                                 ({} event(s))",
                                info.events
                            );
                            indexed.insert(seq, manifest.entries.len());
                            manifest.entries.push(SpoolEntry {
                                sequence: seq,
                                priority: info.priority,
                                digest: info.digest,
                                bytes: actual_bytes,
                                events: info.events,
                                sealed_at_unix: file_mtime_unix(&path),
                            });
                            true
                        }
                        Err(reason) => {
                            Self::quarantine_file(
                                &path,
                                quarantine_dir,
                                seq,
                                &format!(
                                    "spool reconcile: orphaned batch failed verification: {reason}"
                                ),
                            )?;
                            false
                        }
                    }
                }
            };
            if survives {
                confirmed.insert(seq);
            }
        }
        let before = manifest.entries.len();
        manifest.entries.retain(|e| confirmed.contains(&e.sequence));
        let dropped = before - manifest.entries.len();
        if dropped > 0 {
            log::warn!(
                "[cloud] spool reconcile: dropped {dropped} manifest entr(ies) with no surviving file"
            );
        }
        manifest.entries.sort_by_key(|e| e.sequence);
        Ok(())
    }

    /// Rebuild the manifest from `{sequence}.json` files on disk. Every
    /// payload is verified before re-admission; files that fail verification
    /// are moved to quarantine with a note (skip-and-note) rather than being
    /// silently dropped or blindly trusted.
    fn rebuild_from_disk(dir: &Path, quarantine_dir: &Path) -> io::Result<Manifest> {
        let mut sequences: Vec<(u64, PathBuf)> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let seq: u64 = name.strip_suffix(".json")?.parse().ok()?;
                Some((seq, e.path()))
            })
            .collect();
        sequences.sort_by_key(|(seq, _)| *seq);

        let mut manifest = Manifest::default();
        for (seq, path) in sequences {
            let bytes = std::fs::read(&path)?;
            match verify_batch_bytes(&bytes) {
                Ok(info) => {
                    manifest.entries.push(SpoolEntry {
                        sequence: seq,
                        priority: info.priority,
                        digest: info.digest,
                        bytes: bytes.len() as u64,
                        events: info.events,
                        sealed_at_unix: file_mtime_unix(&path),
                    });
                }
                Err(reason) => {
                    Self::quarantine_file(
                        &path,
                        quarantine_dir,
                        seq,
                        &format!("spool rebuild: skipped unreadable batch: {reason}"),
                    )?;
                }
            }
        }
        log::warn!(
            "[cloud] spool rebuild complete: re-admitted {} batch(es); dropped_total reset",
            manifest.entries.len()
        );
        Ok(manifest)
    }

    /// Index the quarantine directory from disk. Every batch gets a note if
    /// it lacks one — a quarantined batch is never deleted un-noted.
    fn scan_quarantine(quarantine_dir: &Path) -> io::Result<VecDeque<QuarantineEntry>> {
        let mut out: Vec<QuarantineEntry> = Vec::new();
        for entry in std::fs::read_dir(quarantine_dir)? {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(seq) = name
                .strip_suffix(".json")
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            let bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
            let note_path = quarantine_dir.join(format!("{seq}.note"));
            let quarantined_at = std::fs::read_to_string(&note_path)
                .ok()
                .and_then(|note| parse_note_field(&note, "quarantined_at_unix"))
                .unwrap_or_else(|| file_mtime_unix(&entry.path()));
            if !note_path.exists() {
                // A quarantined batch is never left un-noted; the write
                // propagates — without the note we can't prove the
                // quarantine later.
                std::fs::write(
                    &note_path,
                    format!(
                        "sequence: {seq}\nquarantined_at_unix: {quarantined_at}\n\
                         reason: recovered at startup; original refusal reason unknown\n"
                    ),
                )?;
            }
            let events = std::fs::read(entry.path())
                .ok()
                .and_then(|b| verify_batch_bytes(&b).ok())
                .map(|info| info.events)
                .unwrap_or(0);
            out.push(QuarantineEntry {
                sequence: seq,
                bytes,
                events,
                quarantined_at_unix: quarantined_at,
            });
        }
        out.sort_by(|a, b| {
            a.quarantined_at_unix
                .cmp(&b.quarantined_at_unix)
                .then(a.sequence.cmp(&b.sequence))
        });
        Ok(out.into())
    }

    /// Durable manifest persist: temp file + file sync + atomic rename +
    /// parent-directory fsync (see [`super::persist_durable`]), so a host or
    /// power loss can't roll the manifest back or leave it torn.
    fn persist(&self) -> io::Result<()> {
        let manifest = Manifest {
            entries: self.entries.iter().cloned().collect(),
            dropped_total: self.dropped_total,
        };
        let bytes = serde_json::to_string_pretty(&manifest).unwrap();
        super::persist_durable(&self.manifest_path, bytes.as_bytes())
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
        drop(file);
        // Sync the directory entry too: without this a power loss can lose
        // the payload file itself, which the manifest (persisted later)
        // would then reference.
        super::sync_dir(&self.dir)?;

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
    /// Degradation-state batches are never dropped. Quarantined batches
    /// count toward the byte cap and are evicted oldest-first when they age
    /// out or when the spool alone can't get back under the cap.
    fn enforce_caps(&mut self) -> io::Result<()> {
        let now = now_unix();
        while let Some(i) = select_victim(&self.entries, self.total_bytes_used(), now) {
            // The file goes first: only after the filesystem confirms the
            // deletion does the index stop describing the batch. A missing
            // file is already-done (idempotent); anything else aborts the
            // eviction so the index never claims a deletion that didn't
            // happen — the batch stays queued and is retried next pass.
            let sequence = self.entries[i].sequence;
            remove_file_if_exists(&self.batch_path(sequence))?;
            let entry = self.entries.remove(i).expect("index from live iter");
            self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
            self.dropped_total = self.dropped_total.saturating_add(entry.events as u64);
            log::warn!(
                "[cloud] spool cap hit: dropped {} event(s) from batch {} (priority {:?})",
                entry.events,
                entry.sequence,
                entry.priority
            );
        }
        self.enforce_quarantine_caps_at(now)
    }

    /// Spool + quarantine bytes: the cap both share.
    fn total_bytes_used(&self) -> u64 {
        self.total_bytes.saturating_add(self.quarantine_bytes)
    }

    /// Evict quarantined batches oldest-first when one is older than 24h or
    /// the shared byte cap is still exceeded. Every evicted batch is noted
    /// (its `.note` was written at quarantine/scan time) and the eviction
    /// is logged as the diagnostic trail.
    fn enforce_quarantine_caps_at(&mut self, now: u64) -> io::Result<()> {
        while let Some(i) =
            select_quarantine_victim(&self.quarantine_entries, self.total_bytes_used(), now)
        {
            // Ensure the note exists *before* deleting anything: a
            // quarantined batch is never deleted un-noted. The write
            // propagates — without the note we can't prove the eviction
            // later, so the batch stays.
            let note_path = self
                .quarantine_dir
                .join(format!("{}.note", self.quarantine_entries[i].sequence));
            if !note_path.exists() {
                std::fs::write(
                    &note_path,
                    format!(
                        "sequence: {}\nquarantined_at_unix: {}\n\
                         reason: recovered at eviction; original refusal reason unknown\n",
                        self.quarantine_entries[i].sequence,
                        self.quarantine_entries[i].quarantined_at_unix,
                    ),
                )?;
            }
            let q = self
                .quarantine_entries
                .remove(i)
                .expect("index from live iter");
            remove_file_if_exists(&self.quarantine_dir.join(batch_file_name(q.sequence)))?;
            remove_file_if_exists(&note_path)?;
            self.quarantine_bytes = self.quarantine_bytes.saturating_sub(q.bytes);
            self.dropped_total = self.dropped_total.saturating_add(q.events as u64);
            log::error!(
                "[cloud] quarantine retention: evicted quarantined batch {} \
                 ({} event(s), {} bytes) — age/size cap",
                q.sequence,
                q.events,
                q.bytes
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

    /// Remove a batch after the edge acknowledged it (200/202). The file is
    /// deleted first; the index and manifest follow only once the filesystem
    /// confirms it. A delete failure propagates and the batch stays queued.
    pub fn remove(&mut self, sequence: u64) -> io::Result<()> {
        if let Some(i) = self.entries.iter().position(|e| e.sequence == sequence) {
            remove_file_if_exists(&self.batch_path(sequence))?;
            let entry = self.entries.remove(i).expect("position from live iter");
            self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
            self.persist()?;
        }
        Ok(())
    }

    /// Move a refused batch to quarantine with a note. Never retried; the
    /// quarantine directory is bounded by the same retention envelope as
    /// the spool (see [`Spool::enforce_quarantine_caps_at`]).
    ///
    /// The rename happens before any in-memory change: only after the
    /// filesystem confirms the move does the index follow. A rename failure
    /// propagates and the batch stays queued for retry; a missing source is
    /// already-done (the entry is dropped, since the batch can't be read
    /// anyway).
    pub fn quarantine(&mut self, sequence: u64, reason: &str) -> io::Result<()> {
        let Some(i) = self.entries.iter().position(|e| e.sequence == sequence) else {
            return Ok(());
        };
        let src = self.batch_path(sequence);
        let dest = self.quarantine_dir.join(batch_file_name(sequence));
        match std::fs::rename(&src, &dest) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                log::warn!(
                    "[cloud] batch {sequence} already gone from spool; dropping its index entry"
                );
                let entry = self.entries.remove(i).expect("position from live iter");
                self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
                self.persist()?;
                return Ok(());
            }
            Err(e) => return Err(e),
        }
        // The rename succeeded: on disk the batch IS quarantined, so the
        // index follows. A note-write failure propagates, but the next
        // open's scan recreates the note — the batch is never lost un-noted.
        let entry = self.entries.remove(i).expect("position from live iter");
        super::persist_durable(
            &self.quarantine_dir.join(format!("{}.note", entry.sequence)),
            format!(
                "sequence: {}\ndigest: {}\nquarantined_at_unix: {}\nreason: {reason}\n",
                entry.sequence,
                entry.digest,
                now_unix()
            )
            .as_bytes(),
        )?;
        self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
        self.quarantine_bytes = self.quarantine_bytes.saturating_add(entry.bytes);
        self.quarantine_entries.push_back(QuarantineEntry {
            sequence: entry.sequence,
            bytes: entry.bytes,
            events: entry.events,
            quarantined_at_unix: now_unix(),
        });
        self.enforce_quarantine_caps_at(now_unix())?;
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

    /// Test hooks: quarantine observability.
    #[cfg(test)]
    pub fn quarantine_batch_count(&self) -> usize {
        self.quarantine_entries.len()
    }

    #[cfg(test)]
    pub fn quarantine_bytes_used(&self) -> u64 {
        self.quarantine_bytes
    }

    #[cfg(test)]
    pub fn total_bytes_used_for_test(&self) -> u64 {
        self.total_bytes_used()
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

/// Delete a file that should be gone. A missing file is already-done
/// (idempotent); any other error propagates so the caller can't update its
/// index as if the deletion had happened.
fn remove_file_if_exists(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// What `verify_batch_bytes` recovers from a payload on disk.
struct BatchInfo {
    digest: String,
    events: usize,
    priority: SpoolPriority,
}

/// Verify a batch payload well enough to re-admit it after a corrupt
/// manifest: valid JSON, the envelope's idempotency key, and an events
/// array. Priority is inferred from the event types present (a batch that
/// carried a degradation_state keeps its never-drop protection).
fn verify_batch_bytes(bytes: &[u8]) -> Result<BatchInfo, String> {
    let v: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid JSON: {e}"))?;
    if v.get("batch_idempotency_key")
        .and_then(|k| k.as_str())
        .is_none()
    {
        return Err("missing batch_idempotency_key".to_string());
    }
    let events = v
        .get("events")
        .and_then(|e| e.as_array())
        .ok_or_else(|| "missing events array".to_string())?;
    let mut has_detection = false;
    let mut has_degradation = false;
    for e in events {
        match e.get("event_type").and_then(|t| t.as_str()) {
            Some("degradation_state") => has_degradation = true,
            Some("detection") => has_detection = true,
            _ => {}
        }
    }
    let priority = if has_degradation {
        SpoolPriority::DegradationState
    } else if has_detection {
        SpoolPriority::Detection
    } else {
        SpoolPriority::Heartbeat
    };
    Ok(BatchInfo {
        digest: hex::encode(Sha256::digest(bytes)),
        events: events.len(),
        priority,
    })
}

/// Parse a `key: value` line out of a quarantine `.note` file.
fn parse_note_field(note: &str, key: &str) -> Option<u64> {
    note.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        if k.trim() == key {
            v.trim().parse::<u64>().ok()
        } else {
            None
        }
    })
}

fn file_mtime_unix(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or_else(now_unix)
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

/// Pick the next quarantined batch to evict: oldest first (by quarantine
/// time, then sequence), but only when it's older than 24h or the shared
/// byte cap is exceeded. Pure for testing.
fn select_quarantine_victim(
    entries: &VecDeque<QuarantineEntry>,
    total_bytes_used: u64,
    now_unix_secs: u64,
) -> Option<usize> {
    entries
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            total_bytes_used > SPOOL_MAX_BYTES
                || now_unix_secs.saturating_sub(e.quarantined_at_unix) > SPOOL_MAX_AGE_SECS
        })
        .min_by(|(_, a), (_, b)| {
            a.quarantined_at_unix
                .cmp(&b.quarantined_at_unix)
                .then(a.sequence.cmp(&b.sequence))
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

    fn qentry(sequence: u64, quarantined_at_unix: u64) -> QuarantineEntry {
        QuarantineEntry {
            sequence,
            bytes: 64,
            events: 2,
            quarantined_at_unix,
        }
    }

    #[test]
    fn quarantine_victim_selection_is_oldest_first() {
        let now = 1_700_000_000;
        let entries: VecDeque<QuarantineEntry> =
            [qentry(5, now), qentry(3, now - 10), qentry(7, now - 10)]
                .into_iter()
                .collect();
        // Over the shared size cap: oldest first, sequence breaks ties.
        assert_eq!(
            select_quarantine_victim(&entries, SPOOL_MAX_BYTES + 1, now),
            Some(1)
        );
        // Aged-out entry evicted even under the size cap.
        let aged: VecDeque<QuarantineEntry> =
            [qentry(5, now), qentry(6, now - SPOOL_MAX_AGE_SECS - 1)]
                .into_iter()
                .collect();
        assert_eq!(select_quarantine_victim(&aged, 100, now), Some(1));
        // Fresh and under the cap: no victim.
        let fresh: VecDeque<QuarantineEntry> =
            [qentry(5, now), qentry(6, now)].into_iter().collect();
        assert_eq!(select_quarantine_victim(&fresh, 100, now), None);
    }

    #[test]
    fn quarantine_bytes_count_toward_the_shared_cap() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = Spool::open(dir.path()).unwrap();
        spool
            .store(&sealed(11, 4), SpoolPriority::Detection)
            .unwrap();
        assert_eq!(spool.total_bytes_used_for_test(), 64);
        spool.quarantine(11, "409 conflict").unwrap();
        assert_eq!(spool.batch_count(), 0);
        assert_eq!(spool.quarantine_batch_count(), 1);
        // The bytes moved with the batch: the cap still sees them.
        assert_eq!(spool.quarantine_bytes_used(), 64);
        assert_eq!(spool.total_bytes_used_for_test(), 64);
        // The batch file and its note survived the move.
        let qdir = dir.path().join(SPOOL_DIR_NAME).join(QUARANTINE_DIR);
        assert!(qdir.join("11.json").exists());
        assert!(qdir.join("11.note").exists());
    }

    #[test]
    fn quarantine_index_rebuilt_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let qdir = dir.path().join(SPOOL_DIR_NAME).join(QUARANTINE_DIR);
        std::fs::create_dir_all(&qdir).unwrap();
        // A quarantined batch with a note, as quarantine() would leave it.
        // (The note's timestamp must be fresh: open() now enforces the 24h
        // quarantine age cap, so an ancient fixture would be evicted.)
        let bytes = br#"{"batch_idempotency_key":"b:n:21","events":[{"event_type":"detection"}]}"#;
        std::fs::write(qdir.join("21.json"), bytes).unwrap();
        std::fs::write(
            qdir.join("21.note"),
            format!(
                "sequence: 21\ndigest: d\nquarantined_at_unix: {}\nreason: 409\n",
                now_unix()
            ),
        )
        .unwrap();
        // And one without a note: open must note it (never delete un-noted).
        std::fs::write(qdir.join("22.json"), bytes).unwrap();

        let spool = Spool::open(dir.path()).unwrap();
        assert_eq!(spool.quarantine_batch_count(), 2);
        assert_eq!(spool.quarantine_bytes_used(), bytes.len() as u64 * 2);
        assert!(
            qdir.join("22.note").exists(),
            "recovered batch must be noted"
        );
    }

    #[test]
    fn corrupt_manifest_rebuilds_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join(SPOOL_DIR_NAME);
        std::fs::create_dir_all(&spool_dir).unwrap();
        // A valid sealed batch on disk...
        let good = serde_json::json!({
            "schema_version": "1.0.0",
            "batch_idempotency_key": "b:n:5",
            "events": [
                {"event_id": "e1", "event_type": "detection"},
                {"event_id": "e2", "event_type": "heartbeat"}
            ]
        });
        std::fs::write(spool_dir.join("5.json"), serde_json::to_vec(&good).unwrap()).unwrap();
        // ...a corrupt one...
        std::fs::write(spool_dir.join("6.json"), b"not json at all").unwrap();
        // ...and a corrupt manifest.
        std::fs::write(spool_dir.join(MANIFEST_NAME), b"{truncated").unwrap();

        let spool = Spool::open(dir.path()).unwrap();
        // The valid batch was re-admitted with its digest recomputed; the
        // corrupt file was skip-and-noted into quarantine.
        assert_eq!(spool.batch_count(), 1);
        let read = spool.read(5).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&read).unwrap();
        assert_eq!(v["batch_idempotency_key"], "b:n:5");
        assert_eq!(spool.quarantine_batch_count(), 1);
        let qdir = spool_dir.join(QUARANTINE_DIR);
        assert!(qdir.join("6.json").exists());
        let note = std::fs::read_to_string(qdir.join("6.note")).unwrap();
        assert!(note.contains("spool rebuild"), "note explains why: {note}");
        // The rebuilt manifest is valid: a second open takes the fast path.
        drop(spool);
        let reopened = Spool::open(dir.path()).unwrap();
        assert_eq!(reopened.batch_count(), 1);
        assert_eq!(reopened.quarantine_batch_count(), 1);
    }

    #[test]
    fn corrupt_manifest_with_no_batch_files_opens_empty() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join(SPOOL_DIR_NAME);
        std::fs::create_dir_all(&spool_dir).unwrap();
        std::fs::write(spool_dir.join(MANIFEST_NAME), b"\x00\x01 garbage").unwrap();
        let spool = Spool::open(dir.path()).unwrap();
        assert_eq!(spool.batch_count(), 0);
        assert_eq!(spool.quarantine_batch_count(), 0);
    }

    fn valid_batch_bytes(seq: u64, event_count: usize) -> Vec<u8> {
        let events: Vec<_> = (0..event_count)
            .map(|i| serde_json::json!({"event_id": format!("e{i}"), "event_type": "detection"}))
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "schema_version": "1.0.0",
            "batch_idempotency_key": format!("b:n:{seq}"),
            "events": events,
        }))
        .unwrap()
    }

    #[test]
    fn reconcile_readmits_orphan_batch_with_valid_manifest() {
        // The crash window: payload synced, manifest persist never landed.
        let dir = tempfile::tempdir().unwrap();
        {
            let mut spool = Spool::open(dir.path()).unwrap();
            spool
                .store(&sealed(1, 5), SpoolPriority::Heartbeat)
                .unwrap();
        }
        // An orphaned payload appears on disk with the manifest untouched.
        let orphan = valid_batch_bytes(2, 3);
        std::fs::write(dir.path().join(SPOOL_DIR_NAME).join("2.json"), &orphan).unwrap();

        let spool = Spool::open(dir.path()).unwrap();
        assert_eq!(spool.batch_count(), 2, "orphan must be re-admitted");
        assert_eq!(spool.read(2).unwrap(), orphan);
        // The reconciled manifest was persisted: a second open agrees.
        drop(spool);
        let reopened = Spool::open(dir.path()).unwrap();
        assert_eq!(reopened.batch_count(), 2);
    }

    #[test]
    fn reconcile_repairs_drifted_but_valid_batch() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut spool = Spool::open(dir.path()).unwrap();
            spool
                .store(&sealed(1, 5), SpoolPriority::Heartbeat)
                .unwrap();
        }
        // The file on disk is replaced by different-but-valid batch bytes
        // (size and digest drift from the manifest).
        let replacement = valid_batch_bytes(1, 4);
        std::fs::write(dir.path().join(SPOOL_DIR_NAME).join("1.json"), &replacement).unwrap();

        let spool = Spool::open(dir.path()).unwrap();
        assert_eq!(spool.batch_count(), 1);
        // The manifest entry was repaired: the digest check passes on the
        // new bytes.
        assert_eq!(spool.read(1).unwrap(), replacement);
        assert_eq!(spool.pending_events(), 4);
    }

    #[test]
    fn reconcile_quarantines_listed_batch_that_fails_reverification() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut spool = Spool::open(dir.path()).unwrap();
            spool
                .store(&sealed(1, 5), SpoolPriority::Heartbeat)
                .unwrap();
        }
        // Torn write: the file no longer parses.
        std::fs::write(dir.path().join(SPOOL_DIR_NAME).join("1.json"), b"{torn").unwrap();

        let spool = Spool::open(dir.path()).unwrap();
        assert_eq!(
            spool.batch_count(),
            0,
            "unverifiable batch leaves the index"
        );
        assert_eq!(spool.quarantine_batch_count(), 1);
        let note = std::fs::read_to_string(
            dir.path()
                .join(SPOOL_DIR_NAME)
                .join(QUARANTINE_DIR)
                .join("1.note"),
        )
        .unwrap();
        assert!(note.contains("reconcile"), "note explains why: {note}");
    }

    #[test]
    fn reopen_enforces_age_cap_on_recovered_state() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut spool = Spool::open(dir.path()).unwrap();
            spool
                .store(&sealed(1, 5), SpoolPriority::Heartbeat)
                .unwrap();
        }
        // Age the manifest entry to the epoch: a recovered spool older than
        // 24h must be evicted at open, not served to the sender.
        let manifest_path = dir.path().join(SPOOL_DIR_NAME).join(MANIFEST_NAME);
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        manifest["entries"][0]["sealed_at_unix"] = serde_json::json!(0);
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

        let spool = Spool::open(dir.path()).unwrap();
        assert_eq!(
            spool.batch_count(),
            0,
            "over-age batch must be evicted at open"
        );
        assert_eq!(spool.dropped_total(), 5);
        assert!(
            !dir.path().join(SPOOL_DIR_NAME).join("1.json").exists(),
            "evicted batch file must be gone"
        );
    }

    #[test]
    fn remove_propagates_fs_errors_without_desync() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = Spool::open(dir.path()).unwrap();
        spool
            .store(&sealed(1, 5), SpoolPriority::Heartbeat)
            .unwrap();
        // Failure injection that works even as root: a directory where the
        // batch file should be makes remove_file fail with a non-NotFound
        // error.
        let batch_path = dir.path().join(SPOOL_DIR_NAME).join("1.json");
        std::fs::remove_file(&batch_path).unwrap();
        std::fs::create_dir(&batch_path).unwrap();

        let err = spool.remove(1).unwrap_err();
        assert_ne!(err.kind(), io::ErrorKind::NotFound);
        // The failure must not desync the index: the batch is still queued
        // with its accounting intact, so a later retry can finish the ack.
        assert_eq!(spool.batch_count(), 1);
        assert_eq!(spool.total_bytes_used_for_test(), 64);
    }

    #[test]
    fn quarantine_propagates_rename_collision() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = Spool::open(dir.path()).unwrap();
        spool
            .store(&sealed(1, 5), SpoolPriority::Heartbeat)
            .unwrap();
        // Block the rename target with a directory: rename fails, the error
        // propagates, and the batch stays queued (never half-moved).
        let qdir = dir.path().join(SPOOL_DIR_NAME).join(QUARANTINE_DIR);
        std::fs::create_dir(qdir.join("1.json")).unwrap();

        let err = spool.quarantine(1, "409 conflict").unwrap_err();
        assert_ne!(err.kind(), io::ErrorKind::NotFound);
        assert_eq!(
            spool.batch_count(),
            1,
            "failed quarantine must not drop the batch"
        );
        assert_eq!(spool.quarantine_batch_count(), 0);
        assert_eq!(spool.total_bytes_used_for_test(), 64);
    }

    #[test]
    fn quarantine_with_vanished_source_drops_the_index_entry() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = Spool::open(dir.path()).unwrap();
        spool
            .store(&sealed(1, 5), SpoolPriority::Heartbeat)
            .unwrap();
        // The payload vanished between oldest() and quarantine(): NotFound
        // is already-done — drop the entry rather than wedging the drain.
        std::fs::remove_file(dir.path().join(SPOOL_DIR_NAME).join("1.json")).unwrap();
        spool.quarantine(1, "409 conflict").unwrap();
        assert_eq!(spool.batch_count(), 0);
        assert_eq!(spool.quarantine_batch_count(), 0);
    }
}
