//! Userspace block-IO stall-victim detector: no eBPF, no privileges beyond /proc.
//!
//! A process stuck waiting on storage shows up in two places a normal user
//! can read: its `wchan` names the kernel wait point, and
//! `/proc/<pid>/io` accounts the bytes it actually moved. Neither is exact
//! — `wchan` is a sampled point-in-time peek, not a delay account — so this
//! monitor runs at the spec's tier B and labels everything accordingly.
//!
//! Design:
//!
//! * **Signal (inferred):** every 2s, each thread's `wchan` is classified
//!   and aggregated to the process — a poll counts as a block-wait sample
//!   when *any* thread is observed in a block-layer wait (`io_schedule`,
//!   `wait_on_page_bit` family, `blkdev_issue_*`, `get_request*`), since
//!   `/proc/<pid>/wchan` alone only reflects the thread-group leader.
//!   The finding is the fraction of samples in a 60s sliding window in
//!   which the process was observed waiting on block IO. Warn at >= 50%,
//!   critical at >= 80% — sustained, not a passing read.
//! * **Cross-check (measured when readable):** `/proc/<pid>/io`
//!   `read_bytes`/`write_bytes` deltas ride along in the snapshot,
//!   computed newest-minus-oldest *inside* the window from timestamped
//!   samples. Bytes moving while wchan says "waiting" is the normal shape
//!   of an IO-heavy victim; bytes *not* moving across the whole window is
//!   worse — possibly hung storage — and the report line says so, but only
//!   when the counters were actually read: unreadable counters are labeled
//!   `unavailable`, never fabricated as zero. The cross-check never gates
//!   the finding: a stuck task is still a stall.
//! * **Warm-up honesty:** the percentage is normalized against the full
//!   window's expected sample count (30), not the samples observed so far,
//!   so a short-lived burst can't inflate into a verdict — same lesson as
//!   the fork monitor's review fix. New processes accumulate samples from
//!   zero and converge to their true fraction.
//! * **Cost:** one `task`-dir listing plus one `wchan` read per thread per
//!   2s poll (tiny files, microseconds each; the scan stops at the first
//!   block-wait found, so stalled processes cost a partial scan).
//!   Per-process thread scans are capped at 1024 lowest tids — the cap
//!   only engages on pathological thread counts, and the scan repeats
//!   every poll. `io` is read only for processes with at least one
//!   block-wait sample in the window (suspects), so idle hosts pay almost
//!   nothing. Per-pid state is pruned by window age, so exited processes
//!   are forgotten within 60s.
//! * **Tier A upgrade path:** taskstats netlink gives exact per-task delay
//!   accounting (`blkio_delay_total`) and would make the wait `measured`.
//!   It needs a dedicated netlink thread; the sampled fraction here is the
//!   honest tier-B version.
//!
//! Findings become `blkio_stall` incidents via the same store-backed dedup
//! discipline as the other monitors: the incident store — not the bounded
//! in-memory warn map — is the source of truth for what was already
//! persisted, so map eviction and daemon restarts cannot duplicate rows.

use log::{debug, info, warn};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::incidents::{Incident, IncidentStore};

/// Sliding window over which block-wait samples are counted.
const WINDOW: Duration = Duration::from_secs(60);
/// Fraction of window samples in block-layer wait at or above which a
/// warning fires: half the window observed waiting on storage.
const WARN_WAIT_PCT: f64 = 50.0;
/// Fraction at or above which a critical fires.
const CRIT_WAIT_PCT: f64 = 80.0;
/// Default quiet period between repeat warnings for the same victim+verdict,
/// mirroring the other monitors.
const DEFAULT_WARN_COOLDOWN: Duration = Duration::from_secs(15 * 60);
/// Cap on the warn-cooldown map; oldest entries are evicted past this.
const MAX_COOLDOWN_ENTRIES: usize = 1024;
/// How many distinct block-wait kinds ride along in the incident snapshot.
const TOP_WCHAN_KINDS: usize = 4;
/// Cap on threads scanned per process per poll for the wchan sample.
/// One wchan read is microseconds, but a pathological 100k-thread process
/// must not stall the 2s loop: lowest tids first (deterministic; thread
/// IDs are allocated densely from the leader, so the cap only engages on
/// absurd thread counts), and the scan repeats every poll anyway.
const MAX_WCHAN_THREADS_PER_POLL: usize = 1024;

/// What a process's sampled block-IO wait fraction means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlkioVerdict {
    Healthy,
    /// Process observed waiting on block IO in >= 50% of window samples.
    /// Storage is its bottleneck (or its workload is purely IO-bound —
    /// correlate with the workload before paging).
    BlkioWarning,
    /// 80% or more of samples waiting: the process is effectively stalled
    /// on storage.
    BlkioCritical,
}

impl BlkioVerdict {
    /// `false` for `Healthy`; used to filter log/report noise.
    pub fn actionable(self) -> bool {
        !matches!(self, BlkioVerdict::Healthy)
    }
}

/// One actionable block-IO stall finding for a scan window.
#[derive(Debug, Clone)]
pub struct BlkioStall {
    pub pid: u32,
    pub comm: Option<String>,
    /// % of the window's expected samples observed in block-layer wait.
    pub wait_pct: f64,
    /// Seconds the window covers.
    pub window_secs: f64,
    /// Block-wait samples actually observed (numerator of `wait_pct`).
    pub wait_samples: u32,
    /// Samples a full window holds (denominator of `wait_pct`).
    pub expected_samples: u32,
    /// `/proc/<pid>/io` deltas across the suspect window, for the
    /// cross-check: bytes moving vs. not. `None` when the counters were
    /// never successfully read inside the window (unreadable or raced
    /// with process exit) — absence is not zero, and the snapshot labels
    /// it `unavailable` instead of fabricating a zero delta.
    pub io_bytes_delta: Option<(u64, u64)>,
    /// Observed block-wait kinds and their sample counts, most common first.
    pub wchan_kinds: Vec<(String, u32)>,
    pub verdict: BlkioVerdict,
}

impl BlkioStall {
    /// Stable identity for cooldown and incident-dedup keys: the process
    /// plus its command name. PIDs are unique per process system-wide, so
    /// this distinguishes two `postgres` backends where a comm-only key
    /// suppressed every same-named process for the whole cooldown. A
    /// recycled PID's counters regress, which re-baselines the
    /// measurement — and the store keys the verdict to this identity, so
    /// the new process dedups against its own history, not another
    /// victim's.
    fn victim_label(&self) -> String {
        let comm = self.comm.clone().unwrap_or_else(|| "unknown".to_string());
        format!("{comm} (pid={})", self.pid)
    }
}

fn classify(wait_pct: f64) -> BlkioVerdict {
    if wait_pct >= CRIT_WAIT_PCT {
        BlkioVerdict::BlkioCritical
    } else if wait_pct >= WARN_WAIT_PCT {
        BlkioVerdict::BlkioWarning
    } else {
        BlkioVerdict::Healthy
    }
}

/// Classifies a `wchan` value: `Some` canonical kind when the task was
/// observed waiting in the block layer, `None` otherwise. Best-effort by
/// construction — `wchan` is a sampled peek, and filesystem-specific waits
/// usually funnel through `io_schedule`/`wait_on_page_bit` anyway.
///
/// Recognized families:
/// * `io_schedule[_timeout]` — the generic block-layer sleep.
/// * `wait_on_page*` — `wait_on_page_bit[_killable]` (file *and* swap cache
///   page waits — this is the swapin signal too), `wait_on_page_writeback`.
/// * `blkdev_issue*` — flush/zeroout/discard submission waits.
/// * `get_request*` — request-queue waits (older kernels).
fn blkio_wait_kind(wchan: &str) -> Option<&'static str> {
    let w = wchan.trim();
    if w.is_empty() || w == "0" {
        // "0" means running (or wchan disabled) — not waiting.
        return None;
    }
    if w.contains("io_schedule") {
        Some("io_schedule")
    } else if w.starts_with("wait_on_page") {
        Some("wait_on_page")
    } else if w.starts_with("blkdev_issue") {
        Some("blkio_issue")
    } else if w.starts_with("get_request") {
        Some("get_request")
    } else {
        None
    }
}

/// Thread IDs for a process. Falls back to the leader alone when the
/// `task` directory can't be listed (a thread exiting mid-scan, or a
/// fixture tree without per-thread files).
fn list_tids(proc_root: &Path, pid: u32) -> Vec<u32> {
    let task_dir = proc_root.join(pid.to_string()).join("task");
    let Ok(entries) = std::fs::read_dir(&task_dir) else {
        return vec![pid];
    };
    let mut tids: Vec<u32> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .collect();
    if tids.is_empty() {
        tids.push(pid);
    }
    tids.sort_unstable();
    tids
}

/// One thread's `wchan`. The leader's file is also visible at the plain
/// pid path; worker threads live under `task/<tid>/`.
fn read_thread_wchan(proc_root: &Path, pid: u32, tid: u32) -> Option<String> {
    let path = if tid == pid {
        proc_root.join(pid.to_string()).join("wchan")
    } else {
        proc_root
            .join(pid.to_string())
            .join("task")
            .join(tid.to_string())
            .join("wchan")
    };
    std::fs::read_to_string(path).ok()
}

fn read_comm(proc_root: &Path, pid: u32) -> Option<String> {
    std::fs::read_to_string(proc_root.join(pid.to_string()).join("comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// `(read_bytes, write_bytes)` from `/proc/<pid>/io`. `None` when the file
/// is missing or unparseable — absence is not zero.
fn read_io_bytes(proc_root: &Path, pid: u32) -> Option<(u64, u64)> {
    let content = std::fs::read_to_string(proc_root.join(pid.to_string()).join("io")).ok()?;
    let mut read_bytes = None;
    let mut write_bytes = None;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("read_bytes:") {
            read_bytes = rest.trim().parse::<u64>().ok();
        } else if let Some(rest) = line.strip_prefix("write_bytes:") {
            write_bytes = rest.trim().parse::<u64>().ok();
        }
    }
    Some((read_bytes?, write_bytes?))
}

/// Numeric `/proc` entries: the live PID set.
fn list_pids(proc_root: &Path) -> Vec<u32> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if let Ok(pid) = name_str.parse::<u32>() {
            out.push(pid);
        }
    }
    out
}

/// IO-byte baseline for a suspect process: timestamped
/// `(sampled_at, read_bytes, write_bytes)` counter samples inside the
/// sliding window. The reported delta is newest-minus-oldest *in the
/// window*, so a stall that started hours ago doesn't smear ancient
/// progress into the current window — and earlier progress can't conceal
/// that no bytes moved during the last 60s.
#[derive(Debug, Clone, Default)]
struct IoBaseline {
    samples: VecDeque<(Instant, u64, u64)>,
}

/// Stateful block-IO stall monitor.
pub struct BlkioStallMonitor {
    proc_root: PathBuf,
    interval: Duration,
    /// Samples a full window holds; the denominator every percentage is
    /// normalized against, so warm-up under-reports instead of inflating.
    expected_samples: u32,
    /// Per-PID `(sampled_at, block-wait kind)` inside the sliding window.
    wait_samples: HashMap<u32, VecDeque<(Instant, &'static str)>>,
    /// Per-suspect-PID IO baselines for the cross-check.
    io_baselines: HashMap<u32, IoBaseline>,
    warn_cooldown: Duration,
    max_iterations: Option<u64>,
    /// When each victim+verdict was last warned about.
    last_warned: HashMap<(String, BlkioVerdict), Instant>,
    /// Whether the last incident-record attempt failed (warn-once, then
    /// debug until a record succeeds — `handle_finding` retries every scan).
    record_unhealthy: bool,
    /// Where findings are recorded so they are visible through the API
    /// and MCP tools, not just the daemon logs. `None` keeps the monitor
    /// log-only.
    incident_store: Option<Arc<IncidentStore>>,
}

impl BlkioStallMonitor {
    pub fn new(interval: Duration) -> Self {
        let expected_samples =
            (WINDOW.as_secs_f64() / interval.as_secs_f64().max(0.001)).round() as u32;
        Self {
            proc_root: PathBuf::from("/proc"),
            interval,
            expected_samples: expected_samples.max(1),
            wait_samples: HashMap::new(),
            io_baselines: HashMap::new(),
            warn_cooldown: DEFAULT_WARN_COOLDOWN,
            max_iterations: None,
            last_warned: HashMap::new(),
            record_unhealthy: false,
            incident_store: None,
        }
    }

    /// Points the monitor at a fixture tree instead of the live `/proc`.
    /// Test-only in practice; mirrors the other monitors.
    pub fn with_proc_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.proc_root = root.into();
        self
    }

    /// Bounds the scan loop so it terminates. Only useful for tests.
    pub fn with_max_iterations(mut self, iterations: u64) -> Self {
        self.max_iterations = Some(iterations);
        self
    }

    /// Quiet period between repeat warnings for the same victim+verdict.
    /// `Duration::ZERO` warns on every occurrence (useful for tests).
    pub fn with_warn_cooldown(mut self, cooldown: Duration) -> Self {
        self.warn_cooldown = cooldown;
        self
    }

    /// Records findings as `blkio_stall` incidents so they surface through
    /// `/incidents` and the MCP tools, not just the daemon logs. Takes
    /// `Option` to mirror the other monitors: the store may be unavailable
    /// (no DB path), in which case the monitor stays log-only.
    pub fn with_incident_store(mut self, store: Option<Arc<IncidentStore>>) -> Self {
        self.incident_store = store;
        self
    }

    /// Log-reporting gate: true the first time a victim reports a given
    /// verdict, and again once the cooldown has elapsed. A verdict *change*
    /// for the same victim always reports. This gates the log line only —
    /// incident recording is decided separately against the store (see
    /// `handle_finding`), so a failed insert is retried on the next scan
    /// instead of being swallowed by this cooldown.
    fn should_warn(&mut self, finding: &BlkioStall) -> bool {
        if self.warn_cooldown.is_zero() {
            return true;
        }
        let key = (finding.victim_label(), finding.verdict);
        let now = Instant::now();
        if let Some(last) = self.last_warned.get(&key)
            && now.duration_since(*last) < self.warn_cooldown
        {
            return false;
        }
        if self.last_warned.len() >= MAX_COOLDOWN_ENTRIES {
            let cooldown = self.warn_cooldown;
            self.last_warned
                .retain(|_, last| now.duration_since(*last) < cooldown);
            // Expiry frees nothing when every entry is still inside its
            // cooldown; evict the oldest instead so the map stays bounded.
            // Mirrors the other monitors' cap discipline.
            while self.last_warned.len() >= MAX_COOLDOWN_ENTRIES {
                let Some(oldest) = self
                    .last_warned
                    .iter()
                    .min_by_key(|(_, last)| **last)
                    .map(|(k, _)| k.clone())
                else {
                    break;
                };
                self.last_warned.remove(&oldest);
            }
        }
        self.last_warned.insert(key, now);
        true
    }

    /// One poll's block-wait sample for a process: `Some(kind)` when any
    /// scanned thread is observed in a block-layer wait, `None`
    /// otherwise. `/proc/<pid>/wchan` reflects only the thread-group
    /// leader, so worker-thread stalls (databases, app servers whose
    /// leader idles in a futex/event loop) are invisible without the
    /// per-thread enumeration — the poll counts as a block-wait sample
    /// for the process when *any* thread is waiting. Threads are scanned
    /// lowest-tid-first up to `MAX_WCHAN_THREADS_PER_POLL`; a thread that
    /// exits mid-scan is skipped (unreadable wchan is not a wait).
    fn sample_process_wchan(&self, pid: u32) -> Option<&'static str> {
        for tid in list_tids(&self.proc_root, pid)
            .into_iter()
            .take(MAX_WCHAN_THREADS_PER_POLL)
        {
            let wchan = read_thread_wchan(&self.proc_root, pid, tid).unwrap_or_default();
            if let Some(kind) = blkio_wait_kind(&wchan) {
                return Some(kind);
            }
        }
        None
    }

    /// One poll: sample every process's `wchan`, maintain the suspect
    /// windows, and return a finding for the worst block-IO waiter when it
    /// is actionable.
    pub fn tick(&mut self) -> Option<BlkioStall> {
        self.tick_at(Instant::now())
    }

    fn tick_at(&mut self, now: Instant) -> Option<BlkioStall> {
        // 1. Sample wchan for every thread of every process; record a
        // block-wait sighting for the process when any thread waits.
        for pid in list_pids(&self.proc_root) {
            if let Some(kind) = self.sample_process_wchan(pid) {
                self.wait_samples
                    .entry(pid)
                    .or_default()
                    .push_back((now, kind));
            }
        }

        // 2. IO cross-check, suspects only: fold this poll's counters into
        // the timestamped baseline. A regressing counter means the PID was
        // recycled: re-baseline instead of fabricating a negative delta.
        // Unreadable counters simply add no sample — availability is
        // tracked explicitly (see fix below), never fabricated as zero.
        let suspects: Vec<u32> = self.wait_samples.keys().copied().collect();
        for pid in suspects {
            let Some((r, w)) = read_io_bytes(&self.proc_root, pid) else {
                continue;
            };
            let baseline = self.io_baselines.entry(pid).or_default();
            if baseline
                .samples
                .back()
                .is_some_and(|&(_, last_r, last_w)| r < last_r || w < last_w)
            {
                debug!("[blkio] io counters regressed for pid={pid}; re-baselining");
                baseline.samples.clear();
            }
            baseline.samples.push_back((now, r, w));
        }

        // 3. Age out samples older than the window; forget processes with
        // nothing left (exited, or quiet again) so state stays bounded.
        let cutoff = now.checked_sub(WINDOW).unwrap_or(now);
        let mut empty_pids = Vec::new();
        for (pid, samples) in self.wait_samples.iter_mut() {
            while samples.front().is_some_and(|&(t, _)| t < cutoff) {
                samples.pop_front();
            }
            if samples.is_empty() {
                empty_pids.push(*pid);
            }
        }
        for pid in empty_pids {
            self.wait_samples.remove(&pid);
            self.io_baselines.remove(&pid);
        }
        // Age the IO samples with the same window: the delta below must
        // cover the window, not the process's lifetime. Drop baselines
        // whose samples all aged out — their counters are unobservable
        // now, which the finding reports as unavailable.
        let mut stale_io = Vec::new();
        for (pid, baseline) in self.io_baselines.iter_mut() {
            while baseline
                .samples
                .front()
                .is_some_and(|&(t, _, _)| t < cutoff)
            {
                baseline.samples.pop_front();
            }
            if baseline.samples.is_empty() {
                stale_io.push(*pid);
            }
        }
        for pid in stale_io {
            self.io_baselines.remove(&pid);
        }

        // 4. Rank suspects by wait fraction, normalized against the full
        // window's expected samples — a process seen for only part of the
        // window under-reports, never inflates.
        let mut best: Option<(u32, f64)> = None;
        for (&pid, samples) in &self.wait_samples {
            let pct = samples.len() as f64 / f64::from(self.expected_samples) * 100.0;
            if pct >= WARN_WAIT_PCT && best.is_none_or(|(_, b)| pct > b) {
                best = Some((pid, pct));
            }
        }
        let (pid, wait_pct) = best?;
        let verdict = classify(wait_pct);
        if !verdict.actionable() {
            return None;
        }
        let samples = &self.wait_samples[&pid];
        let wait_samples = samples.len() as u32;
        let mut kind_counts: HashMap<&'static str, u32> = HashMap::new();
        for &(_, kind) in samples.iter() {
            *kind_counts.entry(kind).or_default() += 1;
        }
        let mut wchan_kinds: Vec<(String, u32)> = kind_counts
            .into_iter()
            .map(|(kind, n)| (kind.to_string(), n))
            .collect();
        wchan_kinds.sort_by_key(|a| std::cmp::Reverse(a.1));
        wchan_kinds.truncate(TOP_WCHAN_KINDS);
        // Newest-minus-oldest *inside the window*; `None` when no counter
        // sample survived the window — never a fabricated zero.
        let io_bytes_delta: Option<(u64, u64)> = self.io_baselines.get(&pid).and_then(|b| {
            let &(_, first_r, first_w) = b.samples.front()?;
            let &(_, last_r, last_w) = b.samples.back()?;
            Some((
                last_r.saturating_sub(first_r),
                last_w.saturating_sub(first_w),
            ))
        });
        Some(BlkioStall {
            pid,
            comm: read_comm(&self.proc_root, pid),
            wait_pct,
            window_secs: WINDOW.as_secs_f64(),
            wait_samples,
            expected_samples: self.expected_samples,
            io_bytes_delta,
            wchan_kinds,
            verdict,
        })
    }

    pub async fn run(mut self) {
        info!("[blkio] starting block-IO stall monitor");
        let mut iterations = 0u64;
        loop {
            if let Some(finding) = self.tick() {
                self.handle_finding(&finding).await;
            }
            iterations += 1;
            if let Some(max) = self.max_iterations
                && iterations >= max
            {
                break;
            }
            sleep(self.interval).await;
        }
    }

    /// Reports one actionable finding: log the warning and, when an incident
    /// store is configured, record it.
    ///
    /// Logging rides `should_warn`'s cooldown — a stalled process is one log
    /// line, not one per poll. Recording is gated only on the store itself,
    /// which is the source of truth for what was persisted: the log
    /// cooldown never suppresses a record attempt, so a transient insert
    /// failure is retried on the next scan instead of vanishing for the
    /// whole cooldown.
    async fn handle_finding(&mut self, finding: &BlkioStall) {
        if self.should_warn(finding) {
            report(finding);
        }
        let recorded = self.recently_recorded_keys().await;
        let key = (finding.victim_label(), format!("{:?}", finding.verdict));
        if recorded.contains(&key) {
            return;
        }
        self.record_incident(finding).await;
    }

    /// `(victim, verdict)` pairs already incidented within the cooldown
    /// window. Empty when no store is configured; fail-open when the store
    /// can't be read — a store that won't answer the dedup query probably
    /// won't take the insert either, and a duplicate row beats a silently
    /// dropped incident.
    async fn recently_recorded_keys(&self) -> HashSet<(String, String)> {
        let Some(store) = &self.incident_store else {
            return HashSet::new();
        };
        match store
            .recent_incident_keys("blkio_stall", self.warn_cooldown.as_secs())
            .await
        {
            Ok(keys) => keys,
            Err(e) => {
                warn!("[blkio] couldn't check recent incidents: {e}");
                HashSet::new()
            }
        }
    }

    /// Best-effort: a failing store must not break the monitoring loop.
    /// The first failure logs at warn level; repeats stay at debug until a
    /// record succeeds, since `handle_finding` retries the insert on every
    /// scan while the stall continues.
    async fn record_incident(&mut self, finding: &BlkioStall) {
        let Some(store) = &self.incident_store else {
            return;
        };
        let incident = incident_from_finding(finding);
        match store.insert(&incident).await {
            Ok(id) => {
                debug!(
                    "[blkio] recorded incident #{id} for {}",
                    finding.victim_label()
                );
                self.record_unhealthy = false;
            }
            Err(e) => {
                if self.record_unhealthy {
                    debug!(
                        "[blkio] still failing to record incident for {}: {e}",
                        finding.victim_label()
                    );
                } else {
                    warn!(
                        "[blkio] failed to record incident for {}: {e}",
                        finding.victim_label()
                    );
                    self.record_unhealthy = true;
                }
            }
        }
    }
}

/// Builds the `blkio_stall` incident row for one finding.
///
/// Field mapping, kept honest about what this monitor measures:
/// * `psi_cpu` / `psi_memory` / `cpu_percent` / `load_avg` are host-level
///   fields this monitor doesn't sample, so they're zero/empty; the
///   triggering reading is the sampled block-wait fraction, carried in
///   `system_snapshot`.
/// * `target_pid` / `target_name` name the victim process; the name
///   carries the PID so same-comm victims are distinct identities.
/// * The wait fraction is `inferred` (sampled wchan peeks, not delay
///   accounting); the IO byte deltas are `measured` kernel counters when
///   they were readable inside the window, `unavailable` otherwise —
///   never a fabricated zero.
fn incident_from_finding(finding: &BlkioStall) -> Incident {
    let wchan_kinds: Vec<serde_json::Value> = finding
        .wchan_kinds
        .iter()
        .map(|(kind, n)| serde_json::json!({ "kind": kind, "samples": n }))
        .collect();
    let snapshot = serde_json::json!({
        "pid": finding.pid,
        "comm": finding.comm,
        "blkio_wait_pct": finding.wait_pct,
        "window_secs": finding.window_secs,
        "wait_samples": finding.wait_samples,
        "expected_samples": finding.expected_samples,
        "io_read_bytes_delta": finding.io_bytes_delta.map(|(r, _)| r),
        "io_write_bytes_delta": finding.io_bytes_delta.map(|(_, w)| w),
        "wchan_kinds": wchan_kinds,
        "source_tier": "polling",
        "verdict": format!("{:?}", finding.verdict),
        // wchan sampling is an inferred fraction; the io counters are
        // measured when readable, unavailable when not. No bytes moving
        // across the whole window while wchan says "waiting" is the
        // hung-storage shape.
        "evidence": {
            "blkio_wait": "inferred",
            "io_counters": if finding.io_bytes_delta.is_some() { "measured" } else { "unavailable" },
        },
    });
    Incident {
        id: None,
        timestamp: chrono::Utc::now().timestamp(),
        event_type: "blkio_stall".to_string(),
        psi_cpu: 0.0,
        psi_memory: 0.0,
        cpu_percent: 0.0,
        load_avg: String::new(),
        action: "alert".to_string(),
        target_pid: Some(finding.pid as i32),
        target_name: Some(finding.victim_label()),
        system_snapshot: serde_json::to_string(&snapshot).ok(),
        llm_analysis: None,
        llm_analyzed_at: None,
        investigation: None,
        recovery_time_ms: None,
        psi_after: None,
    }
}

/// One human- and agent-readable line per actionable finding. The wait
/// fraction is `inferred`; the IO deltas are `measured` when readable and
/// `unavailable` when not — the tags say which is which, and the
/// hung-storage note only appears for counters that were actually read.
fn report(finding: &BlkioStall) {
    let victim = match finding.comm.as_deref() {
        Some(comm) => format!("{comm} (pid={})", finding.pid),
        None => format!("pid={}", finding.pid),
    };
    let (io_note, io_tag) = match finding.io_bytes_delta {
        Some((0, 0)) => (
            "; no IO progress across the window — possible hung storage",
            "io counters measured",
        ),
        Some(_) => ("", "io counters measured"),
        None => ("", "io counters unavailable"),
    };
    match finding.verdict {
        BlkioVerdict::BlkioWarning => warn!(
            "[blkio] WARNING: process {victim} spent {:.0}% of the last {:.0}s in block-IO wait ({}/{} samples) [wait inferred, {io_tag}]{io_note}",
            finding.wait_pct, finding.window_secs, finding.wait_samples, finding.expected_samples,
        ),
        BlkioVerdict::BlkioCritical => warn!(
            "[blkio] CRITICAL: process {victim} spent {:.0}% of the last {:.0}s in block-IO wait ({}/{} samples) — effectively stalled on storage [wait inferred, {io_tag}]{io_note}",
            finding.wait_pct, finding.window_secs, finding.wait_samples, finding.expected_samples,
        ),
        BlkioVerdict::Healthy => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// A fake `/proc` tree: `<dir>/<pid>/{wchan,io,comm}`.
    struct FakeProc {
        dir: TempDir,
    }

    impl FakeProc {
        fn new() -> Self {
            Self {
                dir: TempDir::new().unwrap(),
            }
        }

        fn pid_dir(&self, pid: u32) -> PathBuf {
            let d = self.dir.path().join(pid.to_string());
            fs::create_dir_all(&d).unwrap();
            d
        }

        /// (Re)places a process's wchan, io counters, and comm.
        fn set_proc(&self, pid: u32, comm: &str, wchan: &str, read_bytes: u64, write_bytes: u64) {
            let d = self.pid_dir(pid);
            fs::write(d.join("wchan"), format!("{wchan}\n")).unwrap();
            fs::write(
                d.join("io"),
                format!(
                    "rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\nread_bytes: {read_bytes}\n\
                     write_bytes: {write_bytes}\ncancelled_write_bytes: 0\n"
                ),
            )
            .unwrap();
            fs::write(d.join("comm"), format!("{comm}\n")).unwrap();
        }

        /// (Re)places one thread's wchan. The leader's wchan is also
        /// mirrored at `<pid>/wchan`, like the kernel's alias.
        fn set_thread_wchan(&self, pid: u32, tid: u32, wchan: &str) {
            let task = self
                .dir
                .path()
                .join(pid.to_string())
                .join("task")
                .join(tid.to_string());
            fs::create_dir_all(&task).unwrap();
            fs::write(task.join("wchan"), format!("{wchan}\n")).unwrap();
            if tid == pid {
                fs::write(
                    self.dir.path().join(pid.to_string()).join("wchan"),
                    format!("{wchan}\n"),
                )
                .unwrap();
            }
        }

        fn remove_pid(&self, pid: u32) {
            fs::remove_dir_all(self.dir.path().join(pid.to_string())).unwrap();
        }

        fn monitor_with_interval(&self, interval: Duration) -> BlkioStallMonitor {
            BlkioStallMonitor::new(interval).with_proc_root(self.dir.path())
        }
    }

    fn warning_finding(comm: &str) -> BlkioStall {
        BlkioStall {
            pid: 4242,
            comm: Some(comm.to_string()),
            wait_pct: 60.0,
            window_secs: 60.0,
            wait_samples: 18,
            expected_samples: 30,
            io_bytes_delta: Some((1_000_000, 0)),
            wchan_kinds: vec![("io_schedule".to_string(), 18)],
            verdict: BlkioVerdict::BlkioWarning,
        }
    }

    #[test]
    fn classify_matrix() {
        assert_eq!(classify(0.0), BlkioVerdict::Healthy);
        assert_eq!(classify(49.9), BlkioVerdict::Healthy);
        assert_eq!(classify(50.0), BlkioVerdict::BlkioWarning);
        assert_eq!(classify(79.9), BlkioVerdict::BlkioWarning);
        assert_eq!(classify(80.0), BlkioVerdict::BlkioCritical);
        assert_eq!(classify(100.0), BlkioVerdict::BlkioCritical);
    }

    #[test]
    fn wchan_classification() {
        // Block-layer waits.
        for wchan in [
            "io_schedule",
            "io_schedule_timeout",
            "wait_on_page_bit",
            "wait_on_page_bit_killable",
            "wait_on_page_writeback",
            "blkdev_issue_flush",
            "blkdev_issue_zeroout",
            "get_request",
            "get_request_wait",
        ] {
            assert!(
                blkio_wait_kind(wchan).is_some(),
                "{wchan} must classify as block-IO wait"
            );
        }
        // Everything else is not block-IO wait.
        for wchan in [
            "0",
            "",
            "do_nanosleep",
            "futex_wait_queue_me",
            "poll_schedule_timeout",
            "do_sys_poll",
            "pipe_wait",
            "ep_poll",
        ] {
            assert!(
                blkio_wait_kind(wchan).is_none(),
                "{wchan} must not classify as block-IO wait"
            );
        }
    }

    #[test]
    fn worker_thread_block_wait_fires() {
        // The leader idles in a futex (event loop) while a worker is stuck
        // in io_schedule: /proc/<pid>/wchan alone would miss this
        // entirely, so the monitor enumerates task/<tid>/wchan and a poll
        // counts when *any* thread waits.
        let fake = FakeProc::new();
        // 6s poll => 10 expected samples per 60s window.
        let mut mon = fake.monitor_with_interval(Duration::from_secs(6));
        let t0 = Instant::now();
        let mut finding = None;
        for i in 0..10 {
            fake.set_proc(100, "db", "futex_wait_queue_me", 1000 * i, 0);
            fake.set_thread_wchan(100, 101, "io_schedule");
            finding = mon.tick_at(t0 + Duration::from_secs(6 * i));
        }
        let finding = finding.expect("worker-thread block-IO wait must fire");
        assert_eq!(finding.pid, 100);
        assert_eq!(finding.verdict, BlkioVerdict::BlkioCritical);
        assert_eq!(
            finding.wchan_kinds,
            vec![("io_schedule".to_string(), 10)],
            "the worker thread's wait kind must be reported"
        );
        // The IO cross-check still rode along for the process.
        assert_eq!(finding.io_bytes_delta, Some((9000, 0)));
    }

    #[test]
    fn thread_scan_cap_bounds_cost() {
        // 1030 threads, lowest tids first, cap at 1024: the stalled
        // thread beyond the cap is not sampled on this poll. This pins
        // the documented tradeoff — pathological thread counts can't
        // stall the 2s loop, at the cost of missing waits past the cap.
        let fake = FakeProc::new();
        let mon = fake.monitor_with_interval(Duration::from_secs(2));
        fake.set_proc(100, "db", "futex_wait_queue_me", 0, 0);
        for tid in 101..=1129u32 {
            let wchan = if tid == 1129 {
                "io_schedule"
            } else {
                "futex_wait_queue_me"
            };
            fake.set_thread_wchan(100, tid, wchan);
        }
        assert_eq!(
            mon.sample_process_wchan(100),
            None,
            "threads past the per-process scan cap are not sampled"
        );
    }

    #[test]
    fn warmup_under_reports_and_converges() {
        // 6s poll => 10 expected samples per 60s window. Four wait samples
        // are 40% — a short burst must not inflate into a verdict just
        // because few samples exist yet.
        let fake = FakeProc::new();
        let mut mon = fake.monitor_with_interval(Duration::from_secs(6));
        let t0 = Instant::now();
        fake.set_proc(100, "backfill", "io_schedule", 1000, 0);
        for i in 0..4 {
            assert!(
                mon.tick_at(t0 + Duration::from_secs(6 * i)).is_none(),
                "4/10 samples (40%) must not fire during warm-up"
            );
            fake.set_proc(100, "backfill", "io_schedule", 1000 + 100 * i, 0);
        }
        // The fraction converges as the window fills: 5/10 = 50% warns.
        fake.set_proc(100, "backfill", "io_schedule", 2000, 0);
        let finding = mon
            .tick_at(t0 + Duration::from_secs(24))
            .expect("5/10 samples (50%) must warn");
        assert_eq!(finding.verdict, BlkioVerdict::BlkioWarning);
        assert!((finding.wait_pct - 50.0).abs() < 1e-9);
        assert_eq!(finding.wait_samples, 5);
        assert_eq!(finding.expected_samples, 10);
    }

    #[test]
    fn sustained_wait_fires_critical() {
        // 2s poll => 30 expected samples. A full window of block-IO wait
        // is 100% — critical.
        let fake = FakeProc::new();
        let mut mon = fake.monitor_with_interval(Duration::from_secs(2));
        let t0 = Instant::now();
        let mut finding = None;
        for i in 0..30 {
            fake.set_proc(100, "backfill", "wait_on_page_bit", 1000 * i, 0);
            finding = mon.tick_at(t0 + Duration::from_secs(2 * i));
        }
        let finding = finding.expect("30/30 samples must be critical");
        assert_eq!(finding.verdict, BlkioVerdict::BlkioCritical);
        assert!((finding.wait_pct - 100.0).abs() < 1e-9);
        assert_eq!(finding.pid, 100);
        assert_eq!(finding.comm.as_deref(), Some("backfill"));
        // The IO cross-check rode along: bytes moved while waiting.
        assert!(
            matches!(finding.io_bytes_delta, Some((r, _)) if r > 0),
            "read-byte delta must be measured and positive"
        );
        assert_eq!(
            finding.wchan_kinds,
            vec![("wait_on_page".to_string(), 30)],
            "the observed wchan kind must be reported"
        );
    }

    #[test]
    fn io_counters_not_moving_is_visible() {
        // wchan says "waiting" but no bytes move across the whole window:
        // the hung-storage shape. The finding still fires; the snapshot
        // carries the zero deltas so consumers can tell.
        let fake = FakeProc::new();
        let mut mon = fake.monitor_with_interval(Duration::from_secs(2));
        let t0 = Instant::now();
        let mut finding = None;
        for i in 0..30 {
            fake.set_proc(100, "stuck", "io_schedule", 0, 0);
            finding = mon.tick_at(t0 + Duration::from_secs(2 * i));
        }
        let finding = finding.expect("must fire");
        assert_eq!(
            finding.io_bytes_delta,
            Some((0, 0)),
            "counters were read and did not move: a measured zero"
        );
    }

    #[test]
    fn io_counter_regression_rebaselines() {
        let fake = FakeProc::new();
        let mut mon = fake.monitor_with_interval(Duration::from_secs(2));
        let t0 = Instant::now();
        fake.set_proc(100, "backfill", "io_schedule", 10_000, 0);
        mon.tick_at(t0);
        // PID recycled: counters start over. Must not fabricate a negative
        // delta or panic.
        fake.set_proc(100, "backfill", "io_schedule", 500, 0);
        mon.tick_at(t0 + Duration::from_secs(2));
        fake.set_proc(100, "backfill", "io_schedule", 1500, 0);
        let finding = mon.tick_at(t0 + Duration::from_secs(4));
        // Only 3 samples so far: 10% — no finding, but also no panic and
        // the baseline recovered. Drive to a full window and check the
        // delta is measured from the re-baselined counters.
        assert!(finding.is_none());
        for i in 3..30 {
            fake.set_proc(100, "backfill", "io_schedule", 1500 + 100 * i, 0);
            mon.tick_at(t0 + Duration::from_secs(2 * i));
        }
        // One more tick to get the finding with the final counters.
        fake.set_proc(100, "backfill", "io_schedule", 1500 + 100 * 29, 0);
        let finding = mon
            .tick_at(t0 + Duration::from_secs(60))
            .expect("must fire");
        assert_eq!(
            finding.io_bytes_delta,
            Some((3900, 0)),
            "delta must be measured from the re-baselined counters"
        );
    }

    #[test]
    fn io_delta_covers_only_the_window() {
        // 2s poll, 60s window, 36 ticks (t=0..70s). Bytes move early, then
        // stop at t=40s. The reported delta must be newest-minus-oldest
        // *inside the window* — [t=10s, t=70s]: 20000-5000 — not since
        // first sighting, so ancient progress can't smear into (or
        // conceal a stall within) the current window.
        let fake = FakeProc::new();
        let mut mon = fake.monitor_with_interval(Duration::from_secs(2));
        let t0 = Instant::now();
        let mut finding = None;
        for i in 0..=35u64 {
            fake.set_proc(100, "backfill", "io_schedule", 1000 * i.min(20), 0);
            finding = mon.tick_at(t0 + Duration::from_secs(2 * i));
        }
        let finding = finding.expect("must fire");
        assert_eq!(
            finding.io_bytes_delta,
            Some((15_000, 0)),
            "delta must cover only the 60s window"
        );
    }

    #[test]
    fn unavailable_io_counters_are_not_fabricated() {
        // wchan says "waiting" but /proc/<pid>/io is unreadable (raced
        // with process exit): the finding still fires — the cross-check
        // never gates — but the counters are labeled unavailable, not
        // zero, and no hung-storage claim is made.
        let fake = FakeProc::new();
        let mut mon = fake.monitor_with_interval(Duration::from_secs(2));
        let t0 = Instant::now();
        let mut finding = None;
        for i in 0..30 {
            // wchan + comm present, io file absent.
            let d = fake.pid_dir(100);
            fs::write(d.join("wchan"), "io_schedule\n").unwrap();
            fs::write(d.join("comm"), "backfill\n").unwrap();
            finding = mon.tick_at(t0 + Duration::from_secs(2 * i));
        }
        let finding = finding.expect("must fire");
        assert_eq!(
            finding.io_bytes_delta, None,
            "unreadable counters must be unavailable, not zero"
        );
        let incident = incident_from_finding(&finding);
        let snapshot: serde_json::Value =
            serde_json::from_str(incident.system_snapshot.as_deref().unwrap()).unwrap();
        assert_eq!(snapshot["evidence"]["io_counters"], "unavailable");
        assert!(
            snapshot["io_read_bytes_delta"].is_null() && snapshot["io_write_bytes_delta"].is_null(),
            "the snapshot must not carry fabricated zero deltas"
        );
    }

    #[test]
    fn stale_samples_age_out_and_processes_are_forgotten() {
        let fake = FakeProc::new();
        let mut mon = fake.monitor_with_interval(Duration::from_secs(6));
        let t0 = Instant::now();
        // 5 wait samples => 50% => warning.
        for i in 0..5 {
            fake.set_proc(100, "backfill", "io_schedule", 1000, 0);
            mon.tick_at(t0 + Duration::from_secs(6 * i));
        }
        assert!(!mon.wait_samples.is_empty());
        // The process goes quiet (running, not waiting). Its windowed
        // samples keep it actionable for a while — it really did spend
        // half the window in block-IO wait — but once every sample ages
        // past the 60s window the finding must stop, and the process must
        // be forgotten. Samples land at t=0..24, so t>=84 is fully aged.
        for i in 5..20 {
            fake.set_proc(100, "backfill", "0", 1000, 0);
            let finding = mon.tick_at(t0 + Duration::from_secs(6 * i));
            if i >= 14 {
                assert!(
                    finding.is_none(),
                    "aged-out samples must not fire (t={}s)",
                    6 * i
                );
            }
        }
        assert!(
            mon.wait_samples.is_empty() && mon.io_baselines.is_empty(),
            "quiet processes must be forgotten, keeping state bounded"
        );
        // The process exits entirely: same outcome, no panic.
        fake.remove_pid(100);
        assert!(mon.tick_at(t0 + Duration::from_secs(200)).is_none());
    }

    #[test]
    fn unknown_comm_when_comm_unreadable() {
        let fake = FakeProc::new();
        let mut mon = fake.monitor_with_interval(Duration::from_secs(6));
        let t0 = Instant::now();
        // wchan + io present, comm missing: the rate still fires, the
        // victim is honestly unknown.
        for i in 0..10 {
            let d = fake.pid_dir(200);
            fs::write(d.join("wchan"), "io_schedule\n").unwrap();
            fs::write(
                d.join("io"),
                "rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\nread_bytes: 100\nwrite_bytes: 0\ncancelled_write_bytes: 0\n",
            )
            .unwrap();
            let finding = mon.tick_at(t0 + Duration::from_secs(6 * i));
            if i == 9 {
                let finding = finding.expect("10/10 must fire");
                assert_eq!(finding.comm, None);
                assert_eq!(finding.victim_label(), "unknown (pid=200)");
            }
        }
    }

    #[test]
    fn warn_cooldown_dedups_repeat_verdicts() {
        let mut mon = BlkioStallMonitor::new(Duration::from_secs(2));
        let finding = warning_finding("backfill");
        assert!(mon.should_warn(&finding), "first occurrence must warn");
        assert!(
            !mon.should_warn(&finding),
            "immediate repeat must be cooled down"
        );
        // A verdict change for the same victim is new information.
        let escalated = BlkioStall {
            verdict: BlkioVerdict::BlkioCritical,
            ..warning_finding("backfill")
        };
        assert!(mon.should_warn(&escalated));
        // A different victim is unaffected.
        assert!(mon.should_warn(&warning_finding("other")));
    }

    #[test]
    fn same_comm_processes_do_not_suppress_each_other() {
        // Two processes sharing a comm (think `postgres` backends): the
        // dedup identity includes the PID, so each victim warns on its own.
        let mut mon = BlkioStallMonitor::new(Duration::from_secs(2));
        let a = BlkioStall {
            pid: 100,
            ..warning_finding("postgres")
        };
        let b = BlkioStall {
            pid: 200,
            ..warning_finding("postgres")
        };
        assert!(mon.should_warn(&a), "first victim must warn");
        assert!(
            mon.should_warn(&b),
            "a different PID with the same comm must warn too"
        );
    }

    #[test]
    fn warn_cooldown_expires() {
        let mut mon = BlkioStallMonitor::new(Duration::from_secs(2))
            .with_warn_cooldown(Duration::from_millis(30));
        let finding = warning_finding("backfill");
        assert!(mon.should_warn(&finding));
        assert!(!mon.should_warn(&finding));
        std::thread::sleep(Duration::from_millis(60));
        assert!(mon.should_warn(&finding), "cooldown must expire");
    }

    #[test]
    fn zero_warn_cooldown_warns_every_time() {
        let mut mon =
            BlkioStallMonitor::new(Duration::from_secs(2)).with_warn_cooldown(Duration::ZERO);
        let finding = warning_finding("backfill");
        assert!(mon.should_warn(&finding));
        assert!(mon.should_warn(&finding));
    }

    #[test]
    fn warn_cooldown_map_is_bounded() {
        let mut mon = BlkioStallMonitor::new(Duration::from_secs(2))
            .with_warn_cooldown(Duration::from_secs(3600));
        for i in 0..(MAX_COOLDOWN_ENTRIES + 50) {
            let finding = warning_finding(&format!("backfill-{i}"));
            assert!(mon.should_warn(&finding), "new victim must warn");
        }
        assert!(
            mon.last_warned.len() <= MAX_COOLDOWN_ENTRIES,
            "cooldown map grew past its cap: {}",
            mon.last_warned.len()
        );
    }

    #[test]
    fn incident_from_finding_maps_fields() {
        let finding = BlkioStall {
            pid: 4242,
            comm: Some("backfill".to_string()),
            wait_pct: 85.0,
            window_secs: 60.0,
            wait_samples: 26,
            expected_samples: 30,
            io_bytes_delta: Some((5_000_000, 1000)),
            wchan_kinds: vec![("io_schedule".to_string(), 26)],
            verdict: BlkioVerdict::BlkioCritical,
        };
        let incident = incident_from_finding(&finding);
        assert_eq!(incident.event_type, "blkio_stall");
        assert_eq!(incident.action, "alert");
        assert_eq!(incident.target_pid, Some(4242));
        assert_eq!(
            incident.target_name.as_deref(),
            Some("backfill (pid=4242)"),
            "the incident identity names the victim process, not just the comm"
        );
        // Host-level fields this monitor doesn't sample stay zero/empty;
        // the triggering reading lives in the snapshot.
        assert_eq!(incident.psi_cpu, 0.0);
        assert_eq!(incident.cpu_percent, 0.0);
        let snapshot: serde_json::Value =
            serde_json::from_str(incident.system_snapshot.as_deref().unwrap()).unwrap();
        assert_eq!(snapshot["verdict"], "BlkioCritical");
        assert_eq!(snapshot["source_tier"], "polling");
        assert!((snapshot["blkio_wait_pct"].as_f64().unwrap() - 85.0).abs() < 1e-9);
        assert_eq!(snapshot["io_read_bytes_delta"], 5_000_000);
        assert_eq!(snapshot["wchan_kinds"][0]["kind"], "io_schedule");
        // The wait fraction is inferred (sampled peeks); the IO deltas are
        // measured kernel counters.
        assert_eq!(snapshot["evidence"]["blkio_wait"], "inferred");
        assert_eq!(snapshot["evidence"]["io_counters"], "measured");
    }

    #[tokio::test]
    async fn finding_is_recorded_as_incident() {
        let fake = FakeProc::new();
        let db_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            IncidentStore::new(db_dir.path().join("incidents.db"))
                .await
                .unwrap(),
        );
        let mut mon = fake
            .monitor_with_interval(Duration::from_secs(2))
            .with_incident_store(Some(Arc::clone(&store)));
        let t0 = Instant::now();
        let mut finding = None;
        for i in 0..30 {
            fake.set_proc(100, "backfill", "io_schedule", 1000 * i, 0);
            finding = mon.tick_at(t0 + Duration::from_secs(2 * i));
        }
        let finding = finding.expect("must fire");
        mon.handle_finding(&finding).await;

        let incidents = store
            .recent_filtered(10, Some("blkio_stall"), None)
            .await
            .unwrap();
        assert_eq!(incidents.len(), 1, "one finding, one incident");
        assert_eq!(incidents[0].event_type, "blkio_stall");
        assert_eq!(
            incidents[0].target_name.as_deref(),
            Some("backfill (pid=100)")
        );

        // The store already has this finding: handling it again must not
        // write a second row. Recording is decided against the store, not
        // the log cooldown.
        mon.handle_finding(&finding).await;
        let incidents = store
            .recent_filtered(10, Some("blkio_stall"), None)
            .await
            .unwrap();
        assert_eq!(
            incidents.len(),
            1,
            "repeat findings must not duplicate incidents"
        );

        // A fresh monitor — the daemon restarted, so the bounded in-memory
        // cooldown map is empty — must not re-record either.
        let mut mon2 = fake
            .monitor_with_interval(Duration::from_secs(2))
            .with_incident_store(Some(Arc::clone(&store)));
        let mut finding2 = None;
        for i in 0..30 {
            fake.set_proc(100, "backfill", "io_schedule", 1000 * i, 0);
            finding2 = mon2.tick_at(t0 + Duration::from_secs(2 * i));
        }
        let finding2 = finding2.expect("must fire");
        mon2.handle_finding(&finding2).await;
        let incidents = store
            .recent_filtered(10, Some("blkio_stall"), None)
            .await
            .unwrap();
        assert_eq!(
            incidents.len(),
            1,
            "a restarted monitor must not duplicate incidents the store already has"
        );
    }

    #[tokio::test]
    async fn same_comm_victims_record_independently() {
        // The store dedup key is (target_name, verdict) and the target
        // name carries the PID: two same-comm victims are two identities,
        // so both record — one `postgres` backend no longer suppresses
        // the others for the whole cooldown.
        let db_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            IncidentStore::new(db_dir.path().join("incidents.db"))
                .await
                .unwrap(),
        );
        let mut mon = BlkioStallMonitor::new(Duration::from_secs(2))
            .with_incident_store(Some(Arc::clone(&store)));
        let a = BlkioStall {
            pid: 100,
            ..warning_finding("postgres")
        };
        let b = BlkioStall {
            pid: 200,
            ..warning_finding("postgres")
        };
        mon.handle_finding(&a).await;
        mon.handle_finding(&b).await;
        let incidents = store
            .recent_filtered(10, Some("blkio_stall"), None)
            .await
            .unwrap();
        assert_eq!(
            incidents.len(),
            2,
            "same-comm processes are distinct incident identities"
        );
    }

    #[tokio::test]
    async fn failed_insert_is_retried_on_the_next_scan() {
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("incidents.db");
        let finding = warning_finding("backfill");

        // The store is down: the finding is logged, but the failed insert
        // must not poison future record attempts — recording has no
        // in-memory cooldown, only the store's own contents.
        let down_store = Arc::new(IncidentStore::new(&db_path).await.unwrap());
        down_store.close_pool_for_test().await;
        let mut mon = BlkioStallMonitor::new(Duration::from_secs(2))
            .with_incident_store(Some(Arc::clone(&down_store)));
        mon.handle_finding(&finding).await;

        // The store recovers (fresh pool on the same file). The next scan
        // must retry the insert instead of sitting out a cooldown.
        let up_store = Arc::new(IncidentStore::new(&db_path).await.unwrap());
        mon.incident_store = Some(Arc::clone(&up_store));
        mon.handle_finding(&finding).await;
        let incidents = up_store
            .recent_filtered(10, Some("blkio_stall"), None)
            .await
            .unwrap();
        assert_eq!(
            incidents.len(),
            1,
            "a failed insert must be retried once the store recovers"
        );

        // And the now-recorded finding dedups against the store: no second row.
        mon.handle_finding(&finding).await;
        let incidents = up_store
            .recent_filtered(10, Some("blkio_stall"), None)
            .await
            .unwrap();
        assert_eq!(incidents.len(), 1, "a recorded finding must not duplicate");
    }

    #[tokio::test]
    async fn monitor_without_store_stays_log_only() {
        // No incident store configured: handle_finding must not fail, just log.
        let mut mon =
            BlkioStallMonitor::new(Duration::from_secs(2)).with_warn_cooldown(Duration::ZERO);
        mon.handle_finding(&warning_finding("backfill")).await;
    }
}
