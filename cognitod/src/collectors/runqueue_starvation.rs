//! Userspace runqueue-starvation detector: no eBPF, no privileges beyond /proc.
//!
//! A thread that is runnable but not running is waiting on a runqueue —
//! somebody else's threads are eating its CPU. The kernel accounts exactly
//! this in `/proc/<pid>/task/<tid>/schedstat` (`runqueue_wait_ns`), so the
//! victim side of CPU starvation is a *measured* number from userspace.
//!
//! Design:
//!
//! * **Signal (measured):** per-thread `schedstat` Δ over a 10s sliding
//!   window ⇒ ms each thread spent waiting for a CPU. Polled every 5s.
//!   Findings are per-*process*: a process's wait is the sum of its
//!   measured threads' window waits, so starvation spread across threads
//!   fires even when no single thread crosses the line on its own. Warn
//!   at >= 2000 ms aggregate per 10s window (2 thread-seconds lost to
//!   runqueue waiting), critical at >= 5000 ms. The constants reuse the
//!   per-thread experiment grounding (an uncontended spinner waited
//!   ~31 ms / 5s, while the same spinner against 4 hogs waited ~6514 ms /
//!   10s): for a single-threaded process the aggregate *is* the thread's
//!   wait, so behavior there is unchanged. Short-lived threads can't
//!   double-count the aggregate: a thread contributes only once it has
//!   two samples in the window, and a regressing counter (TID recycled)
//!   re-baselines instead of fabricating a Δ.
//! * **Cost bound:** `schedstat` is read only for the threads of the top-50
//!   processes by recent CPU time (`utime+stime` Δ from `/proc/<pid>/stat`,
//!   per the spec). One cheap `stat` read per process ranks the field;
//!   only the top-50's threads pay the `schedstat` read. In-memory baselines
//!   still scale with thread count but are pruned after 60s idle.
//! * **Coverage tradeoff, stated plainly:** a thread whose process falls
//!   outside the top-50 isn't measured on that poll. In practice the
//!   population most likely to starve *is* the CPU-hungry one — starving
//!   threads are runnable threads competing for CPUs — and ranking is at
//!   process granularity, so a fully-starved thread is still measured while
//!   any sibling thread burns CPU. Threads of genuinely idle processes
//!   can't meaningfully starve: they weren't trying to run.
//! * **Warm-up honesty:** the window wait is the raw Δ in ms — it is never
//!   divided by a short warm-up span, so a partial window can only
//!   *under*-report, never inflate into a verdict.
//! * **Offender honesty:** offender identity ("whose threads preempted the
//!   victim") needs `sched_switch` and is eBPF-only (spec §4). The incident
//!   labels the offender `unavailable` and says so; correlate manually with
//!   `cgroup_pressure` incidents for the `inferred` version.
//! * **Degradation:** kernels without `CONFIG_SCHEDSTATS` have no readable
//!   schedstat files. The monitor then disables itself (warns once, never
//!   fabricates) and resumes if the files appear.
//!
//! Findings become `cpu_starvation` incidents via the same store-backed
//! dedup discipline as the other monitors: the incident store — not the
//! bounded in-memory warn map — is the source of truth for what was already
//! persisted, so map eviction and daemon restarts cannot duplicate rows.
//!
//! **Latency/SLO watch mode** (`[watch]` config): the calibration work
//! showed no global threshold is safe — ambient baseline wait varies by
//! more than 10x across hosts — so for the workload the customer actually
//! watches, the operator names targets (pid, cgroup, or comm) plus an SLO
//! signal instead of a lower magic number. Watched processes bypass the
//! top-50 measurement gate, each target keeps its own rolling baseline of
//! per-poll aggregates, and a finding fires only when the wait is
//! elevated against that baseline AND a fresh p99 sample is breaching the
//! SLO. Either condition alone stays silent; there is deliberately no
//! absolute wait floor. The SLO-breach requirement is the noise guard.

use log::{debug, info, warn};
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::config::{WatchConfig, WatchSelector, WatchTargetConfig};
use crate::incidents::{Incident, IncidentStore};

/// Sliding window over which per-thread runqueue wait is accumulated.
const WINDOW: Duration = Duration::from_secs(10);
/// The monitor's window in seconds, for deriving window fractions below.
const WINDOW_SECS: f64 = 10.0;
/// Wait at or above which a warning fires: 20% of a CPU's time in the
/// window spent waiting on a runqueue (experiment-grounded, see above).
const WARN_WAIT_MS: f64 = 2000.0;
/// Wait at or above which a critical fires: 50% of the window waiting.
const CRIT_WAIT_MS: f64 = 5000.0;
/// The frozen absolute thresholds as fractions of the measurement window.
/// The on-demand probe's window is the ~1s probe interval, not 10s; the
/// fractions keep one physical meaning — "what share of this window did
/// the process's threads lose to runqueue waiting?" — across both paths.
const WARN_WAIT_FRAC: f64 = WARN_WAIT_MS / (WINDOW_SECS * 1000.0);
const CRIT_WAIT_FRAC: f64 = CRIT_WAIT_MS / (WINDOW_SECS * 1000.0);
/// Default quiet period between repeat warnings for the same victim+verdict,
/// mirroring the other monitors.
const DEFAULT_WARN_COOLDOWN: Duration = Duration::from_secs(15 * 60);
/// Cap on the warn-cooldown map; oldest entries are evicted past this.
const MAX_COOLDOWN_ENTRIES: usize = 1024;
/// Baselines idle longer than this are dropped — the thread exited or the
/// host went quiet; either way the memory shouldn't linger.
const STALE_BASELINE: Duration = Duration::from_secs(60);
/// How many of the worst waiters ride along in the incident snapshot for
/// context. The finding itself names only the worst.
const TOP_WAITERS_IN_SNAPSHOT: usize = 5;
/// `schedstat` is read only for the threads of this many top processes by
/// recent CPU time — the spec's cost bound for the 5s poll.
const TOP_PROCESSES_BY_CPU: usize = 50;
/// Minimum per-target baseline samples before watch evaluation. With the
/// default 5s poll this is ~60s of history; a median from fewer points is
/// not a baseline, it's noise.
const MIN_WATCH_BASELINE_SAMPLES: usize = 12;
/// How long a posted p99 sample stays usable. Older than this, the SLO
/// signal is stale and the dual condition cannot be evaluated — the
/// target stays silent.
const WATCH_LATENCY_TTL: Duration = Duration::from_secs(90);
/// Bound for the latency-sample channel feeding the monitor. The monitor
/// drains it once per 5s poll, so without a bound a stuck or malicious
/// producer could grow daemon memory without limit. Samples are
/// best-effort telemetry: past the bound the endpoint sheds load with
/// 429 instead of queueing.
pub const WATCH_LATENCY_CHANNEL_CAP: usize = 128;

/// What a process's measured aggregate runqueue wait means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StarvationVerdict {
    Healthy,
    /// Process's threads spent >= 2000 ms waiting in aggregate: something
    /// is eating its share.
    StarvationWarning,
    /// Process's threads spent >= 5000 ms waiting in aggregate:
    /// effectively starved.
    StarvationCritical,
}

impl StarvationVerdict {
    /// `false` for `Healthy`; used to filter log/report noise.
    pub fn actionable(self) -> bool {
        !matches!(self, StarvationVerdict::Healthy)
    }

    /// Stable wire string for the queryable snapshot: a deterministic
    /// classification of the measured wait, never a reinterpretation.
    pub fn as_str(self) -> &'static str {
        match self {
            StarvationVerdict::Healthy => "healthy",
            StarvationVerdict::StarvationWarning => "starvation_warning",
            StarvationVerdict::StarvationCritical => "starvation_critical",
        }
    }
}

/// One per-process contention snapshot, published for the queryable
/// `GET /processes/{pid}/contention` endpoint.
///
/// One measured contention finding for `GET /processes/{pid}/contention`,
/// produced by [`ContentionProbe::measure`].
///
/// This is the SAME physical quantity the monitor's threshold path
/// evaluates — the per-process aggregate runqueue wait from schedstat —
/// but measured on demand for the named PID instead of polled in the
/// top-50 loop: a fresh two-sample measurement per request, including a
/// measured healthy, not a thresholded incident excerpt.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessContentionSnapshot {
    /// The process (tgid) this finding describes — the snapshot's identity.
    pub tgid: u32,
    pub comm: Option<String>,
    /// Process birth identity: `/proc/<pid>/stat` field 22 (`starttime`,
    /// clock ticks since boot) read in the same call as the measurement.
    /// Together with `boot_id` this names one process *incarnation* — a
    /// recycled PID gets a different starttime. `None` when uncapturable;
    /// a consumer binding evidence to a process identity must treat `None`
    /// as unbindable (never as matching).
    pub start_ticks: Option<u64>,
    /// Kernel boot ID read from the probe's `/proc` root — the other half
    /// of the incarnation identity. `None` when unreadable.
    pub boot_id: Option<String>,
    /// Epistemic label of the measurement — always `"measured"`. The
    /// wait is read from kernel schedstat accounting, not inferred.
    pub label: &'static str,
    /// Deterministic classification of the measured wait against the
    /// frozen threshold fractions (see [`classify_for_window`]): the
    /// monitor's 2000/5000 ms absolute thresholds are 0.2/0.5 of its 10s
    /// window, expressed here as fractions so the on-demand probe's
    /// shorter window classifies against the same physical meaning.
    pub verdict: &'static str,
    /// Measured ms the process's threads spent waiting on a runqueue
    /// inside the window, summed across measured threads.
    pub wait_ms: f64,
    /// The worst single thread's wait, for context.
    pub worst_thread_wait_ms: f64,
    /// How many of the process's threads were measured this probe.
    pub measured_thread_count: usize,
    /// Seconds the measurement window covers.
    pub window_secs: f64,
    /// Wall-clock unix seconds when the snapshot was taken —
    /// presentation/correlation only, never part of a measurement digest.
    pub measured_at_unix: u64,
}

/// On-demand per-process contention measurement for
/// `GET /processes/{pid}/contention`.
///
/// Unlike the monitor's poll loop (top-50 by CPU, 10s window,
/// threshold-only incidents), the probe measures the named PID
/// synchronously on every request: two `schedstat` samples `probe` apart,
/// per-thread Δ, aggregated to the process. No measurement gate, no
/// warm-up, no incident store, no monitor dependency — a process that
/// exists gets a fresh measured answer every time, including "healthy",
/// which the thresholded incident path structurally cannot express.
///
/// Absence is typed, never zero:
/// * `NotFound` — the PID doesn't exist (checked before and after the
///   probe, so a process that exits mid-probe is absence, not data).
/// * `Degraded` — the PID exists but no `schedstat` is readable
///   (`CONFIG_SCHEDSTATS` off). The endpoint answers 503 so "no
///   measurement infrastructure" is never confused with "no contention".
pub struct ContentionProbe {
    proc_root: PathBuf,
    probe: Duration,
    /// Kernel boot ID captured once at construction — host-boot-scoped
    /// half of the process incarnation identity (see
    /// [`ProcessContentionSnapshot::boot_id`]).
    boot_id: Option<String>,
}

/// Why an on-demand contention measurement has no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentionMeasureError {
    /// No such process.
    NotFound,
    /// The process exists but its `schedstat` files are unreadable — the
    /// measurement infrastructure is missing, not the contention.
    Degraded,
}

/// How long the probe waits between its two `schedstat` samples: long
/// enough to average out scheduling jitter, short enough for a
/// synchronous request handler. The verdict thresholds scale with the
/// actual measured window (see [`classify_for_window`]), so the probe
/// length is a latency/precision tradeoff, not a semantic change.
const PROBE_INTERVAL: Duration = Duration::from_secs(1);

/// One `schedstat` sample: `tid -> runqueue_wait_ns` for every thread of
/// `tgid` whose file is readable right now. `None` when the process has
/// no readable `schedstat` at all — the caller distinguishes "process
/// gone" from "infrastructure missing".
/// `tgid` whose file is readable right now. `None` when the process has
/// no readable `schedstat` at all — the caller distinguishes "process
/// gone" from "infrastructure missing".
fn sample_process_wait(proc_root: &Path, tgid: u32) -> Option<HashMap<u32, u64>> {
    // Thread list for exactly this process: the query names one pid, so
    // only its threads are read (no whole-/proc scan, no top-50 gate).
    let mut tids: Vec<u32> = Vec::new();
    match std::fs::read_dir(proc_root.join(tgid.to_string()).join("task")) {
        Ok(entries) => {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str()
                    && let Ok(tid) = name.parse::<u32>()
                {
                    tids.push(tid);
                }
            }
        }
        // No task dir (fixture trees, odd kernels): the leader's files
        // are still readable at the plain pid path.
        Err(_) => tids.push(tgid),
    }
    let mut out = HashMap::new();
    for tid in tids {
        if let Some((_, wait_ns)) = read_schedstat(&thread_file(proc_root, tgid, tid, "schedstat"))
        {
            out.insert(tid, wait_ns);
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Per-process wait Δ between two samples: the sum of each thread's
/// `runqueue_wait_ns` Δ, worst thread for context. A thread contributes
/// only when it appears in both samples with a non-regressing counter —
/// threads born or exited mid-probe have no Δ, and a regressing counter
/// (TID recycled) is skipped rather than fabricated, mirroring the
/// monitor's baseline discipline.
fn aggregate_wait_delta(
    first: &HashMap<u32, u64>,
    second: &HashMap<u32, u64>,
) -> (f64, f64, usize) {
    let mut total_ms = 0.0;
    let mut worst_ms = 0.0;
    let mut threads = 0usize;
    for (&tid, &w1) in first {
        let Some(&w2) = second.get(&tid) else {
            continue;
        };
        if w2 < w1 {
            continue;
        }
        let delta_ms = (w2 - w1) as f64 / 1e6;
        total_ms += delta_ms;
        threads += 1;
        if delta_ms > worst_ms {
            worst_ms = delta_ms;
        }
    }
    (total_ms, worst_ms, threads)
}

/// [`StarvationVerdict`] for `wait_ms` measured over `window_secs`.
/// The thresholds are [`WARN_WAIT_FRAC`]/[`CRIT_WAIT_FRAC`] of the window —
/// the monitor's frozen absolute thresholds expressed as fractions, so
/// the on-demand probe's shorter window classifies against the same
/// physical meaning.
fn classify_for_window(wait_ms: f64, window_secs: f64) -> StarvationVerdict {
    let window_ms = window_secs * 1000.0;
    if wait_ms >= CRIT_WAIT_FRAC * window_ms {
        StarvationVerdict::StarvationCritical
    } else if wait_ms >= WARN_WAIT_FRAC * window_ms {
        StarvationVerdict::StarvationWarning
    } else {
        StarvationVerdict::Healthy
    }
}

impl ContentionProbe {
    /// `proc_root` is the `/proc` the probe reads; the PID-existence
    /// checks use it, so "exists" means the same thing everywhere.
    pub fn new(proc_root: PathBuf) -> Self {
        let boot_id = read_boot_id(&proc_root);
        Self {
            proc_root,
            probe: PROBE_INTERVAL,
            boot_id,
        }
    }

    /// Overrides the two-sample probe interval (tests). The verdict
    /// thresholds scale with the actual measured window, so a short probe
    /// stays physically meaningful.
    pub fn with_probe_interval(mut self, probe: Duration) -> Self {
        self.probe = probe;
        self
    }

    /// The `/proc` root the probe reads.
    pub fn proc_root(&self) -> &Path {
        &self.proc_root
    }

    /// Measures `tgid`'s runqueue wait right now: two `schedstat` samples
    /// `probe` apart, per-thread Δ aggregated to the process. Every call
    /// measures — there is no gate, no cache, no warm-up.
    pub async fn measure(
        &self,
        tgid: u32,
    ) -> Result<ProcessContentionSnapshot, ContentionMeasureError> {
        let pid_dir = self.proc_root.join(tgid.to_string());
        if !pid_dir.is_dir() {
            return Err(ContentionMeasureError::NotFound);
        }
        let t0 = Instant::now();
        // The process must exist AND have readable schedstat: absence of
        // the latter with presence of the former is degraded
        // infrastructure (CONFIG_SCHEDSTATS off), never a healthy zero.
        let first = match sample_process_wait(&self.proc_root, tgid) {
            Some(s) => s,
            None => {
                return Err(if pid_dir.is_dir() {
                    ContentionMeasureError::Degraded
                } else {
                    ContentionMeasureError::NotFound
                });
            }
        };
        tokio::time::sleep(self.probe).await;
        if !pid_dir.is_dir() {
            return Err(ContentionMeasureError::NotFound);
        }
        let second = sample_process_wait(&self.proc_root, tgid).unwrap_or_default();
        // The honest window is the actual elapsed sample spacing, not the
        // nominal probe — the verdict fractions apply to what was really
        // measured.
        let window_secs = t0.elapsed().as_secs_f64().max(1e-9);
        let (total_ms, worst_ms, threads) = aggregate_wait_delta(&first, &second);
        let measured_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(ProcessContentionSnapshot {
            tgid,
            // Birth identity captured in the same call as the measurement,
            // so the finding can never be rebound to a recycled PID
            // incarnation at query time.
            comm: read_task_comm(&self.proc_root, tgid, tgid),
            start_ticks: read_stat_start_ticks(&self.proc_root, tgid),
            boot_id: self.boot_id.clone(),
            label: "measured",
            verdict: classify_for_window(total_ms, window_secs).as_str(),
            wait_ms: total_ms,
            worst_thread_wait_ms: worst_ms,
            measured_thread_count: threads,
            window_secs,
            measured_at_unix,
        })
    }
}

/// One actionable starvation finding for a scan window: the worst-waiting
/// process, with its wait aggregated across measured threads.
#[derive(Debug, Clone)]
pub struct CpuStarvation {
    /// The victim process's worst-waiting measured thread — the thread to
    /// look at first. Equals `tgid` for single-threaded processes.
    pub tid: u32,
    /// Its thread-group leader (process): the finding's identity.
    pub tgid: u32,
    pub comm: Option<String>,
    /// Measured ms the process's threads spent waiting on a runqueue
    /// inside the window, summed across measured threads. For
    /// single-threaded processes this equals the thread's wait.
    pub wait_ms: f64,
    /// The worst single thread's wait, for context: how concentrated the
    /// starvation is.
    pub worst_thread_wait_ms: f64,
    /// How many of the process's threads were measured this poll.
    pub thread_count: usize,
    /// Seconds the window covers.
    pub window_secs: f64,
    /// Worst waiters for snapshot context: `(tid, tgid, comm, wait_ms)`,
    /// worst first, across all measured processes.
    pub top_waiters: Vec<(u32, u32, Option<String>, f64)>,
    pub verdict: StarvationVerdict,
}

impl CpuStarvation {
    /// Stable identity for cooldown and incident-dedup keys: the victim
    /// process plus its command name. Process-scoped — not per-thread —
    /// on purpose: which thread waits most can flap poll to poll while
    /// the starving process stays the same, and per-thread identities
    /// would let one process's starvation record a row per thread. Two
    /// same-named processes stay distinct via the tgid.
    fn victim_label(&self) -> String {
        let comm = self.comm.clone().unwrap_or_else(|| "unknown".to_string());
        format!("{comm} (tgid={})", self.tgid)
    }
}

/// Deterministic classification: maps a 10s-window aggregate runqueue
/// wait to a [`StarvationVerdict`]. Delegates to [`classify_for_window`]
/// so the monitor and the on-demand probe classify against one physical
/// meaning; at 10s this reproduces the frozen 2000/5000 ms thresholds.
fn classify(wait_ms: f64) -> StarvationVerdict {
    classify_for_window(wait_ms, WINDOW.as_secs_f64())
}

/// `(cpu_time_ns, runqueue_wait_ns)` from a `schedstat` file. Field order is
/// `cpu_time_ns runqueue_wait_ns timeslices` (spec §6). `None` when the file
/// is missing or unparseable — absence is not zero.
fn read_schedstat(path: &Path) -> Option<(u64, u64)> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut fields = content.split_whitespace();
    let cpu_ns = fields.next()?.parse::<u64>().ok()?;
    let wait_ns = fields.next()?.parse::<u64>().ok()?;
    Some((cpu_ns, wait_ns))
}

/// `utime + stime` in clock ticks from `/proc/<pid>/stat` (fields 14, 15).
/// `None` when the file is missing or unparseable — absence is not zero.
/// The comm field may itself contain spaces and parentheses, so fields are
/// split after the *last* `)`.
fn read_stat_cputime(proc_root: &Path, pid: u32) -> Option<u64> {
    let content = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    let after_comm = content.rfind(')')?;
    let mut fields = content[after_comm + 1..].split_whitespace();
    // fields[0] is field 3 (state); utime is field 14, stime field 15.
    let utime = fields.nth(11)?.parse::<u64>().ok()?;
    let stime = fields.next()?.parse::<u64>().ok()?;
    Some(utime.saturating_add(stime))
}

/// Process birth identity: `starttime` in clock ticks since boot from
/// `/proc/<pid>/stat` field 22. Together with the boot ID this names one
/// process *incarnation* — a recycled PID gets a different starttime, so a
/// measurement can never be silently rebound to a new process. `None`
/// when the file is missing or unparseable — absence is not zero, and the
/// snapshot carries the `None` honestly rather than fabricating identity.
fn read_stat_start_ticks(proc_root: &Path, pid: u32) -> Option<u64> {
    let content = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    let after_comm = content.rfind(')')?;
    let mut fields = content[after_comm + 1..].split_whitespace();
    // fields[0] is field 3 (state); starttime is field 22.
    fields.nth(19)?.parse::<u64>().ok()
}

/// Kernel boot ID from `/proc/sys/kernel/random/boot_id`, via the
/// outlet's proc root. Constant for the daemon's lifetime (a reboot kills
/// the daemon); `None` when unreadable.
fn read_boot_id(proc_root: &Path) -> Option<String> {
    let content = std::fs::read_to_string(proc_root.join("sys/kernel/random/boot_id")).ok()?;
    let id = content.trim();
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
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

/// Top-N pids by CPU-time delta, highest first (ties: lowest pid first, so
/// the choice is deterministic). Pure for testability.
fn top_pids_by_cpu(deltas: &mut [(u32, u64)]) -> Vec<u32> {
    deltas.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    deltas
        .iter()
        .take(TOP_PROCESSES_BY_CPU)
        .map(|&(pid, _)| pid)
        .collect()
}
/// Path to a per-thread proc file. The leader's files are also visible at
/// the plain pid path (`/proc/<tgid>/schedstat` is the same file as
/// `/proc/<tgid>/task/<tgid>/schedstat`), which doubles as the fallback
/// when a `task` directory can't be listed.
fn thread_file(proc_root: &Path, tgid: u32, tid: u32, name: &str) -> PathBuf {
    if tid == tgid {
        proc_root.join(tgid.to_string()).join(name)
    } else {
        proc_root
            .join(tgid.to_string())
            .join("task")
            .join(tid.to_string())
            .join(name)
    }
}

fn read_task_comm(proc_root: &Path, tgid: u32, tid: u32) -> Option<String> {
    std::fs::read_to_string(thread_file(proc_root, tgid, tid, "comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// `(tgid, tid)` for every thread under `proc_root`. Falls back to the
/// leader alone when a `task` directory can't be listed.
fn list_threads(proc_root: &Path) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Ok(tgid) = name_str.parse::<u32>() else {
            continue;
        };
        let task_dir = proc_root.join(name_str).join("task");
        let Ok(task_entries) = std::fs::read_dir(&task_dir) else {
            out.push((tgid, tgid));
            continue;
        };
        let mut any = false;
        for task_entry in task_entries.flatten() {
            let task_name = task_entry.file_name();
            let Some(task_str) = task_name.to_str() else {
                continue;
            };
            let Ok(tid) = task_str.parse::<u32>() else {
                continue;
            };
            out.push((tgid, tid));
            any = true;
        }
        if !any {
            out.push((tgid, tgid));
        }
    }
    out
}

/// Per-thread wait baseline: enough history to Δ over the window.
struct ThreadBaseline {
    /// `(sampled_at, runqueue_wait_ns)` within the sliding window.
    samples: VecDeque<(Instant, u64)>,
    last_seen: Instant,
}

/// Per-process wait aggregate for one poll: the sum of the process's
/// measured threads' window waits, plus the worst thread for context.
#[derive(Default)]
struct ProcAggregate {
    total_ms: f64,
    worst_tid: u32,
    worst_ms: f64,
    threads: usize,
}

/// One poll's measured data, shared by the global-threshold path and the
/// watch path so both evaluate the same scan.
struct Poll {
    /// Per-process aggregate wait for every measured process this poll.
    agg: HashMap<u32, ProcAggregate>,
    /// `(tid, tgid, wait_ms)` for every measured thread, worst first.
    waiters: Vec<(u32, u32, f64)>,
}

/// One SLO signal sample posted via `POST /v1/watch/latency`: the observed
/// p99 latency (ms) for the processes a selector names. Carried from the
/// API layer to the monitor over an mpsc channel; the monitor stamps
/// arrival time itself, so the sample carries no clock.
#[derive(Debug, Clone, PartialEq)]
pub struct LatencySample {
    pub selector: WatchSelector,
    pub p99_ms: f64,
}

/// One watch-mode finding: a watched process whose runqueue wait is
/// elevated against its own rolling baseline while its SLO is breaching.
#[derive(Debug, Clone)]
pub struct WatchFinding {
    /// The watched victim process (tgid).
    pub tgid: u32,
    pub comm: Option<String>,
    /// This poll's aggregate wait (ms) — measured.
    pub wait_ms: f64,
    pub worst_thread_wait_ms: f64,
    pub thread_count: usize,
    pub window_secs: f64,
    /// The target's rolling baseline median (ms) the wait is compared
    /// against.
    pub baseline_median_ms: f64,
    /// `wait_ms / baseline_median_ms` — how elevated this poll is
    /// (inferred).
    pub elevation: f64,
    pub elevation_factor: f64,
    /// The breaching p99 sample (ms) — measured.
    pub slo_p99_ms: f64,
    /// The configured breach threshold (ms).
    pub slo_threshold_ms: f64,
    /// `comm=myserver` / `pid=1234` / `cgroup=...` — which target fired.
    pub watch_selector: String,
    /// Worst waiters for snapshot context: `(tid, tgid, comm, wait_ms)`,
    /// worst first, across all measured processes.
    pub top_waiters: Vec<(u32, u32, Option<String>, f64)>,
}

impl WatchFinding {
    /// Stable identity for cooldown and incident-dedup keys. The `"watch"`
    /// verdict component keeps watch incidents from colliding with the
    /// global-threshold path's `(victim, StarvationWarning)` keys: the
    /// same process can be incidented by both paths independently.
    fn victim_label(&self) -> String {
        let comm = self.comm.clone().unwrap_or_else(|| "unknown".to_string());
        format!("{comm} (tgid={})", self.tgid)
    }
}

/// A configured watch target plus its rolling state. One baseline deque
/// per matched process (keyed by tgid): the selector names a workload,
/// but the elevation promise is per process — a shared deque would let
/// one process's waits set another's baseline, and N matched processes
/// would satisfy the warm-up sample count in a single poll.
struct WatchTarget {
    selector: WatchSelector,
    slo_p99_ms: f64,
    elevation_factor: f64,
    baseline_secs: u64,
    /// tgid -> `(sampled_at, aggregate_wait_ms)`: each matched process's
    /// own rolling baseline, pruned to `baseline_secs`. Only polls where
    /// the process was actually measured feed its deque.
    baselines: HashMap<u32, VecDeque<(Instant, f64)>>,
    /// `(received_at, p99_ms)` from the latency endpoint, pruned to the
    /// 90s TTL.
    latency: VecDeque<(Instant, f64)>,
}

impl WatchTarget {
    /// `None` when the config entry fails validation — the daemon skips
    /// such targets with a warning instead of arming nonsense. Mirrors
    /// `--check-config` so a config that was never checked is still safe.
    fn from_config(cfg: &WatchTargetConfig) -> Option<Self> {
        if !cfg.is_valid() {
            return None;
        }
        Some(Self {
            selector: cfg.selector.clone(),
            slo_p99_ms: cfg.slo_p99_ms,
            elevation_factor: cfg.elevation_factor,
            baseline_secs: cfg.baseline_secs,
            baselines: HashMap::new(),
            latency: VecDeque::new(),
        })
    }

    /// Whether the selector names this tgid right now.
    fn matches(&self, tgid: u32, proc_root: &Path) -> bool {
        match &self.selector {
            WatchSelector { pid: Some(pid), .. } => tgid == *pid,
            WatchSelector {
                comm: Some(comm), ..
            } => read_task_comm(proc_root, tgid, tgid).as_deref() == Some(comm.as_str()),
            WatchSelector {
                cgroup: Some(want), ..
            } => std::fs::read_to_string(proc_root.join(tgid.to_string()).join("cgroup"))
                .is_ok_and(|contents| contents.contains(want.as_str())),
            _ => false,
        }
    }
}

/// Median of a sample set. Pure for testability.
fn median_of(mut vals: Vec<f64>) -> f64 {
    vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let n = vals.len();
    if n % 2 == 1 {
        vals[n / 2]
    } else {
        (vals[n / 2 - 1] + vals[n / 2]) / 2.0
    }
}

/// Stateful runqueue-starvation monitor.
pub struct RunqueueStarvationMonitor {
    proc_root: PathBuf,
    interval: Duration,
    wait_baselines: HashMap<u32, ThreadBaseline>,
    /// Per-pid last `utime+stime` (ticks): ranks the next poll's top-50.
    /// Rebuilt every poll; a pid absent one poll re-baselines at zero Δ.
    cpu_baselines: HashMap<u32, u64>,
    /// `None` until the first poll; `Some(false)` while schedstat is
    /// unreadable (degraded, warns once).
    schedstat_available: Option<bool>,
    warn_cooldown: Duration,
    max_iterations: Option<u64>,
    /// When each victim+verdict was last warned about. The verdict
    /// component is the `Debug` verdict for the threshold path and the
    /// literal `"watch"` for watch findings, so the two paths dedup
    /// independently.
    last_warned: HashMap<(String, String), Instant>,
    /// Whether the last incident-record attempt failed (warn-once, then
    /// debug until a record succeeds — `handle_burst` retries every scan).
    record_unhealthy: bool,
    /// Where findings are recorded so they are visible through the API
    /// and MCP tools, not just the daemon logs. `None` keeps the monitor
    /// log-only.
    incident_store: Option<Arc<IncidentStore>>,
    /// Configured watch targets (empty when `[watch]` is absent — watch
    /// mode disarmed).
    watch_targets: Vec<WatchTarget>,
    /// SLO samples posted via `POST /v1/watch/latency`. `None` keeps the
    /// monitor threshold-only.
    latency_rx: Option<mpsc::Receiver<LatencySample>>,
}

impl RunqueueStarvationMonitor {
    pub fn new(interval: Duration) -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            interval,
            wait_baselines: HashMap::new(),
            cpu_baselines: HashMap::new(),
            schedstat_available: None,
            warn_cooldown: DEFAULT_WARN_COOLDOWN,
            max_iterations: None,
            last_warned: HashMap::new(),
            record_unhealthy: false,
            incident_store: None,
            watch_targets: Vec::new(),
            latency_rx: None,
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

    /// Records findings as `cpu_starvation` incidents so they surface
    /// through `/incidents` and the MCP tools, not just the daemon logs.
    /// Takes `Option` to mirror the other monitors: the store may be
    /// unavailable (no DB path), in which case the monitor stays log-only.
    pub fn with_incident_store(mut self, store: Option<Arc<IncidentStore>>) -> Self {
        self.incident_store = store;
        self
    }

    /// Arms the latency/SLO watch mode from `[watch]` config. Invalid
    /// target entries are skipped with a warning — the same validation
    /// `--check-config` applies — so an unchecked config can't arm a
    /// nonsense target.
    pub fn with_watch_config(mut self, watch: WatchConfig) -> Self {
        for (i, cfg) in watch.targets.iter().enumerate() {
            match WatchTarget::from_config(cfg) {
                Some(target) => {
                    info!(
                        "[runqueue] watch target armed: {} (slo_p99_ms={:.1}, elevation_factor={:.1}, baseline_secs={})",
                        target.selector.label(),
                        target.slo_p99_ms,
                        target.elevation_factor,
                        target.baseline_secs
                    );
                    self.watch_targets.push(target);
                }
                None => warn!(
                    "[runqueue] ignoring invalid [[watch.targets]] #{i}: {}",
                    cfg.problems().join("; ")
                ),
            }
        }
        self
    }

    /// Receives SLO samples posted via `POST /v1/watch/latency`. Without
    /// a receiver the monitor stays threshold-only even with targets
    /// configured (their baselines still build, but the dual condition
    /// can never evaluate).
    pub fn with_latency_receiver(mut self, rx: mpsc::Receiver<LatencySample>) -> Self {
        self.latency_rx = Some(rx);
        self
    }

    /// Log-reporting gate: true the first time a victim reports a given
    /// verdict, and again once the cooldown has elapsed. A verdict *change*
    /// for the same victim always reports. This gates the log line only —
    /// incident recording is decided separately against the store (see
    /// `handle_finding`), so a failed insert is retried on the next scan
    /// instead of being swallowed by this cooldown.
    fn should_warn(&mut self, finding: &CpuStarvation) -> bool {
        self.should_warn_key((finding.victim_label(), format!("{:?}", finding.verdict)))
    }

    /// The same gate keyed explicitly. Watch findings use the literal
    /// `"watch"` verdict component so their cooldown is independent of the
    /// threshold path's.
    fn should_warn_key(&mut self, key: (String, String)) -> bool {
        if self.warn_cooldown.is_zero() {
            return true;
        }
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

    /// Folds one poll's `runqueue_wait_ns` reading into the thread's
    /// baseline and returns the measured wait (ms) accumulated inside the
    /// window, or `None` until two samples exist. The wait is the raw Δ —
    /// never divided by a short warm-up span, so a partial window can only
    /// under-report, never inflate.
    ///
    /// The newest sample at or before the window cutoff is retained as
    /// the baseline anchor: polls land slightly more than 5s apart (the
    /// loop sleeps after each scan), so without the anchor the sample
    /// from two polls ago ages just past the window and gets pruned —
    /// leaving a ~5s delta reported as `window_secs = 10`, which can
    /// misclassify a critical as a warning.
    fn update_baseline(&mut self, tid: u32, now: Instant, wait_ns: u64) -> Option<f64> {
        let baseline = self
            .wait_baselines
            .entry(tid)
            .or_insert_with(|| ThreadBaseline {
                samples: VecDeque::new(),
                last_seen: now,
            });
        baseline.last_seen = now;
        // A regressing cumulative counter means the TID was recycled (or
        // the counter wrapped): drop the history and start over rather
        // than fabricating a negative — or wildly positive — Δ.
        if baseline
            .samples
            .back()
            .is_some_and(|&(_, last)| wait_ns < last)
        {
            debug!("[runqueue] runqueue_wait_ns regressed for tid={tid}; re-baselining");
            baseline.samples.clear();
        }
        baseline.samples.push_back((now, wait_ns));
        let cutoff = now.checked_sub(WINDOW).unwrap_or(now);
        // Prune aged samples but keep the anchor: pop the front only while
        // the *second* sample is still at or before the cutoff, so the
        // front remains the newest sample on or before the cutoff. When
        // every sample has aged out, one anchor survives and the
        // two-sample check below yields `None` until fresh data arrives.
        while baseline.samples.len() > 1 && baseline.samples[1].0 <= cutoff {
            baseline.samples.pop_front();
        }
        let &(first_t, first_w) = baseline.samples.front()?;
        let &(last_t, last_w) = baseline.samples.back()?;
        // Distinct samples: `tick` always pushes a fresh `now`, but tests
        // drive `tick_at` directly and may reuse a timestamp.
        if baseline.samples.len() < 2 || last_t <= first_t {
            return None;
        }
        Some(last_w.saturating_sub(first_w) as f64 / 1e6)
    }

    /// One poll of the global-threshold path: rank processes by recent CPU
    /// time, refresh the top-50's threads' wait baselines, aggregate waits
    /// to the process, and return a finding for the worst-waiting process
    /// when it is actionable. The first sighting of a thread only
    /// establishes its baseline.
    pub fn tick(&mut self) -> Option<CpuStarvation> {
        self.tick_at(Instant::now())
    }

    fn tick_at(&mut self, now: Instant) -> Option<CpuStarvation> {
        let poll = self.poll_at(now)?;
        self.threshold_finding(&poll)
    }

    /// One poll driving both detection paths off the same scan: the
    /// global-threshold finding (if any) plus every watch-mode finding.
    fn tick_full_at(&mut self, now: Instant) -> (Option<CpuStarvation>, Vec<WatchFinding>) {
        self.drain_latency(now);
        let Some(poll) = self.poll_at(now) else {
            return (None, Vec::new());
        };
        let threshold = self.threshold_finding(&poll);
        let watch = self.evaluate_watch(&poll, now);
        (threshold, watch)
    }

    /// Test entry for the watch path: one poll's watch findings.
    #[cfg(test)]
    fn watch_tick_at(&mut self, now: Instant) -> Vec<WatchFinding> {
        self.tick_full_at(now).1
    }

    /// One poll: rank processes by recent CPU time, refresh measured
    /// threads' wait baselines, and aggregate waits to the process.
    /// Returns `None` when schedstat is unreadable (degradation — both
    /// detection paths stay silent).
    fn poll_at(&mut self, now: Instant) -> Option<Poll> {
        // Phase 1: rank processes by CPU time consumed since the last poll
        // (`utime+stime` Δ). A first sighting has no Δ yet and ranks zero —
        // ranking converges from the second poll. Absence is not zero, so
        // unreadable stat files simply don't rank.
        let mut deltas: Vec<(u32, u64)> = Vec::new();
        let mut cpu_now: HashMap<u32, u64> = HashMap::new();
        let mut pids: Vec<u32> = Vec::new();
        for pid in list_pids(&self.proc_root) {
            let Some(cputime) = read_stat_cputime(&self.proc_root, pid) else {
                continue;
            };
            let last = self.cpu_baselines.get(&pid).copied().unwrap_or(cputime);
            deltas.push((pid, cputime.saturating_sub(last)));
            cpu_now.insert(pid, cputime);
            pids.push(pid);
        }
        self.cpu_baselines = cpu_now;
        let top: HashSet<u32> = top_pids_by_cpu(&mut deltas).into_iter().collect();
        // Watch targets bypass the top-50 gate: the operator explicitly
        // asked for these processes, and the cost is a few extra schedstat
        // reads.
        let watched = self.resolve_watched_tgids(&pids);
        // Phase 2: read schedstat for the top-50's threads plus every
        // watched process's threads — the cost bound, widened only by the
        // explicit watch list. Threads outside both sets aren't measured
        // this poll; their baselines keep aging and are pruned after 60s
        // idle. (Per-PID queries no longer ride this poll: they are
        // measured on demand by ContentionProbe.)
        let mut any_schedstat = false;
        // `(tid, tgid, wait_ms)` for every measured thread with a
        // measurable window.
        let mut waiters: Vec<(u32, u32, f64)> = Vec::new();
        for (tgid, tid) in list_threads(&self.proc_root) {
            if !top.contains(&tgid) && !watched.contains(&tgid) {
                continue;
            }
            let sched_path = thread_file(&self.proc_root, tgid, tid, "schedstat");
            let Some((_, wait_ns)) = read_schedstat(&sched_path) else {
                continue;
            };
            any_schedstat = true;
            if let Some(wait_ms) = self.update_baseline(tid, now, wait_ns) {
                waiters.push((tid, tgid, wait_ms));
            }
        }

        // Drop baselines for threads long gone so the map stays bounded.
        // (Before the degradation early-return: an empty scan must still
        // prune.)
        self.wait_baselines
            .retain(|_, b| now.duration_since(b.last_seen) < STALE_BASELINE);

        // Degradation: no schedstat anywhere means CONFIG_SCHEDSTATS is
        // off (or /proc is otherwise unusable). Disable findings — warn
        // once, never fabricate — and resume if the files appear.
        if !any_schedstat {
            if self.schedstat_available != Some(false) {
                warn!(
                    "[runqueue] no readable schedstat files; CONFIG_SCHEDSTATS is likely off — \
                     starvation detection disabled until they appear"
                );
            }
            self.schedstat_available = Some(false);
            return None;
        }
        if self.schedstat_available == Some(false) {
            info!("[runqueue] schedstat readable again; starvation detection resumed");
        }
        self.schedstat_available = Some(true);

        waiters.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(Ordering::Equal));
        // Aggregate to the process: sum each measured thread's window wait
        // under its tgid. A thread contributes at most its own Δ per poll —
        // short-lived threads only appear once they have two samples, and
        // recycled TIDs re-baseline on counter regression — so the sum
        // can't double-count.
        let mut agg: HashMap<u32, ProcAggregate> = HashMap::new();
        for &(tid, tgid, wait_ms) in &waiters {
            let e = agg.entry(tgid).or_default();
            e.total_ms += wait_ms;
            e.threads += 1;
            if wait_ms > e.worst_ms {
                e.worst_tid = tid;
                e.worst_ms = wait_ms;
            }
        }
        Some(Poll { agg, waiters })
    }

    /// The worst-waiting process in one poll's scan, classified against the
    /// global 2000/5000 ms thresholds. Unchanged behavior — the coarse net
    /// stays exactly as it was.
    fn threshold_finding(&self, poll: &Poll) -> Option<CpuStarvation> {
        // Worst process by aggregate wait; ties break toward the lowest
        // tgid so the pick is deterministic.
        let (&tgid, worst) = poll.agg.iter().max_by(|a, b| {
            a.1.total_ms
                .partial_cmp(&b.1.total_ms)
                .unwrap_or(Ordering::Equal)
                .then_with(|| b.0.cmp(a.0))
        })?;
        let verdict = classify(worst.total_ms);
        if !verdict.actionable() {
            return None;
        }
        let top_waiters: Vec<(u32, u32, Option<String>, f64)> = poll
            .waiters
            .iter()
            .take(TOP_WAITERS_IN_SNAPSHOT)
            .map(|&(tid, tgid, wait_ms)| {
                (
                    tid,
                    tgid,
                    read_task_comm(&self.proc_root, tgid, tid),
                    wait_ms,
                )
            })
            .collect();
        let comm = read_task_comm(&self.proc_root, tgid, tgid)
            // The leader's comm can be momentarily unreadable (exec in
            // flight); fall back to the worst thread's rather than
            // reporting unknown.
            .or_else(|| read_task_comm(&self.proc_root, tgid, worst.worst_tid));
        Some(CpuStarvation {
            tid: worst.worst_tid,
            tgid,
            comm,
            wait_ms: worst.total_ms,
            worst_thread_wait_ms: worst.worst_ms,
            thread_count: worst.threads,
            window_secs: WINDOW.as_secs_f64(),
            top_waiters,
            verdict,
        })
    }

    /// tgids the watch selectors name this poll, for the top-50 bypass.
    fn resolve_watched_tgids(&self, pids: &[u32]) -> HashSet<u32> {
        let mut out = HashSet::new();
        if self.watch_targets.is_empty() {
            return out;
        }
        for target in &self.watch_targets {
            match &target.selector {
                WatchSelector { pid: Some(pid), .. } => {
                    if pids.contains(pid) {
                        out.insert(*pid);
                    }
                }
                WatchSelector {
                    comm: Some(comm), ..
                } => {
                    for pid in pids {
                        if read_task_comm(&self.proc_root, *pid, *pid).as_deref()
                            == Some(comm.as_str())
                        {
                            out.insert(*pid);
                        }
                    }
                }
                WatchSelector {
                    cgroup: Some(want), ..
                } => {
                    for pid in pids {
                        let path = self.proc_root.join(pid.to_string()).join("cgroup");
                        if std::fs::read_to_string(&path)
                            .is_ok_and(|contents| contents.contains(want.as_str()))
                        {
                            out.insert(*pid);
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }

    /// Pulls every pending SLO sample off the channel into its target's
    /// latency deque, stamped with arrival time. Samples naming no
    /// configured target are dropped (debug): posting for a selector
    /// nobody watches is not an error.
    fn drain_latency(&mut self, now: Instant) {
        let Some(rx) = &mut self.latency_rx else {
            return;
        };
        while let Ok(sample) = rx.try_recv() {
            let mut matched = false;
            for target in &mut self.watch_targets {
                if target.selector == sample.selector {
                    target.latency.push_back((now, sample.p99_ms));
                    matched = true;
                }
            }
            if !matched {
                debug!(
                    "[runqueue] watch latency sample for unconfigured selector {}; dropping",
                    sample.selector.label()
                );
            }
        }
    }

    /// Watch-mode evaluation over one poll's scan. For every target, every
    /// matched process that was actually measured this poll feeds its own
    /// per-process rolling baseline; a finding fires only when the
    /// process's wait is elevated against that baseline AND a fresh p99
    /// sample is breaching the SLO. Either condition alone stays silent.
    /// A stale or absent signal means the dual condition cannot be
    /// evaluated, so the target stays silent — debug, never warn.
    fn evaluate_watch(&mut self, poll: &Poll, now: Instant) -> Vec<WatchFinding> {
        let mut findings = Vec::new();
        for target in &mut self.watch_targets {
            let label = target.selector.label();
            // Prune each process's PRIOR points to the configured window
            // first, and drop deques that pruned to empty so dead pids
            // don't accumulate entries across pid reuse.
            let baseline_window = Duration::from_secs(target.baseline_secs);
            for deque in target.baselines.values_mut() {
                deque.retain(|(at, _)| now.duration_since(*at) <= baseline_window);
            }
            target.baselines.retain(|_, deque| !deque.is_empty());
            // And the SLO signal to its TTL.
            target
                .latency
                .retain(|(at, _)| now.duration_since(*at) <= WATCH_LATENCY_TTL);

            // Collect this poll's matched measurements, but do NOT feed
            // them into the baseline yet: evaluation compares the current
            // wait against the median of PRIOR points, so an elevated
            // sample can never raise its own reference.
            let mut matched: Vec<(u32, f64, u32, f64, usize)> = Vec::new();
            for (&tgid, agg) in &poll.agg {
                if target.matches(tgid, &self.proc_root) {
                    matched.push((tgid, agg.total_ms, agg.worst_tid, agg.worst_ms, agg.threads));
                }
            }

            let breaching_p99 = match target.latency.back() {
                Some(&(_, p99)) if p99 >= target.slo_p99_ms => Some(p99),
                _ => {
                    debug!(
                        "[runqueue] watch {label}: no SLO sample breaching {:.1}ms within TTL; staying silent",
                        target.slo_p99_ms
                    );
                    None
                }
            };

            for &(tgid, wait_ms, _worst_tid, worst_ms, threads) in &matched {
                // Each process is evaluated against its OWN baseline: a
                // shared median would let one process's waits set
                // another's reference.
                let prior = target.baselines.get(&tgid).map(VecDeque::len).unwrap_or(0);
                if prior < MIN_WATCH_BASELINE_SAMPLES {
                    debug!(
                        "[runqueue] watch {label} tgid={tgid}: {prior}/{} baseline samples, not evaluating yet",
                        MIN_WATCH_BASELINE_SAMPLES
                    );
                    continue;
                }
                let median = median_of(target.baselines[&tgid].iter().map(|&(_, w)| w).collect());
                let Some(p99) = breaching_p99 else {
                    continue;
                };
                if wait_ms <= target.elevation_factor * median {
                    continue;
                }
                let top_waiters: Vec<(u32, u32, Option<String>, f64)> = poll
                    .waiters
                    .iter()
                    .take(TOP_WAITERS_IN_SNAPSHOT)
                    .map(|&(tid, tgid, wait_ms)| {
                        (
                            tid,
                            tgid,
                            read_task_comm(&self.proc_root, tgid, tid),
                            wait_ms,
                        )
                    })
                    .collect();
                findings.push(WatchFinding {
                    tgid,
                    comm: read_task_comm(&self.proc_root, tgid, tgid),
                    wait_ms,
                    worst_thread_wait_ms: worst_ms,
                    thread_count: threads,
                    window_secs: WINDOW.as_secs_f64(),
                    baseline_median_ms: median,
                    // The divisor floor keeps the snapshot serializable
                    // when the baseline median is exactly zero (any
                    // positive wait is then infinitely elevated).
                    elevation: wait_ms / median.max(1e-6),
                    elevation_factor: target.elevation_factor,
                    slo_p99_ms: p99,
                    slo_threshold_ms: target.slo_p99_ms,
                    watch_selector: label.clone(),
                    top_waiters,
                });
            }

            // Feed this poll's matched measurements into each process's
            // rolling baseline AFTER evaluation, whether or not anything
            // fired: the baseline tracks the workload continuously, and
            // the next poll's median sees this poll as a prior point.
            for &(tgid, wait_ms, _, _, _) in &matched {
                target
                    .baselines
                    .entry(tgid)
                    .or_default()
                    .push_back((now, wait_ms));
            }
        }
        findings
    }

    pub async fn run(mut self) {
        info!("[runqueue] starting runqueue starvation monitor");
        let mut iterations = 0u64;
        loop {
            let (threshold, watch) = self.tick_full_at(Instant::now());
            if let Some(finding) = threshold {
                self.handle_finding(&finding).await;
            }
            for finding in &watch {
                self.handle_watch_finding(finding).await;
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
    /// Logging rides `should_warn`'s cooldown — a starving thread is one log
    /// line, not one per poll. Recording is gated only on the store itself,
    /// which is the source of truth for what was persisted: the log
    /// cooldown never suppresses a record attempt, so a transient insert
    /// failure is retried on the next scan instead of vanishing for the
    /// whole cooldown.
    async fn handle_finding(&mut self, finding: &CpuStarvation) {
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
            .recent_incident_keys("cpu_starvation", self.warn_cooldown.as_secs())
            .await
        {
            Ok(keys) => keys,
            Err(e) => {
                warn!("[runqueue] couldn't check recent incidents: {e}");
                HashSet::new()
            }
        }
    }

    /// Best-effort: a failing store must not break the monitoring loop.
    /// The first failure logs at warn level; repeats stay at debug until a
    /// record succeeds, since `handle_finding` retries the insert on every
    /// scan while the starvation continues.
    async fn record_incident(&mut self, finding: &CpuStarvation) {
        let Some(store) = &self.incident_store else {
            return;
        };
        let incident = incident_from_finding(finding);
        match store.insert(&incident).await {
            Ok(id) => {
                debug!(
                    "[runqueue] recorded incident #{id} for {}",
                    finding.victim_label()
                );
                self.record_unhealthy = false;
            }
            Err(e) => {
                if self.record_unhealthy {
                    debug!(
                        "[runqueue] still failing to record incident for {}: {e}",
                        finding.victim_label()
                    );
                } else {
                    warn!(
                        "[runqueue] failed to record incident for {}: {e}",
                        finding.victim_label()
                    );
                    self.record_unhealthy = true;
                }
            }
        }
    }

    /// Watch-mode counterpart to `handle_finding`: the cooldown key uses
    /// the literal `"watch"` verdict and the store-backed dedup reads the
    /// same `(victim, "watch")` pair from `$.verdict`, so the same victim
    /// can be incidented by the threshold path and the watch path without
    /// either suppressing the other.
    async fn handle_watch_finding(&mut self, finding: &WatchFinding) {
        if self.should_warn_key((finding.victim_label(), "watch".to_string())) {
            report_watch(finding);
        }
        let key = (finding.victim_label(), "watch".to_string());
        if self.recently_recorded_keys().await.contains(&key) {
            return;
        }
        self.record_watch_incident(finding).await;
    }

    /// Best-effort insert of a watch finding as a `cpu_starvation`
    /// incident. Shares the failure discipline with `record_incident`:
    /// warn once, debug on repeats, retried on every scan while the
    /// condition holds.
    async fn record_watch_incident(&mut self, finding: &WatchFinding) {
        let Some(store) = &self.incident_store else {
            return;
        };
        let incident = incident_from_watch_finding(finding);
        match store.insert(&incident).await {
            Ok(id) => {
                debug!(
                    "[runqueue] recorded watch incident #{id} for {}",
                    finding.victim_label()
                );
                self.record_unhealthy = false;
            }
            Err(e) => {
                if self.record_unhealthy {
                    debug!(
                        "[runqueue] still failing to record watch incident for {}: {e}",
                        finding.victim_label()
                    );
                } else {
                    warn!(
                        "[runqueue] failed to record watch incident for {}: {e}",
                        finding.victim_label()
                    );
                    self.record_unhealthy = true;
                }
            }
        }
    }
}

/// Builds the `cpu_starvation` incident row for one finding.
///
/// Field mapping, kept honest about what this monitor measures:
/// * `psi_cpu` / `psi_memory` / `cpu_percent` / `load_avg` are host-level
///   fields this monitor doesn't sample, so they're zero/empty; the
///   triggering reading is the process's aggregate runqueue wait, carried
///   in `system_snapshot`.
/// * `target_pid` / `target_name` name the *measured* victim process
///   (tgid); the worst thread rides along in the snapshot.
/// * The offender is `unavailable`: naming which threads preempted the
///   victim needs eBPF `sched_switch` (spec §4). Correlate with
///   `cgroup_pressure` incidents for the `inferred` version.
fn incident_from_finding(finding: &CpuStarvation) -> Incident {
    let top_waiters: Vec<serde_json::Value> = finding
        .top_waiters
        .iter()
        .map(|(tid, tgid, comm, wait_ms)| {
            serde_json::json!({
                "tid": tid,
                "tgid": tgid,
                "comm": comm,
                "wait_ms": wait_ms,
            })
        })
        .collect();
    let snapshot = serde_json::json!({
        "tid": finding.tid,
        "tgid": finding.tgid,
        "comm": finding.comm,
        // The thresholded quantity: the process's aggregate wait across
        // its measured threads. worst_thread_wait_ms says how
        // concentrated it is.
        "wait_ms": finding.wait_ms,
        "worst_thread_wait_ms": finding.worst_thread_wait_ms,
        "thread_count": finding.thread_count,
        "window_secs": finding.window_secs,
        "top_waiters": top_waiters,
        "source_tier": "polling",
        "verdict": format!("{:?}", finding.verdict),
        // The victim's wait is a measured kernel counter; the offender is
        // not identified — that needs eBPF.
        "evidence": {
            "runqueue_wait": "measured",
            "offender": "unavailable",
        },
    });
    Incident {
        id: None,
        timestamp: chrono::Utc::now().timestamp(),
        event_type: "cpu_starvation".to_string(),
        psi_cpu: 0.0,
        psi_memory: 0.0,
        cpu_percent: 0.0,
        load_avg: String::new(),
        action: "alert".to_string(),
        target_pid: Some(finding.tgid as i32),
        target_name: Some(finding.victim_label()),
        system_snapshot: serde_json::to_string(&snapshot).ok(),
        llm_analysis: None,
        llm_analyzed_at: None,
        investigation: None,
        recovery_time_ms: None,
        psi_after: None,
    }
}

/// Builds the `cpu_starvation` incident row for a watch-mode finding.
/// The verdict is the literal `"watch"`, and the store-backed dedup reads
/// `$.verdict` from the snapshot, so `recent_incident_keys` returns
/// `(victim, "watch")` pairs that never collide with the threshold path's
/// `StarvationWarning`/`StarvationCritical` keys.
///
/// Field mapping, kept honest about what watch mode measures:
/// * `detection_mode: "watch"` marks the path that fired.
/// * `wait_ms` / `baseline_median_ms` / `elevation` / `elevation_factor`
///   describe the wait against the workload's own baseline.
/// * `slo_p99_ms` / `slo_threshold_ms` describe the breaching SLO signal.
/// * `watch_selector` names the configured target that fired.
/// * `target_pid` / `target_name` name the *measured* victim process
///   (tgid); the worst thread rides along in the snapshot.
/// * The offender is `unavailable`: naming which threads preempted the
///   victim needs eBPF `sched_switch` (spec §4).
fn incident_from_watch_finding(finding: &WatchFinding) -> Incident {
    let top_waiters: Vec<serde_json::Value> = finding
        .top_waiters
        .iter()
        .map(|(tid, tgid, comm, wait_ms)| {
            serde_json::json!({
                "tid": tid,
                "tgid": tgid,
                "comm": comm,
                "wait_ms": wait_ms,
            })
        })
        .collect();
    let snapshot = serde_json::json!({
        "detection_mode": "watch",
        "tgid": finding.tgid,
        "comm": finding.comm,
        // This poll's aggregate wait across the victim's measured
        // threads; worst_thread_wait_ms says how concentrated it is.
        "wait_ms": finding.wait_ms,
        "worst_thread_wait_ms": finding.worst_thread_wait_ms,
        "thread_count": finding.thread_count,
        "window_secs": finding.window_secs,
        // The target's own rolling baseline this wait is judged against.
        "baseline_median_ms": finding.baseline_median_ms,
        "elevation": finding.elevation,
        "elevation_factor": finding.elevation_factor,
        // The breaching SLO signal that armed the finding.
        "slo_p99_ms": finding.slo_p99_ms,
        "slo_threshold_ms": finding.slo_threshold_ms,
        "watch_selector": finding.watch_selector,
        "top_waiters": top_waiters,
        "source_tier": "polling",
        // Literal "watch": the store-backed dedup key reads $.verdict.
        "verdict": "watch",
        // The wait and the SLO breach are measured kernel/endpoint
        // readings; the elevation is inferred (higher *than usual for
        // this workload*, not higher than an absolute line); the offender
        // is not identified — that needs eBPF.
        "evidence": {
            "runqueue_wait": "measured",
            "baseline_elevation": "inferred",
            "slo_breach": "measured",
            "offender": "unavailable",
        },
    });
    Incident {
        id: None,
        timestamp: chrono::Utc::now().timestamp(),
        event_type: "cpu_starvation".to_string(),
        psi_cpu: 0.0,
        psi_memory: 0.0,
        cpu_percent: 0.0,
        load_avg: String::new(),
        action: "alert".to_string(),
        target_pid: Some(finding.tgid as i32),
        target_name: Some(finding.victim_label()),
        system_snapshot: serde_json::to_string(&snapshot).ok(),
        llm_analysis: None,
        llm_analyzed_at: None,
        investigation: None,
        recovery_time_ms: None,
        psi_after: None,
    }
}

/// One human- and agent-readable line per watch finding: wait and SLO
/// breach are `measured`, the elevation against the baseline is
/// `inferred`, no offender is named.
fn report_watch(finding: &WatchFinding) {
    let name = finding.comm.as_deref().unwrap_or("unknown");
    warn!(
        "[runqueue] WATCH: process {name} (tgid={}) waited {:.0}ms for CPU over the last {:.0}s \
         ({:.1}x its {:.0}ms baseline, factor {:.1}) while p99 {:.1}ms breached SLO {:.1}ms \
         [wait measured, elevation inferred, SLO breach measured, offender unavailable]",
        finding.tgid,
        finding.wait_ms,
        finding.window_secs,
        finding.elevation,
        finding.baseline_median_ms,
        finding.elevation_factor,
        finding.slo_p99_ms,
        finding.slo_threshold_ms
    );
}

/// One human- and agent-readable line per actionable finding. The wait is
/// `measured`; no offender is named — the tag says which is which.
/// Single-threaded victims keep the historic per-thread line (the
/// aggregate *is* the thread's wait there); multi-threaded victims report
/// the aggregate plus the worst thread.
fn report(finding: &CpuStarvation) {
    let name = finding.comm.as_deref().unwrap_or("unknown");
    let (victim, detail) = if finding.thread_count <= 1 {
        let pct = finding.wait_ms / 1000.0 / finding.window_secs * 100.0;
        (
            format!("thread {name} (tid={})", finding.tid),
            format!("{pct:.0}% of window"),
        )
    } else {
        (
            format!(
                "process {name} (tgid={}, {} threads)",
                finding.tgid, finding.thread_count
            ),
            format!(
                "worst thread tid={}: {:.0}ms",
                finding.tid, finding.worst_thread_wait_ms
            ),
        )
    };
    match finding.verdict {
        StarvationVerdict::StarvationWarning => warn!(
            "[runqueue] WARNING: {victim} waited {:.0}ms for CPU over the last {:.0}s ({detail}) [wait measured, offender unavailable]",
            finding.wait_ms, finding.window_secs
        ),
        StarvationVerdict::StarvationCritical => warn!(
            "[runqueue] CRITICAL: {victim} waited {:.0}ms for CPU over the last {:.0}s ({detail}) — effectively starved [wait measured, offender unavailable]",
            finding.wait_ms, finding.window_secs
        ),
        StarvationVerdict::Healthy => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// A fake `/proc` tree: `<dir>/<pid>/task/<tid>/{schedstat,comm}`.
    struct FakeProc {
        dir: TempDir,
    }

    impl FakeProc {
        fn new() -> Self {
            Self {
                dir: TempDir::new().unwrap(),
            }
        }

        fn task_dir(&self, pid: u32, tid: u32) -> PathBuf {
            let d = self
                .dir
                .path()
                .join(pid.to_string())
                .join("task")
                .join(tid.to_string());
            fs::create_dir_all(&d).unwrap();
            d
        }

        /// (Re)places a thread's schedstat (cpu_ns fixed) and comm, plus a
        /// default `<pid>/stat` (constant CPU time) so the process ranks.
        /// Use `set_stat` afterwards for explicit CPU-time control.
        fn set_thread(&self, pid: u32, tid: u32, comm: &str, wait_ns: u64) {
            let d = self.task_dir(pid, tid);
            fs::write(d.join("schedstat"), format!("1000000 {wait_ns} 7\n")).unwrap();
            fs::write(d.join("comm"), format!("{comm}\n")).unwrap();
            self.set_stat(pid, 1000, 0);
            if pid == tid {
                // The kernel aliases /proc/<tgid>/schedstat to
                // /proc/<tgid>/task/<tgid>/schedstat; mirror the alias so
                // the monitor reads what the fixture wrote.
                let leader = self.dir.path().join(pid.to_string());
                fs::write(leader.join("schedstat"), format!("1000000 {wait_ns} 7\n")).unwrap();
                fs::write(leader.join("comm"), format!("{comm}\n")).unwrap();
            }
        }

        /// (Re)places `<pid>/stat` with the given utime/stime (ticks).
        /// Fields 14/15 are parsed after the last `)`; the comm may itself
        /// contain parens.
        fn set_stat(&self, pid: u32, utime: u64, stime: u64) {
            // Deterministic birth identity for the fake proc: one
            // incarnation per pid unless set_stat_start says otherwise.
            self.set_stat_start(pid, utime, stime, u64::from(pid) * 1000 + 42);
        }

        fn set_stat_start(&self, pid: u32, utime: u64, stime: u64, start_ticks: u64) {
            let d = self.dir.path().join(pid.to_string());
            fs::create_dir_all(&d).unwrap();
            fs::write(
                d.join("stat"),
                format!(
                    "{pid} (comm (with) parens) R 0 0 0 0 0 0 0 0 0 0 {utime} {stime} 0 0 0 0 0 0 {start_ticks}\n"
                ),
            )
            .unwrap();
        }

        fn remove_pid(&self, pid: u32) {
            fs::remove_dir_all(self.dir.path().join(pid.to_string())).unwrap();
        }

        fn monitor(&self) -> RunqueueStarvationMonitor {
            RunqueueStarvationMonitor::new(Duration::from_secs(5)).with_proc_root(self.dir.path())
        }

        /// Writes `<pid>/cgroup` with the given contents, for
        /// cgroup-selector watch tests.
        fn set_cgroup(&self, pid: u32, contents: &str) {
            let d = self.dir.path().join(pid.to_string());
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("cgroup"), contents).unwrap();
        }

        /// Monitor with watch targets armed and a latency channel;
        /// returns the sender so tests can post SLO samples.
        fn watch_monitor(
            &self,
            targets: Vec<WatchTargetConfig>,
        ) -> (RunqueueStarvationMonitor, mpsc::Sender<LatencySample>) {
            let (tx, rx) = mpsc::channel::<LatencySample>(WATCH_LATENCY_CHANNEL_CAP);
            let mon = self
                .monitor()
                .with_watch_config(WatchConfig {
                    targets,
                    ..Default::default()
                })
                .with_latency_receiver(rx);
            (mon, tx)
        }
    }

    fn warning_finding(comm: &str) -> CpuStarvation {
        CpuStarvation {
            tid: 4242,
            tgid: 4242,
            comm: Some(comm.to_string()),
            wait_ms: 2500.0,
            worst_thread_wait_ms: 2500.0,
            thread_count: 1,
            window_secs: 10.0,
            top_waiters: vec![(4242, 4242, Some(comm.to_string()), 2500.0)],
            verdict: StarvationVerdict::StarvationWarning,
        }
    }

    /// A `[watch]` target for tests: pid selector, SLO p99 100ms,
    /// 3x elevation factor, 1h baseline window.
    fn pid_target(pid: u32) -> WatchTargetConfig {
        WatchTargetConfig {
            selector: WatchSelector::pid(pid),
            slo_p99_ms: 100.0,
            elevation_factor: 3.0,
            baseline_secs: 3600,
            ..Default::default()
        }
    }

    /// Runs `n` polls at 5s intervals, advancing `wait_ns` by `step_ns`
    /// per poll for the given thread. Returns the time of the last poll.
    /// Note the monitor measures wait over a 10s window while polls are 5s
    /// apart, so a steady `step_ns`/poll advance reads as `2 * step_ns`
    /// per poll once the window fills (the first poll reads `step_ns`).
    #[allow(clippy::too_many_arguments)]
    fn run_baseline_polls(
        fake: &FakeProc,
        mon: &mut RunqueueStarvationMonitor,
        pid: u32,
        tid: u32,
        comm: &str,
        n: usize,
        step_ns: u64,
        t0: Instant,
    ) -> Instant {
        let mut t = t0;
        for k in 0..n {
            fake.set_thread(pid, tid, comm, k as u64 * step_ns);
            let findings = mon.watch_tick_at(t);
            assert!(
                findings.is_empty(),
                "no watch finding expected while the baseline is building (poll {k})"
            );
            t += Duration::from_secs(5);
        }
        t
    }

    /// `wait_ns` to write for the "elevated" poll after `n_polls`
    /// baseline polls of `step_ns`/poll: the monitor's 10s window anchors
    /// on the sample two polls back, so the measured wait is
    /// `wait_ns - (n_polls - 2) * step_ns`. A `jump_ns` here reads as
    /// exactly `jump_ns` ms of wait.
    fn elevated_wait_ns(n_polls: u64, step_ns: u64, jump_ns: u64) -> u64 {
        (n_polls - 2) * step_ns + jump_ns
    }

    #[test]
    fn classify_matrix() {
        assert_eq!(classify(0.0), StarvationVerdict::Healthy);
        assert_eq!(classify(1999.9), StarvationVerdict::Healthy);
        assert_eq!(classify(2000.0), StarvationVerdict::StarvationWarning);
        assert_eq!(classify(4999.9), StarvationVerdict::StarvationWarning);
        assert_eq!(classify(5000.0), StarvationVerdict::StarvationCritical);
        assert_eq!(classify(60_000.0), StarvationVerdict::StarvationCritical);
    }

    #[test]
    fn first_tick_establishes_baseline() {
        let fake = FakeProc::new();
        fake.set_thread(1, 1, "init", 0);
        let mut mon = fake.monitor();
        assert!(
            mon.tick_at(Instant::now()).is_none(),
            "first sighting of a thread must be baseline-only"
        );
    }

    #[test]
    fn detects_warning_and_critical_waits() {
        let t0 = Instant::now();
        // 2500 ms waited over the 10s window -> warning.
        let fake = FakeProc::new();
        let mut mon = fake.monitor();
        fake.set_thread(1, 7, "hungry", 0);
        assert!(mon.tick_at(t0).is_none());
        fake.set_thread(1, 7, "hungry", 1_250_000_000);
        assert!(mon.tick_at(t0 + Duration::from_secs(5)).is_none());
        fake.set_thread(1, 7, "hungry", 2_500_000_000);
        let finding = mon
            .tick_at(t0 + Duration::from_secs(10))
            .expect("2500ms wait must warn");
        assert_eq!(finding.verdict, StarvationVerdict::StarvationWarning);
        assert!((finding.wait_ms - 2500.0).abs() < 1e-9);
        assert_eq!(finding.tid, 7);
        assert_eq!(finding.comm.as_deref(), Some("hungry"));

        // 6000 ms waited over the window -> critical. The intermediate
        // 5s poll already sees 3000 ms -> warning.
        let fake = FakeProc::new();
        let mut mon = fake.monitor();
        fake.set_thread(1, 7, "hungry", 0);
        assert!(mon.tick_at(t0).is_none());
        fake.set_thread(1, 7, "hungry", 3_000_000_000);
        let mid = mon
            .tick_at(t0 + Duration::from_secs(5))
            .expect("3000ms over 5s must warn");
        assert_eq!(mid.verdict, StarvationVerdict::StarvationWarning);
        fake.set_thread(1, 7, "hungry", 6_000_000_000);
        let finding = mon
            .tick_at(t0 + Duration::from_secs(10))
            .expect("6000ms wait must be critical");
        assert_eq!(finding.verdict, StarvationVerdict::StarvationCritical);
    }

    #[test]
    fn warmup_does_not_inflate_partial_windows() {
        // 1500 ms waited over the first 5s is reported as 1500 ms — not
        // scaled up to a full window. A partial window can only
        // under-report, never inflate into a verdict.
        let fake = FakeProc::new();
        fake.set_thread(1, 7, "hungry", 0);
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        assert!(mon.tick_at(t0).is_none());
        fake.set_thread(1, 7, "hungry", 1_500_000_000);
        assert!(
            mon.tick_at(t0 + Duration::from_secs(5)).is_none(),
            "a partial-window wait must not be scaled up into a warning"
        );
        // Once the window fills with a genuinely large wait, it fires.
        fake.set_thread(1, 7, "hungry", 2_500_000_000);
        let finding = mon
            .tick_at(t0 + Duration::from_secs(10))
            .expect("2500ms over the full window must warn");
        assert_eq!(finding.verdict, StarvationVerdict::StarvationWarning);
    }

    #[test]
    fn window_anchor_spans_full_window_at_uneven_poll_spacing() {
        // Polls land 5.2s apart: the loop sleeps 5s *after* each scan and
        // any incident handling. Without a baseline anchor, the t0 sample
        // ages just past the 10s window on the third poll and gets pruned,
        // leaving a ~5.2s delta reported as window_secs = 10 — a 5000ms
        // critical misclassified as a warning. The anchor retains the
        // newest sample at or before the cutoff, so the delta spans the
        // full window.
        let fake = FakeProc::new();
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        fake.set_thread(1, 7, "hungry", 0);
        assert!(mon.tick_at(t0).is_none());
        fake.set_thread(1, 7, "hungry", 2_500_000_000);
        let mid = mon
            .tick_at(t0 + Duration::from_millis(5200))
            .expect("2500ms over 5.2s must warn");
        assert_eq!(mid.verdict, StarvationVerdict::StarvationWarning);
        fake.set_thread(1, 7, "hungry", 5_000_000_000);
        let finding = mon
            .tick_at(t0 + Duration::from_millis(10_400))
            .expect("5000ms over the full window must fire");
        assert_eq!(
            finding.verdict,
            StarvationVerdict::StarvationCritical,
            "the window delta must span the full 10s, not just the last 5.2s"
        );
        assert!((finding.wait_ms - 5000.0).abs() < 1e-9);
    }

    #[test]
    fn same_process_victims_share_one_identity() {
        // Identity is the process now: two threads of the same tgid are
        // one victim — aggregation subsumes per-thread findings — while
        // two same-comm *processes* still warn independently.
        let mut mon = RunqueueStarvationMonitor::new(Duration::from_secs(5));
        let a = CpuStarvation {
            tid: 7,
            tgid: 1,
            ..warning_finding("worker")
        };
        let b = CpuStarvation {
            tid: 8,
            tgid: 1,
            ..warning_finding("worker")
        };
        let c = CpuStarvation {
            tid: 9,
            tgid: 2,
            ..warning_finding("worker")
        };
        assert!(mon.should_warn(&a), "first victim must warn");
        assert!(
            !mon.should_warn(&b),
            "a second thread of the same process is the same victim"
        );
        assert!(
            mon.should_warn(&c),
            "a different tgid with the same comm must warn too"
        );
    }

    #[test]
    fn worst_process_by_aggregate_wins() {
        // Process 1: one thread at 4000 ms. Process 2: three threads at
        // 1500 ms each — no single thread actionable, but the 4500 ms
        // aggregate beats process 1's 4000 ms. Per-thread ranking would
        // have picked process 1; aggregation picks process 2.
        let fake = FakeProc::new();
        fake.set_thread(1, 1, "solo", 0);
        for tid in [2u32, 10, 11, 12] {
            fake.set_thread(2, tid, "spread", 0);
        }
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        assert!(mon.tick_at(t0).is_none());
        fake.set_thread(1, 1, "solo", 4_000_000_000);
        for tid in [10u32, 11, 12] {
            fake.set_thread(2, tid, "spread", 1_500_000_000);
        }
        let finding = mon
            .tick_at(t0 + Duration::from_secs(10))
            .expect("the 4500ms aggregate must fire");
        assert_eq!(finding.tgid, 2);
        assert_eq!(finding.verdict, StarvationVerdict::StarvationWarning);
        assert!((finding.wait_ms - 4500.0).abs() < 1e-9);
        assert!((finding.worst_thread_wait_ms - 1500.0).abs() < 1e-9);
        assert_eq!(finding.thread_count, 4);
        assert_eq!(finding.comm.as_deref(), Some("spread"));
    }

    #[test]
    fn process_aggregate_fires_when_no_single_thread_crosses() {
        // Three worker threads at 800 ms each: every thread is healthy on
        // its own, but the 2400 ms process aggregate warns. This is the
        // serving-workload shape — starvation spread across threads.
        let fake = FakeProc::new();
        for tid in [1u32, 7, 8, 9] {
            fake.set_thread(1, tid, "serving", 0);
        }
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        assert!(mon.tick_at(t0).is_none());
        for tid in [7u32, 8, 9] {
            fake.set_thread(1, tid, "serving", 800_000_000);
        }
        let finding = mon
            .tick_at(t0 + Duration::from_secs(10))
            .expect("2400ms aggregate must warn");
        assert_eq!(finding.tgid, 1);
        assert_eq!(finding.verdict, StarvationVerdict::StarvationWarning);
        assert!((finding.wait_ms - 2400.0).abs() < 1e-9);
        assert_eq!(finding.thread_count, 4);
        assert_eq!(finding.victim_label(), "serving (tgid=1)");
    }

    #[test]
    fn process_aggregate_under_threshold_stays_silent() {
        // Three threads at 600 ms each: 1800 ms aggregate sits under the
        // 2000 ms warn line, so no finding — aggregation doesn't invent
        // verdicts.
        let fake = FakeProc::new();
        for tid in [1u32, 7, 8, 9] {
            fake.set_thread(1, tid, "serving", 0);
        }
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        assert!(mon.tick_at(t0).is_none());
        for tid in [7u32, 8, 9] {
            fake.set_thread(1, tid, "serving", 600_000_000);
        }
        assert!(
            mon.tick_at(t0 + Duration::from_secs(10)).is_none(),
            "an 1800ms aggregate must not warn"
        );
    }

    #[test]
    fn top_pids_by_cpu_ranking() {
        // 60 processes with distinct deltas: the 50 highest win, highest
        // first.
        let mut deltas: Vec<(u32, u64)> = (1..=60).map(|pid| (pid, u64::from(pid))).collect();
        let top = top_pids_by_cpu(&mut deltas);
        assert_eq!(top.len(), 50);
        assert_eq!(top[0], 60, "highest delta ranks first");
        assert_eq!(top[49], 11, "the 50th-highest delta ranks last");
        assert!(!top.contains(&10));
        assert!(!top.contains(&1));

        // Ties break by lowest pid, so the choice is deterministic.
        let mut tied: Vec<(u32, u64)> = (1..=55).map(|pid| (pid, 100)).collect();
        let top = top_pids_by_cpu(&mut tied);
        assert_eq!(top.len(), 50);
        assert_eq!(top[0], 1);
        assert_eq!(top[49], 50);
        assert!(!top.contains(&55));

        // Fewer than 50 processes: everyone ranks, highest delta first.
        let mut few: Vec<(u32, u64)> = vec![(7, 0), (3, 5)];
        assert_eq!(top_pids_by_cpu(&mut few), vec![3, 7]);
    }

    #[test]
    fn victim_outside_top50_is_not_measured() {
        // 51 processes: pid 1's runqueue wait explodes to 6000 ms but it
        // burns no CPU, while 50 others each burn CPU. Pid 1 falls outside
        // the top-50, so its schedstat is never read and no finding fires.
        // This is the documented coverage tradeoff of the cost bound.
        let fake = FakeProc::new();
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        for pid in 1..=51u32 {
            fake.set_thread(pid, pid, "worker", 0);
            fake.set_stat(pid, 1000, 0);
        }
        assert!(mon.tick_at(t0).is_none());
        for pid in 1..=51u32 {
            fake.set_thread(pid, pid, "worker", if pid == 1 { 6_000_000_000 } else { 0 });
            fake.set_stat(pid, 1000 + if pid == 1 { 0 } else { 1000 }, 0);
        }
        assert!(
            mon.tick_at(t0 + Duration::from_secs(5)).is_none(),
            "a starving thread outside the top-50 by CPU is not measured"
        );
    }

    #[test]
    fn victim_inside_top50_is_measured() {
        // Same 51 processes, but the starving thread's process also burns
        // the most CPU: it ranks in the top-50 and its 6000 ms wait fires
        // critical.
        let fake = FakeProc::new();
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        for pid in 1..=51u32 {
            fake.set_thread(pid, pid, "worker", 0);
            fake.set_stat(pid, 1000, 0);
        }
        assert!(mon.tick_at(t0).is_none());
        for pid in 1..=51u32 {
            fake.set_thread(pid, pid, "worker", if pid == 1 { 6_000_000_000 } else { 0 });
            fake.set_stat(pid, 1000 + if pid == 1 { 2000 } else { 1000 }, 0);
        }
        let finding = mon
            .tick_at(t0 + Duration::from_secs(5))
            .expect("a top-50 victim's 6000ms wait must fire");
        assert_eq!(finding.verdict, StarvationVerdict::StarvationCritical);
        assert_eq!(finding.tid, 1);
        assert!((finding.wait_ms - 6000.0).abs() < 1e-9);
    }

    #[test]
    fn schedstat_absent_degrades_gracefully() {
        // No schedstat files at all (CONFIG_SCHEDSTATS off): the monitor
        // must never fabricate a finding.
        let fake = FakeProc::new();
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        assert!(mon.tick_at(t0).is_none());
        assert!(mon.tick_at(t0 + Duration::from_secs(5)).is_none());
        assert_eq!(mon.schedstat_available, Some(false));
        // Recovery: files appear later, detection resumes.
        fake.set_thread(1, 7, "hungry", 0);
        assert!(mon.tick_at(t0 + Duration::from_secs(10)).is_none());
        assert_eq!(mon.schedstat_available, Some(true));
        fake.set_thread(1, 7, "hungry", 6_000_000_000);
        let finding = mon
            .tick_at(t0 + Duration::from_secs(20))
            .expect("detection must resume once schedstat appears");
        assert_eq!(finding.verdict, StarvationVerdict::StarvationCritical);
    }

    #[test]
    fn wait_counter_regression_rebaselines() {
        let fake = FakeProc::new();
        fake.set_thread(1, 7, "hungry", 5_000_000_000);
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        assert!(mon.tick_at(t0).is_none());
        // Counter regressed (TID recycled or wrapped): re-baseline, don't
        // fabricate a storm from the drop.
        fake.set_thread(1, 7, "hungry", 1_000_000_000);
        assert!(
            mon.tick_at(t0 + Duration::from_secs(10)).is_none(),
            "a regressing counter must re-baseline, not fire"
        );
        // The next window measures forward from the new baseline.
        fake.set_thread(1, 7, "hungry", 4_000_000_000);
        let finding = mon
            .tick_at(t0 + Duration::from_secs(20))
            .expect("3000ms after re-baseline must warn");
        assert_eq!(finding.verdict, StarvationVerdict::StarvationWarning);
    }

    #[test]
    fn stale_baselines_are_pruned() {
        let fake = FakeProc::new();
        fake.set_thread(1, 7, "hungry", 0);
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        assert!(mon.tick_at(t0).is_none());
        assert_eq!(mon.wait_baselines.len(), 1);
        // The thread exits; its baseline must not linger forever.
        fake.remove_pid(1);
        mon.tick_at(t0 + Duration::from_secs(61));
        assert!(
            mon.wait_baselines.is_empty(),
            "baselines for long-gone threads must be pruned"
        );
    }

    #[test]
    fn warn_cooldown_dedups_repeat_verdicts() {
        let mut mon = RunqueueStarvationMonitor::new(Duration::from_secs(5));
        let finding = warning_finding("hungry");
        assert!(mon.should_warn(&finding), "first occurrence must warn");
        assert!(
            !mon.should_warn(&finding),
            "immediate repeat must be cooled down"
        );
        // A verdict change for the same victim is new information.
        let escalated = CpuStarvation {
            verdict: StarvationVerdict::StarvationCritical,
            ..warning_finding("hungry")
        };
        assert!(mon.should_warn(&escalated));
        // A different victim is unaffected.
        assert!(mon.should_warn(&warning_finding("other")));
    }

    #[test]
    fn warn_cooldown_expires() {
        let mut mon = RunqueueStarvationMonitor::new(Duration::from_secs(5))
            .with_warn_cooldown(Duration::from_millis(30));
        let finding = warning_finding("hungry");
        assert!(mon.should_warn(&finding));
        assert!(!mon.should_warn(&finding));
        std::thread::sleep(Duration::from_millis(60));
        assert!(mon.should_warn(&finding), "cooldown must expire");
    }

    #[test]
    fn zero_warn_cooldown_warns_every_time() {
        let mut mon = RunqueueStarvationMonitor::new(Duration::from_secs(5))
            .with_warn_cooldown(Duration::ZERO);
        let finding = warning_finding("hungry");
        assert!(mon.should_warn(&finding));
        assert!(mon.should_warn(&finding));
    }

    #[test]
    fn warn_cooldown_map_is_bounded() {
        let mut mon = RunqueueStarvationMonitor::new(Duration::from_secs(5))
            .with_warn_cooldown(Duration::from_secs(3600));
        for i in 0..(MAX_COOLDOWN_ENTRIES + 50) {
            let finding = warning_finding(&format!("hungry-{i}"));
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
        let finding = CpuStarvation {
            tid: 4242,
            tgid: 4200,
            comm: Some("hungry".to_string()),
            wait_ms: 8600.0,
            worst_thread_wait_ms: 6500.0,
            thread_count: 2,
            window_secs: 10.0,
            top_waiters: vec![
                (4242, 4200, Some("hungry".to_string()), 6500.0),
                (4243, 4200, Some("hungry".to_string()), 2100.0),
            ],
            verdict: StarvationVerdict::StarvationCritical,
        };
        let incident = incident_from_finding(&finding);
        assert_eq!(incident.event_type, "cpu_starvation");
        assert_eq!(incident.action, "alert");
        assert_eq!(incident.target_pid, Some(4200));
        assert_eq!(
            incident.target_name.as_deref(),
            Some("hungry (tgid=4200)"),
            "the incident identity names the victim process, not the thread"
        );
        // Host-level fields this monitor doesn't sample stay zero/empty;
        // the triggering reading lives in the snapshot.
        assert_eq!(incident.psi_cpu, 0.0);
        assert_eq!(incident.cpu_percent, 0.0);
        let snapshot: serde_json::Value =
            serde_json::from_str(incident.system_snapshot.as_deref().unwrap()).unwrap();
        assert_eq!(snapshot["verdict"], "StarvationCritical");
        assert_eq!(snapshot["source_tier"], "polling");
        assert!((snapshot["wait_ms"].as_f64().unwrap() - 8600.0).abs() < 1e-9);
        assert!((snapshot["worst_thread_wait_ms"].as_f64().unwrap() - 6500.0).abs() < 1e-9);
        assert_eq!(snapshot["thread_count"], 2);
        assert_eq!(snapshot["top_waiters"].as_array().unwrap().len(), 2);
        // The victim's wait is measured; the offender is honestly
        // unavailable — naming it needs eBPF.
        assert_eq!(snapshot["evidence"]["runqueue_wait"], "measured");
        assert_eq!(snapshot["evidence"]["offender"], "unavailable");
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
        let mut mon = fake.monitor().with_incident_store(Some(Arc::clone(&store)));
        let t0 = Instant::now();
        fake.set_thread(1, 7, "hungry", 0);
        assert!(mon.tick_at(t0).is_none());
        fake.set_thread(1, 7, "hungry", 6_000_000_000);
        let finding = mon
            .tick_at(t0 + Duration::from_secs(10))
            .expect("6000ms wait must be critical");
        mon.handle_finding(&finding).await;

        let incidents = store
            .recent_filtered(10, Some("cpu_starvation"), None)
            .await
            .unwrap();
        assert_eq!(incidents.len(), 1, "one finding, one incident");
        assert_eq!(incidents[0].event_type, "cpu_starvation");
        assert_eq!(incidents[0].target_name.as_deref(), Some("hungry (tgid=1)"));

        // The store already has this finding: handling it again must not
        // write a second row. Recording is decided against the store, not
        // the log cooldown.
        mon.handle_finding(&finding).await;
        let incidents = store
            .recent_filtered(10, Some("cpu_starvation"), None)
            .await
            .unwrap();
        assert_eq!(
            incidents.len(),
            1,
            "repeat findings must not duplicate incidents"
        );

        // A fresh monitor — the daemon restarted, so the bounded in-memory
        // cooldown map is empty — must not re-record either.
        let mut mon2 = fake.monitor().with_incident_store(Some(Arc::clone(&store)));
        assert!(mon2.tick_at(t0).is_none());
        fake.set_thread(1, 7, "hungry", 12_000_000_000);
        let finding2 = mon2
            .tick_at(t0 + Duration::from_secs(10))
            .expect("starvation must fire");
        mon2.handle_finding(&finding2).await;
        let incidents = store
            .recent_filtered(10, Some("cpu_starvation"), None)
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
        // name carries the tgid: two same-comm *processes* are two
        // identities, so both record — one `java` process no longer
        // suppresses the others for the whole cooldown.
        let db_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            IncidentStore::new(db_dir.path().join("incidents.db"))
                .await
                .unwrap(),
        );
        let mut mon = RunqueueStarvationMonitor::new(Duration::from_secs(5))
            .with_incident_store(Some(Arc::clone(&store)));
        let a = CpuStarvation {
            tid: 7,
            tgid: 1,
            ..warning_finding("worker")
        };
        let b = CpuStarvation {
            tid: 8,
            tgid: 2,
            ..warning_finding("worker")
        };
        mon.handle_finding(&a).await;
        mon.handle_finding(&b).await;
        let incidents = store
            .recent_filtered(10, Some("cpu_starvation"), None)
            .await
            .unwrap();
        assert_eq!(
            incidents.len(),
            2,
            "same-comm victims are distinct incident identities"
        );
    }

    #[tokio::test]
    async fn failed_insert_is_retried_on_the_next_scan() {
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("incidents.db");
        let finding = warning_finding("hungry");

        // The store is down: the finding is logged, but the failed insert
        // must not poison future record attempts — recording has no
        // in-memory cooldown, only the store's own contents.
        let down_store = Arc::new(IncidentStore::new(&db_path).await.unwrap());
        down_store.close_pool_for_test().await;
        let mut mon = RunqueueStarvationMonitor::new(Duration::from_secs(5))
            .with_incident_store(Some(Arc::clone(&down_store)));
        mon.handle_finding(&finding).await;

        // The store recovers (fresh pool on the same file). The next scan
        // must retry the insert instead of sitting out a cooldown.
        let up_store = Arc::new(IncidentStore::new(&db_path).await.unwrap());
        mon.incident_store = Some(Arc::clone(&up_store));
        mon.handle_finding(&finding).await;
        let incidents = up_store
            .recent_filtered(10, Some("cpu_starvation"), None)
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
            .recent_filtered(10, Some("cpu_starvation"), None)
            .await
            .unwrap();
        assert_eq!(incidents.len(), 1, "a recorded finding must not duplicate");
    }

    #[tokio::test]
    async fn monitor_without_store_stays_log_only() {
        // No incident store configured: handle_finding must not fail, just log.
        let mut mon = RunqueueStarvationMonitor::new(Duration::from_secs(5))
            .with_warn_cooldown(Duration::ZERO);
        mon.handle_finding(&warning_finding("hungry")).await;
    }

    #[test]
    fn median_of_is_correct() {
        assert_eq!(median_of(vec![3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median_of(vec![4.0, 1.0, 3.0, 2.0]), 2.5);
        assert_eq!(median_of(vec![7.0]), 7.0);
    }

    #[test]
    fn watch_fires_on_elevated_wait_plus_slo_breach() {
        let t0 = Instant::now();
        let fake = FakeProc::new();
        let (mut mon, tx) = fake.watch_monitor(vec![pid_target(100)]);

        // 13 polls at 10ms/poll build the baseline: 12 measured samples
        // (median 10ms). The first poll only establishes the thread
        // baseline and yields no measurement, so 13 polls give 12 priors.
        let t = run_baseline_polls(&fake, &mut mon, 100, 100, "watched", 13, 5_000_000, t0);

        // Poll 14: wait jumps to 100ms (10x the 10ms prior median, factor
        // 3x) while p99 142.5ms breaches the 100ms SLO. Both conditions
        // hold against the 12 PRIOR samples — the 100ms point itself is
        // only appended to the baseline after evaluation.
        fake.set_thread(
            100,
            100,
            "watched",
            elevated_wait_ns(13, 5_000_000, 100_000_000),
        );
        tx.try_send(LatencySample {
            selector: WatchSelector::pid(100),
            p99_ms: 142.5,
        })
        .unwrap();
        let (threshold, watch) = mon.tick_full_at(t);
        assert!(
            threshold.is_none(),
            "100ms is far under the 2000ms global threshold — watch mode fires on its own"
        );
        assert_eq!(watch.len(), 1, "dual condition met: must fire exactly once");
        let f = &watch[0];
        assert_eq!(f.tgid, 100);
        assert_eq!(f.comm.as_deref(), Some("watched"));
        assert!((f.wait_ms - 100.0).abs() < 1e-9);
        assert!((f.baseline_median_ms - 10.0).abs() < 1e-9);
        assert!((f.elevation - 10.0).abs() < 1e-9);
        assert_eq!(f.elevation_factor, 3.0);
        assert!((f.slo_p99_ms - 142.5).abs() < 1e-9);
        assert!((f.slo_threshold_ms - 100.0).abs() < 1e-9);
        assert_eq!(f.watch_selector, "pid=100");
        assert_eq!(f.victim_label(), "watched (tgid=100)");
    }

    #[test]
    fn watch_baselines_are_per_process() {
        // One comm selector matching two processes: each is evaluated
        // against its OWN baseline. Spiking only pid 101 must fire only
        // for 101 — a shared baseline would let 101's spike (or 100's
        // calm) set the other's reference.
        let t0 = Instant::now();
        let fake = FakeProc::new();
        let target = WatchTargetConfig {
            selector: WatchSelector::comm("svc".to_string()),
            slo_p99_ms: 100.0,
            elevation_factor: 3.0,
            baseline_secs: 3600,
            ..Default::default()
        };
        let (mut mon, tx) = fake.watch_monitor(vec![target]);
        let mut t = t0;
        for k in 0..13 {
            for pid in [100u32, 101] {
                fake.set_thread(pid, pid, "svc", k as u64 * 5_000_000);
            }
            let findings = mon.watch_tick_at(t);
            assert!(
                findings.is_empty(),
                "no finding expected while baselines build (poll {k})"
            );
            t += Duration::from_secs(5);
        }
        // Poll 14: pid 101's wait jumps to 100ms (10x its own 10ms
        // median); pid 100 stays at baseline; pid 102 appears for the
        // first time and is still warming up.
        fake.set_thread(100, 100, "svc", 13 * 5_000_000);
        fake.set_thread(
            101,
            101,
            "svc",
            elevated_wait_ns(13, 5_000_000, 100_000_000),
        );
        fake.set_thread(102, 102, "svc", 3 * 5_000_000);
        tx.try_send(LatencySample {
            selector: WatchSelector::comm("svc".to_string()),
            p99_ms: 142.5,
        })
        .unwrap();
        let findings = mon.watch_tick_at(t);
        assert_eq!(
            findings.len(),
            1,
            "only the spiked process may fire, on its own baseline"
        );
        let f = &findings[0];
        assert_eq!(f.tgid, 101);
        assert!((f.baseline_median_ms - 10.0).abs() < 1e-9);
        assert_eq!(f.watch_selector, "comm=svc");
    }

    #[test]
    fn watch_silent_when_slo_healthy() {
        // Elevated wait alone must not fire: the SLO signal is the noise
        // guard.
        let t0 = Instant::now();
        let fake = FakeProc::new();
        let (mut mon, tx) = fake.watch_monitor(vec![pid_target(100)]);
        let t = run_baseline_polls(&fake, &mut mon, 100, 100, "watched", 13, 5_000_000, t0);

        fake.set_thread(
            100,
            100,
            "watched",
            elevated_wait_ns(13, 5_000_000, 100_000_000),
        );
        tx.try_send(LatencySample {
            selector: WatchSelector::pid(100),
            p99_ms: 50.0, // healthy: under the 100ms SLO
        })
        .unwrap();
        let (_, watch) = mon.tick_full_at(t);
        assert!(
            watch.is_empty(),
            "elevated wait with a healthy SLO must stay silent"
        );
    }

    #[test]
    fn watch_silent_when_wait_at_baseline() {
        // A breaching SLO alone must not fire: without elevated wait it
        // is some other bottleneck's problem, not runqueue starvation.
        let t0 = Instant::now();
        let fake = FakeProc::new();
        let (mut mon, tx) = fake.watch_monitor(vec![pid_target(100)]);
        let t = run_baseline_polls(&fake, &mut mon, 100, 100, "watched", 13, 5_000_000, t0);

        fake.set_thread(
            100,
            100,
            "watched",
            elevated_wait_ns(13, 5_000_000, 12_000_000),
        ); // +12ms: at baseline
        tx.try_send(LatencySample {
            selector: WatchSelector::pid(100),
            p99_ms: 142.5, // breaching
        })
        .unwrap();
        let (_, watch) = mon.tick_full_at(t);
        assert!(
            watch.is_empty(),
            "breaching SLO with baseline-level wait must stay silent"
        );
    }

    #[test]
    fn watch_silent_without_latency_signal() {
        // No SLO signal at all: the dual condition cannot be evaluated.
        let t0 = Instant::now();
        let fake = FakeProc::new();
        let (mut mon, _tx) = fake.watch_monitor(vec![pid_target(100)]);
        let t = run_baseline_polls(&fake, &mut mon, 100, 100, "watched", 13, 5_000_000, t0);

        fake.set_thread(
            100,
            100,
            "watched",
            elevated_wait_ns(13, 5_000_000, 100_000_000),
        );
        let watch = mon.watch_tick_at(t);
        assert!(
            watch.is_empty(),
            "elevated wait with no SLO signal must stay silent"
        );
    }

    #[test]
    fn watch_silent_with_stale_latency_signal() {
        // A breaching sample older than the 90s TTL is stale: the dual
        // condition cannot be evaluated.
        let t0 = Instant::now();
        let fake = FakeProc::new();
        let (mut mon, tx) = fake.watch_monitor(vec![pid_target(100)]);
        let t = run_baseline_polls(&fake, &mut mon, 100, 100, "watched", 13, 5_000_000, t0);

        // Poll 14: elevated wait + fresh breaching sample -> fires.
        fake.set_thread(
            100,
            100,
            "watched",
            elevated_wait_ns(13, 5_000_000, 100_000_000),
        );
        tx.try_send(LatencySample {
            selector: WatchSelector::pid(100),
            p99_ms: 142.5,
        })
        .unwrap();
        let (_, watch) = mon.tick_full_at(t);
        assert_eq!(watch.len(), 1, "fresh signal must fire");

        // Poll 15, 140s later: the sample is stale, the wait is still
        // elevated. Only the signal's age changed -> silent.
        let t2 = t + Duration::from_secs(140);
        fake.set_thread(
            100,
            100,
            "watched",
            elevated_wait_ns(14, 5_000_000, 100_000_000),
        );
        let (_, watch) = mon.tick_full_at(t2);
        assert!(
            watch.is_empty(),
            "a stale SLO signal must not arm the finding"
        );
    }

    #[test]
    fn watch_needs_twelve_baseline_samples() {
        // 11 measured samples is not a baseline: the 12th poll stays
        // silent even with both conditions met, because evaluation needs
        // 12 PRIOR samples. The 12th poll's measurement still feeds the
        // baseline, so the 13th poll (12 priors) fires.
        let t0 = Instant::now();
        let fake = FakeProc::new();
        let (mut mon, tx) = fake.watch_monitor(vec![pid_target(100)]);
        // 12 polls -> 11 measurements (the first poll only establishes
        // the thread baseline).
        let t = run_baseline_polls(&fake, &mut mon, 100, 100, "watched", 12, 5_000_000, t0);

        fake.set_thread(
            100,
            100,
            "watched",
            elevated_wait_ns(12, 5_000_000, 100_000_000),
        );
        tx.try_send(LatencySample {
            selector: WatchSelector::pid(100),
            p99_ms: 142.5,
        })
        .unwrap();
        let (_, watch) = mon.tick_full_at(t);
        assert!(
            watch.is_empty(),
            "no evaluation before 12 PRIOR baseline samples"
        );

        // The 13th measured sample has 12 priors: same conditions now fire.
        fake.set_thread(
            100,
            100,
            "watched",
            elevated_wait_ns(13, 5_000_000, 100_000_000),
        );
        tx.try_send(LatencySample {
            selector: WatchSelector::pid(100),
            p99_ms: 142.5,
        })
        .unwrap();
        let (_, watch) = mon.tick_full_at(t + Duration::from_secs(5));
        assert_eq!(
            watch.len(),
            1,
            "the 13th measured sample (12 priors) must arm evaluation"
        );
    }

    #[test]
    fn watch_targets_have_independent_baselines() {
        // Pid 100 idles at 10ms/poll; pid 200 idles at 400ms/poll. A 100ms
        // wait is 10x elevated for pid 100 but baseline-level for pid 200
        // — only pid 100 may fire.
        let t0 = Instant::now();
        let fake = FakeProc::new();
        let (mut mon, tx) = fake.watch_monitor(vec![pid_target(100), pid_target(200)]);

        let mut t = t0;
        for k in 0..13 {
            fake.set_thread(100, 100, "low", k * 5_000_000);
            fake.set_thread(200, 200, "high", k * 200_000_000);
            assert!(mon.watch_tick_at(t).is_empty());
            t += Duration::from_secs(5);
        }

        fake.set_thread(
            100,
            100,
            "low",
            elevated_wait_ns(13, 5_000_000, 100_000_000),
        );
        fake.set_thread(
            200,
            200,
            "high",
            elevated_wait_ns(13, 200_000_000, 450_000_000),
        );
        for pid in [100u32, 200] {
            tx.try_send(LatencySample {
                selector: WatchSelector::pid(pid),
                p99_ms: 142.5,
            })
            .unwrap();
        }
        let (_, watch) = mon.tick_full_at(t);
        assert_eq!(
            watch.len(),
            1,
            "only the target elevated against its OWN baseline may fire"
        );
        assert_eq!(watch[0].tgid, 100);
        assert!((watch[0].baseline_median_ms - 10.0).abs() < 1e-9);
    }

    #[test]
    fn watch_resolves_pid_comm_and_cgroup_selectors() {
        let t0 = Instant::now();
        let fake = FakeProc::new();
        let targets = vec![
            WatchTargetConfig {
                selector: WatchSelector::pid(300),
                ..pid_target(0)
            },
            WatchTargetConfig {
                selector: WatchSelector::comm("byname".to_string()),
                ..pid_target(0)
            },
            WatchTargetConfig {
                selector: WatchSelector::cgroup("/kubepods/burstable/podabc".to_string()),
                ..pid_target(0)
            },
        ];
        let (mut mon, tx) = fake.watch_monitor(targets);
        fake.set_cgroup(302, "0::/kubepods/burstable/podabc/container1\n");

        let mut t = t0;
        for k in 0..13 {
            fake.set_thread(300, 300, "other", k * 5_000_000);
            fake.set_thread(301, 301, "byname", k * 5_000_000);
            fake.set_thread(302, 302, "grouped", k * 5_000_000);
            assert!(mon.watch_tick_at(t).is_empty());
            t += Duration::from_secs(5);
        }

        fake.set_thread(
            300,
            300,
            "other",
            elevated_wait_ns(13, 5_000_000, 100_000_000),
        );
        fake.set_thread(
            301,
            301,
            "byname",
            elevated_wait_ns(13, 5_000_000, 100_000_000),
        );
        fake.set_thread(
            302,
            302,
            "grouped",
            elevated_wait_ns(13, 5_000_000, 100_000_000),
        );
        tx.try_send(LatencySample {
            selector: WatchSelector::pid(300),
            p99_ms: 142.5,
        })
        .unwrap();
        tx.try_send(LatencySample {
            selector: WatchSelector::comm("byname".to_string()),
            p99_ms: 142.5,
        })
        .unwrap();
        tx.try_send(LatencySample {
            selector: WatchSelector::cgroup("/kubepods/burstable/podabc".to_string()),
            p99_ms: 142.5,
        })
        .unwrap();
        let (_, watch) = mon.tick_full_at(t);
        let mut fired: Vec<(u32, String)> = watch
            .iter()
            .map(|f| (f.tgid, f.watch_selector.clone()))
            .collect();
        fired.sort();
        assert_eq!(
            fired,
            vec![
                (300, "pid=300".to_string()),
                (301, "comm=byname".to_string()),
                (302, "cgroup=/kubepods/burstable/podabc".to_string()),
            ],
            "pid, comm and cgroup selectors must each resolve their process"
        );
    }

    #[test]
    fn watch_bypasses_top_50_cpu_gate() {
        // The watched process burns no CPU (Δ=0 every poll) while 60
        // fillers burn plenty: it can never rank in the top-50, so without
        // the bypass it would never even be measured.
        let t0 = Instant::now();
        let fake = FakeProc::new();
        let (mut mon, tx) = fake.watch_monitor(vec![pid_target(42)]);
        let mut t = t0;
        for k in 0..13u64 {
            for f in 0..60u32 {
                fake.set_stat(1000 + f, 1_000_000 + k * 1_000, 0); // Δ=1000 ticks/poll
            }
            fake.set_thread(42, 42, "watched", k * 5_000_000); // Δ=0 CPU, 10ms wait/poll
            assert!(
                mon.watch_tick_at(t).is_empty(),
                "baseline still building (poll {k})"
            );
            t += Duration::from_secs(5);
        }
        for f in 0..60u32 {
            fake.set_stat(1000 + f, 1_000_000 + 13 * 1_000, 0);
        }
        fake.set_thread(
            42,
            42,
            "watched",
            elevated_wait_ns(13, 5_000_000, 100_000_000),
        );
        tx.try_send(LatencySample {
            selector: WatchSelector::pid(42),
            p99_ms: 142.5,
        })
        .unwrap();
        let (_, watch) = mon.tick_full_at(t);
        assert_eq!(
            watch.len(),
            1,
            "the watched process must be measured despite ranking outside the top-50"
        );
        assert_eq!(watch[0].tgid, 42);
    }

    #[test]
    fn watch_snapshot_carries_mode_and_all_four_evidence_labels() {
        let finding = WatchFinding {
            tgid: 100,
            comm: Some("watched".to_string()),
            wait_ms: 100.0,
            worst_thread_wait_ms: 100.0,
            thread_count: 1,
            window_secs: 10.0,
            baseline_median_ms: 10.0,
            elevation: 10.0,
            elevation_factor: 3.0,
            slo_p99_ms: 142.5,
            slo_threshold_ms: 100.0,
            watch_selector: "pid=100".to_string(),
            top_waiters: vec![(100, 100, Some("watched".to_string()), 100.0)],
        };
        let incident = incident_from_watch_finding(&finding);
        assert_eq!(incident.event_type, "cpu_starvation");
        assert_eq!(incident.target_name.as_deref(), Some("watched (tgid=100)"));
        assert_eq!(incident.target_pid, Some(100));
        let snap: serde_json::Value =
            serde_json::from_str(incident.system_snapshot.as_deref().unwrap()).unwrap();
        assert_eq!(snap["detection_mode"], "watch");
        assert_eq!(snap["wait_ms"], 100.0);
        assert_eq!(snap["baseline_median_ms"], 10.0);
        assert_eq!(snap["elevation"], 10.0);
        assert_eq!(snap["elevation_factor"], 3.0);
        assert_eq!(snap["slo_p99_ms"], 142.5);
        assert_eq!(snap["slo_threshold_ms"], 100.0);
        assert_eq!(snap["watch_selector"], "pid=100");
        // The verdict the dedup key reads must be the literal "watch".
        assert_eq!(snap["verdict"], "watch");
        assert_eq!(snap["evidence"]["runqueue_wait"], "measured");
        assert_eq!(snap["evidence"]["baseline_elevation"], "inferred");
        assert_eq!(snap["evidence"]["slo_breach"], "measured");
        assert_eq!(snap["evidence"]["offender"], "unavailable");
    }

    #[test]
    fn watch_dedup_key_is_independent_from_threshold_verdicts() {
        // The same victim can be incidented by the threshold path and the
        // watch path without either suppressing the other.
        let watch = WatchFinding {
            tgid: 4242,
            comm: Some("hungry".to_string()),
            wait_ms: 100.0,
            worst_thread_wait_ms: 100.0,
            thread_count: 1,
            window_secs: 10.0,
            baseline_median_ms: 10.0,
            elevation: 10.0,
            elevation_factor: 3.0,
            slo_p99_ms: 142.5,
            slo_threshold_ms: 100.0,
            watch_selector: "pid=4242".to_string(),
            top_waiters: vec![],
        };
        let threshold = warning_finding("hungry");
        let watch_key = (watch.victim_label(), "watch".to_string());
        let threshold_key = (threshold.victim_label(), format!("{:?}", threshold.verdict));
        assert_eq!(watch.victim_label(), threshold.victim_label());
        assert_ne!(
            watch_key, threshold_key,
            "watch and threshold dedup keys must not collide"
        );
    }

    #[test]
    fn watch_skips_invalid_targets_but_arms_valid_ones() {
        // with_watch_config mirrors --check-config: invalid entries are
        // skipped with a warning, valid ones still arm.
        let fake = FakeProc::new();
        let targets = vec![
            pid_target(100),
            WatchTargetConfig {
                selector: WatchSelector::pid(200),
                slo_p99_ms: 0.0, // invalid: must be skipped
                ..pid_target(200)
            },
        ];
        let (mon, _tx) = fake.watch_monitor(targets);
        assert_eq!(mon.watch_targets.len(), 1, "only the valid target must arm");
        assert_eq!(mon.watch_targets[0].selector, WatchSelector::pid(100));
    }

    #[tokio::test]
    async fn watch_findings_record_as_incidents_with_watch_verdict() {
        let db_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            IncidentStore::new(db_dir.path().join("incidents.db"))
                .await
                .unwrap(),
        );
        let t0 = Instant::now();
        let fake = FakeProc::new();
        let (tx, rx) = mpsc::channel::<LatencySample>(WATCH_LATENCY_CHANNEL_CAP);
        let mut mon = fake
            .monitor()
            .with_watch_config(WatchConfig {
                targets: vec![pid_target(100)],
                ..Default::default()
            })
            .with_latency_receiver(rx)
            .with_incident_store(Some(Arc::clone(&store)));
        let t = run_baseline_polls(&fake, &mut mon, 100, 100, "watched", 13, 5_000_000, t0);

        fake.set_thread(
            100,
            100,
            "watched",
            elevated_wait_ns(13, 5_000_000, 100_000_000),
        );
        tx.try_send(LatencySample {
            selector: WatchSelector::pid(100),
            p99_ms: 142.5,
        })
        .unwrap();
        let (_, watch) = mon.tick_full_at(t);
        assert_eq!(watch.len(), 1);
        mon.handle_watch_finding(&watch[0]).await;
        let incidents = store
            .recent_filtered(10, Some("cpu_starvation"), None)
            .await
            .unwrap();
        assert_eq!(incidents.len(), 1, "watch finding must record");
        let snap: serde_json::Value =
            serde_json::from_str(incidents[0].system_snapshot.as_deref().unwrap()).unwrap();
        assert_eq!(snap["detection_mode"], "watch");
        assert_eq!(snap["verdict"], "watch");

        // Handling it again must not duplicate the row.
        mon.handle_watch_finding(&watch[0]).await;
        let incidents = store
            .recent_filtered(10, Some("cpu_starvation"), None)
            .await
            .unwrap();
        assert_eq!(
            incidents.len(),
            1,
            "repeat watch finding must not duplicate"
        );

        // And the threshold path's verdict keys can't suppress it: the
        // (victim, "watch") pair is distinct from (victim,
        // StarvationWarning).
        let keys = store
            .recent_incident_keys("cpu_starvation", 3600)
            .await
            .unwrap();
        assert!(keys.contains(&("watched (tgid=100)".to_string(), "watch".to_string())));
    }

    #[test]
    fn aggregate_wait_delta_sums_threads_and_skips_turnover_and_regression() {
        let first: HashMap<u32, u64> = [(1, 100), (2, 200), (3, 300), (4, 400)]
            .into_iter()
            .collect();
        let second: HashMap<u32, u64> = [(1, 150), (2, 200), (4, 100), (5, 500)]
            .into_iter()
            .collect();
        // tid 1: +50ns measured. tid 2: zero delta, still counted.
        // tid 3: gone mid-probe — no Δ possible. tid 4: counter regressed
        // (TID recycled) — skipped, never fabricated. tid 5: born
        // mid-probe — no baseline, skipped.
        let (total_ms, worst_ms, threads) = aggregate_wait_delta(&first, &second);
        assert!((total_ms - 0.00005).abs() < 1e-9, "got {total_ms}");
        assert!((worst_ms - 0.00005).abs() < 1e-9, "got {worst_ms}");
        assert_eq!(threads, 2);
    }

    #[test]
    fn classify_for_window_scales_thresholds_to_the_window() {
        // A 1s probe window: warn at 200ms, critical at 500ms — the same
        // physical meaning as the monitor's 2000/5000 ms per 10s.
        assert_eq!(classify_for_window(199.9, 1.0), StarvationVerdict::Healthy);
        assert_eq!(
            classify_for_window(200.0, 1.0),
            StarvationVerdict::StarvationWarning
        );
        assert_eq!(
            classify_for_window(500.0, 1.0),
            StarvationVerdict::StarvationCritical
        );
        // The fractions reproduce the frozen 10s absolutes exactly.
        assert!((WARN_WAIT_FRAC * 10_000.0 - WARN_WAIT_MS).abs() < 1e-9);
        assert!((CRIT_WAIT_FRAC * 10_000.0 - CRIT_WAIT_MS).abs() < 1e-9);
        // And the monitor's 10s classification is unchanged behavior.
        assert_eq!(classify(1999.9), StarvationVerdict::Healthy);
        assert_eq!(classify(2000.0), StarvationVerdict::StarvationWarning);
        assert_eq!(classify(5000.0), StarvationVerdict::StarvationCritical);
    }

    /// No monitor, no incident store, no top-50 gate: the probe measures
    /// the named PID on demand. A quiet process the poll loop would never
    /// look at still gets a fresh measured answer — including healthy,
    /// which the thresholded incident path structurally cannot express.
    #[tokio::test]
    async fn probe_measures_any_pid_on_demand_with_no_monitor() {
        let procfs = FakeProc::new();
        procfs.set_thread(4242, 4242, "hog", 0);
        let probe = ContentionProbe::new(procfs.dir.path().to_path_buf())
            .with_probe_interval(Duration::from_millis(50));
        let snap = probe
            .measure(4242)
            .await
            .expect("an existing pid must measure");
        // The finding's identity is the process it describes.
        assert_eq!(snap.tgid, 4242);
        // Birth identity captured in the same call as the measurement: the
        // fake proc's deterministic starttime for this incarnation.
        assert_eq!(snap.start_ticks, Some(4242 * 1000 + 42));
        // The fake /proc has no sys/kernel/random/boot_id — absence is
        // honest, not fabricated.
        assert_eq!(snap.boot_id, None);
        assert_eq!(snap.label, "measured");
        assert_eq!(snap.verdict, "healthy");
        assert_eq!(snap.wait_ms, 0.0);
        assert_eq!(snap.worst_thread_wait_ms, 0.0);
        assert_eq!(snap.measured_thread_count, 1);
        // The honest window is the actual sample spacing (~50ms), not a
        // nominal constant.
        assert!(
            (0.04..10.0).contains(&snap.window_secs),
            "window_secs must be the real probe spacing, got {}",
            snap.window_secs
        );
        assert_eq!(snap.comm.as_deref(), Some("hog"));
    }

    #[tokio::test]
    async fn probe_aggregates_threads() {
        let procfs = FakeProc::new();
        procfs.set_thread(4242, 4242, "hog", 0);
        procfs.set_thread(4242, 4243, "worker", 0);
        let probe = ContentionProbe::new(procfs.dir.path().to_path_buf())
            .with_probe_interval(Duration::from_millis(20));
        let snap = probe.measure(4242).await.expect("must measure");
        assert_eq!(snap.measured_thread_count, 2);
        assert_eq!(snap.wait_ms, 0.0);
    }

    #[tokio::test]
    async fn probe_detects_real_wait_delta() {
        let procfs = FakeProc::new();
        procfs.set_thread(4242, 4242, "hog", 0);
        // +100ms of runqueue wait lands between the two samples. The
        // kernel aliases /proc/<tgid>/schedstat to the leader's task
        // file; the probe reads the leader path, so both get the bump.
        let task_schedstat = procfs.dir.path().join("4242/task/4242/schedstat");
        let leader_schedstat = procfs.dir.path().join("4242/schedstat");
        let bumper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            std::fs::write(&task_schedstat, "1000000 100000000 7\n").unwrap();
            std::fs::write(&leader_schedstat, "1000000 100000000 7\n").unwrap();
        });
        let probe = ContentionProbe::new(procfs.dir.path().to_path_buf())
            .with_probe_interval(Duration::from_millis(300));
        let snap = probe.measure(4242).await.expect("must measure");
        bumper.join().unwrap();
        assert!(
            (snap.wait_ms - 100.0).abs() < 25.0,
            "wait_ms must be the measured schedstat Δ, got {}",
            snap.wait_ms
        );
        // 100ms over a ~300ms window is a third of the window: warning.
        assert_eq!(snap.verdict, "starvation_warning");
    }

    #[tokio::test]
    async fn probe_reports_not_found_for_missing_pid() {
        let procfs = FakeProc::new();
        let probe = ContentionProbe::new(procfs.dir.path().to_path_buf());
        // Typed absence, not zero: a process that doesn't exist has no
        // measurement, and the probe itself is healthy.
        assert!(matches!(
            probe.measure(9999).await,
            Err(ContentionMeasureError::NotFound)
        ));
    }

    #[tokio::test]
    async fn probe_reports_degraded_without_schedstat() {
        let procfs = FakeProc::new();
        // A pid dir with a stat file but no schedstat anywhere: the
        // CONFIG_SCHEDSTATS-off equivalent. The process exists, so this
        // is degraded infrastructure — never a healthy zero.
        procfs.set_stat(4242, 100, 0);
        let probe = ContentionProbe::new(procfs.dir.path().to_path_buf())
            .with_probe_interval(Duration::from_millis(20));
        assert!(matches!(
            probe.measure(4242).await,
            Err(ContentionMeasureError::Degraded)
        ));
    }

    #[tokio::test]
    async fn probe_captures_boot_id() {
        let procfs = FakeProc::new();
        procfs.set_thread(4242, 4242, "hog", 0);
        let dir = procfs.dir.path().join("sys/kernel/random");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("boot_id"), "test-boot-id\n").unwrap();
        let probe = ContentionProbe::new(procfs.dir.path().to_path_buf())
            .with_probe_interval(Duration::from_millis(20));
        let snap = probe.measure(4242).await.expect("must measure");
        assert_eq!(snap.boot_id.as_deref(), Some("test-boot-id"));
    }

    #[tokio::test]
    async fn probe_follows_pid_recycle_identity() {
        // A recycled PID must never inherit the previous incarnation's
        // finding: the snapshot carries the birth identity captured in
        // the same call as the measurement.
        let procfs = FakeProc::new();
        procfs.set_thread(4242, 4242, "hog", 0);
        // set_thread rewrites stat as a side effect; re-assert the
        // incarnation after every fixture write.
        procfs.set_stat_start(4242, 1000, 0, 1111); // incarnation A
        let probe = ContentionProbe::new(procfs.dir.path().to_path_buf())
            .with_probe_interval(Duration::from_millis(20));
        let snap = probe.measure(4242).await.expect("must measure");
        assert_eq!(
            snap.start_ticks,
            Some(1111),
            "snapshot must carry incarnation A's birth identity"
        );

        // The PID is recycled: same number, new process, new starttime.
        procfs.set_thread(4242, 4242, "hog", 0);
        procfs.set_stat_start(4242, 2000, 0, 2222); // incarnation B
        let snap = probe.measure(4242).await.expect("must measure");
        assert_eq!(
            snap.start_ticks,
            Some(2222),
            "snapshot must follow the current incarnation, not the recycled one"
        );
    }
}
