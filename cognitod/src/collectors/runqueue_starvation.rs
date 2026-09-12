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

use log::{debug, info, warn};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::incidents::{Incident, IncidentStore};

/// Sliding window over which per-thread runqueue wait is accumulated.
const WINDOW: Duration = Duration::from_secs(10);
/// Wait at or above which a warning fires: 20% of a CPU's time in the
/// window spent waiting on a runqueue (experiment-grounded, see above).
const WARN_WAIT_MS: f64 = 2000.0;
/// Wait at or above which a critical fires: 50% of the window waiting.
const CRIT_WAIT_MS: f64 = 5000.0;
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

fn classify(wait_ms: f64) -> StarvationVerdict {
    if wait_ms >= CRIT_WAIT_MS {
        StarvationVerdict::StarvationCritical
    } else if wait_ms >= WARN_WAIT_MS {
        StarvationVerdict::StarvationWarning
    } else {
        StarvationVerdict::Healthy
    }
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
    /// When each victim+verdict was last warned about.
    last_warned: HashMap<(String, StarvationVerdict), Instant>,
    /// Whether the last incident-record attempt failed (warn-once, then
    /// debug until a record succeeds — `handle_burst` retries every scan).
    record_unhealthy: bool,
    /// Where findings are recorded so they are visible through the API
    /// and MCP tools, not just the daemon logs. `None` keeps the monitor
    /// log-only.
    incident_store: Option<Arc<IncidentStore>>,
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

    /// Log-reporting gate: true the first time a victim reports a given
    /// verdict, and again once the cooldown has elapsed. A verdict *change*
    /// for the same victim always reports. This gates the log line only —
    /// incident recording is decided separately against the store (see
    /// `handle_finding`), so a failed insert is retried on the next scan
    /// instead of being swallowed by this cooldown.
    fn should_warn(&mut self, finding: &CpuStarvation) -> bool {
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

    /// One poll: rank processes by recent CPU time, refresh the top-50's
    /// threads' wait baselines, aggregate waits to the process, and return
    /// a finding for the worst-waiting process when it is actionable. The
    /// first sighting of a thread only establishes its baseline.
    pub fn tick(&mut self) -> Option<CpuStarvation> {
        self.tick_at(Instant::now())
    }

    fn tick_at(&mut self, now: Instant) -> Option<CpuStarvation> {
        // Phase 1: rank processes by CPU time consumed since the last poll
        // (`utime+stime` Δ). A first sighting has no Δ yet and ranks zero —
        // ranking converges from the second poll. Absence is not zero, so
        // unreadable stat files simply don't rank.
        let mut deltas: Vec<(u32, u64)> = Vec::new();
        let mut cpu_now: HashMap<u32, u64> = HashMap::new();
        for pid in list_pids(&self.proc_root) {
            let Some(cputime) = read_stat_cputime(&self.proc_root, pid) else {
                continue;
            };
            let last = self.cpu_baselines.get(&pid).copied().unwrap_or(cputime);
            deltas.push((pid, cputime.saturating_sub(last)));
            cpu_now.insert(pid, cputime);
        }
        self.cpu_baselines = cpu_now;
        let top: HashSet<u32> = top_pids_by_cpu(&mut deltas).into_iter().collect();

        // Phase 2: read schedstat only for the top-50's threads — the cost
        // bound. Threads outside the top-50 aren't measured this poll;
        // their baselines keep aging and are pruned after 60s idle.
        let mut any_schedstat = false;
        // `(tid, tgid, wait_ms)` for every measured thread with a
        // measurable window.
        let mut waiters: Vec<(u32, u32, f64)> = Vec::new();
        for (tgid, tid) in list_threads(&self.proc_root) {
            if !top.contains(&tgid) {
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
        // Worst process by aggregate wait; ties break toward the lowest
        // tgid so the pick is deterministic.
        let (&tgid, worst) = agg.iter().max_by(|a, b| {
            a.1.total_ms
                .partial_cmp(&b.1.total_ms)
                .unwrap_or(Ordering::Equal)
                .then_with(|| b.0.cmp(a.0))
        })?;
        let verdict = classify(worst.total_ms);
        if !verdict.actionable() {
            return None;
        }
        let top_waiters: Vec<(u32, u32, Option<String>, f64)> = waiters
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

    pub async fn run(mut self) {
        info!("[runqueue] starting runqueue starvation monitor");
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
            let d = self.dir.path().join(pid.to_string());
            fs::create_dir_all(&d).unwrap();
            fs::write(
                d.join("stat"),
                format!(
                    "{pid} (comm (with) parens) R 0 0 0 0 0 0 0 0 0 0 {utime} {stime} 0 0 0 0 0\n"
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
        assert_eq!(
            incidents[0].target_name.as_deref(),
            Some("hungry (tgid=1)")
        );

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
}
