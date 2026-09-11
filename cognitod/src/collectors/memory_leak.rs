//! Userspace memory-leak-trend detector: no eBPF, no privileges beyond /proc.
//!
//! A process whose resident set grows steadily for fifteen minutes is worth
//! an operator's attention — but RSS growth is *not* proof of a leak. Page
//! cache, allocator arenas, and lazy freeing all look identical from
//! `/proc/<pid>/statm`. This monitor therefore reports a "growth trend
//! consistent with a leak" (confidence `inferred`, everywhere), never a
//! leak, and attaches `smaps_rollup` allocator hints at fire time so a human
//! or agent can tell anon growth from file-backed growth.
//!
//! Design:
//!
//! * **Signal (inferred):** per-process RSS (`statm` resident field × page
//!   size), sampled every 30s. Least-squares linear fit over the in-window
//!   samples (15-min window ⇒ 30 samples at full coverage).
//! * **Fire:** positive slope AND R² > 0.8 AND fitted growth (slope ×
//!   in-window span) > 50MB. All three thresholds are spec-derived
//!   heuristics, not production-calibrated — they sit in named constants
//!   and are documented as such. The R² gate is what keeps a sawtooth
//!   (alloc/free churn with net drift) from firing.
//! * **Warm-up honesty:** a verdict needs at least half a window of samples
//!   (15). The fit runs only over samples inside the window and growth is
//!   slope × *in-window* span, so a partial window can only under-report,
//!   never inflate into a finding.
//! * **Process identity:** baselines are keyed on `(pid, starttime)` — the
//!   `starttime` field (field 22) of `/proc/<pid>/stat` is unique per
//!   process incarnation, so a recycled PID starts a fresh baseline
//!   instead of inheriting the dead process's trend. `comm` alone would
//!   collide; `pid` alone would too.
//! * **Cost:** one `statm` read per process per 30s is negligible (spec §5).
//!   `smaps_rollup` is read *once per firing*, not per poll, for the
//!   anon/private-dirty breakdown. Sample deques are pruned to the window
//!   (with the same anchor-retention discipline as the runqueue monitor)
//!   and idle PIDs are dropped after two windows.
//! * **Degradation:** an unreadable `statm` skips that process's sample
//!   for the poll — absence is not zero, and the baseline is left intact.
//!   A missing `smaps_rollup` yields `smaps: unavailable`, never fabricated
//!   zeros.
//! * **eBPF upgrade:** allocation-site attribution via uprobes (spec §4).
//!
//! Findings become `memory_leak` incidents via the same store-backed dedup
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

/// Sliding window for the linear fit.
const WINDOW: Duration = Duration::from_secs(15 * 60);
/// Minimum samples before any verdict: half the window at full coverage.
/// Fewer than this and the fit is noise — the monitor stays silent.
const MIN_SAMPLES: usize = 15;
/// R² at or above which the trend is "sustained" rather than churn.
const MIN_R_SQUARED: f64 = 0.8;
/// Fitted window growth (slope × in-window span) at or above which a
/// sustained trend becomes actionable. Spec-derived heuristic.
const MIN_GROWTH_BYTES: u64 = 50 * 1024 * 1024;
/// Default quiet period between repeat warnings for the same
/// process+verdict, mirroring the other monitors.
const DEFAULT_WARN_COOLDOWN: Duration = Duration::from_secs(15 * 60);
/// Cap on the warn-cooldown map; oldest entries are evicted past this.
const MAX_COOLDOWN_ENTRIES: usize = 1024;
/// Baselines idle longer than this are dropped — the process exited or the
/// host went quiet; either way the memory shouldn't linger.
const STALE_BASELINE: Duration = Duration::from_secs(30 * 60);
/// Page-size fallback if `sysconf` fails; the real size comes from the
/// kernel at runtime.
const FALLBACK_PAGE_SIZE: u64 = 4096;

/// What a process's RSS trend means. There is a single actionable verdict:
/// RSS growth is never proof of a leak, so there is no "critical" — only
/// the sustained-trend warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeakVerdict {
    Healthy,
    /// Positive slope, R² > 0.8, growth > 50MB over the window: a growth
    /// trend consistent with a leak.
    LeakWarning,
}

impl LeakVerdict {
    /// `false` for `Healthy`; used to filter log/report noise.
    pub fn actionable(self) -> bool {
        !matches!(self, LeakVerdict::Healthy)
    }
}

/// Allocator hints from `smaps_rollup`, read once per firing.
#[derive(Debug, Clone)]
pub struct SmapsHints {
    /// Total RSS from the rollup, KiB.
    pub rss_kb: u64,
    /// Anonymous (non-file-backed) memory, KiB — the leak-suspect part.
    pub anon_kb: u64,
    /// Private dirty pages, KiB.
    pub private_dirty_kb: u64,
}

/// One actionable leak-trend finding for a scan window.
#[derive(Debug, Clone)]
pub struct MemoryLeak {
    pub pid: u32,
    /// `/proc/<pid>/stat` field 22: unique per process incarnation.
    pub starttime: u64,
    pub comm: Option<String>,
    /// Fitted RSS growth rate, bytes/sec.
    pub slope_bytes_per_sec: f64,
    /// Goodness of the linear fit.
    pub r_squared: f64,
    /// Fitted growth over the in-window span, bytes.
    pub growth_bytes: u64,
    /// Seconds the window covers.
    pub window_secs: f64,
    /// Samples the fit ran on.
    pub sample_count: usize,
    /// Allocator hints; `None` when `smaps_rollup` was unreadable.
    pub smaps: Option<SmapsHints>,
    pub verdict: LeakVerdict,
}

impl MemoryLeak {
    /// Stable identity for cooldown and incident-dedup keys: the process
    /// incarnation, not just the PID. Two same-named processes are distinct
    /// (different PIDs); a recycled PID is distinct (different starttime),
    /// so one victim never suppresses another's incident for the whole
    /// cooldown.
    fn victim_label(&self) -> String {
        let comm = self.comm.clone().unwrap_or_else(|| "unknown".to_string());
        format!("{comm} (pid={}, start={})", self.pid, self.starttime)
    }

    /// Slope in MiB/hour for human- and agent-readable output.
    fn slope_mib_per_hr(&self) -> f64 {
        self.slope_bytes_per_sec * 3600.0 / (1024.0 * 1024.0)
    }

    fn growth_mib(&self) -> f64 {
        self.growth_bytes as f64 / (1024.0 * 1024.0)
    }
}

fn classify(slope: f64, r2: f64, growth_bytes: u64) -> LeakVerdict {
    if slope > 0.0 && r2 >= MIN_R_SQUARED && growth_bytes >= MIN_GROWTH_BYTES {
        LeakVerdict::LeakWarning
    } else {
        LeakVerdict::Healthy
    }
}

/// Page size in bytes, from the kernel; falls back to 4KiB if `sysconf`
/// fails rather than failing the whole scan.
fn page_size_bytes() -> u64 {
    let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if raw > 0 {
        raw as u64
    } else {
        FALLBACK_PAGE_SIZE
    }
}

/// Resident set size in bytes from `/proc/<pid>/statm` (field 2, pages).
/// `None` when the file is missing or unparseable — absence is not zero.
fn read_rss_bytes(proc_root: &Path, pid: u32) -> Option<u64> {
    let content = std::fs::read_to_string(proc_root.join(pid.to_string()).join("statm")).ok()?;
    let resident_pages = content.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    Some(resident_pages.saturating_mul(page_size_bytes()))
}

/// Process start time (jiffies since boot) from `/proc/<pid>/stat` field
/// 22. Unique per process incarnation: the PID-reuse-safe half of the
/// baseline key. `None` when missing/unparseable — absence is not zero.
/// Fields are split after the *last* `)` since comm may contain parens.
fn read_starttime(proc_root: &Path, pid: u32) -> Option<u64> {
    let content = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    let after_comm = content.rfind(')')?;
    content[after_comm + 1..]
        .split_whitespace()
        .nth(19)?
        .parse::<u64>()
        .ok()
}

fn read_comm(proc_root: &Path, pid: u32) -> Option<String> {
    std::fs::read_to_string(proc_root.join(pid.to_string()).join("comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
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

/// Least-squares fit of `ys` over `xs` (seconds). Returns
/// `(slope_per_sec, r_squared)`, or `None` when the fit is degenerate
/// (fewer than two points, or all `xs` identical).
fn linear_fit(xs: &[f64], ys: &[f64]) -> Option<(f64, f64)> {
    if xs.len() < 2 || xs.len() != ys.len() {
        return None;
    }
    let n = xs.len() as f64;
    let mean_x = xs.iter().sum::<f64>() / n;
    let mean_y = ys.iter().sum::<f64>() / n;
    let mut ss_xy = 0.0;
    let mut ss_xx = 0.0;
    let mut ss_yy = 0.0;
    for (x, y) in xs.iter().zip(ys.iter()) {
        let dx = x - mean_x;
        let dy = y - mean_y;
        ss_xy += dx * dy;
        ss_xx += dx * dx;
        ss_yy += dy * dy;
    }
    if ss_xx == 0.0 {
        return None;
    }
    let slope = ss_xy / ss_xx;
    // Constant RSS ⇒ no variance to explain; that's a zero-slope healthy
    // trend, not a perfect fit.
    let r2 = if ss_yy == 0.0 {
        0.0
    } else {
        (ss_xy * ss_xy) / (ss_xx * ss_yy)
    };
    Some((slope, r2.clamp(0.0, 1.0)))
}

/// Allocator hints from `/proc/<pid>/smaps_rollup`: the `Rss:`,
/// `Anonymous:`, and `Private_Dirty:` summary lines (KiB). `None` when the
/// file is missing or unparseable — absence is not zero. Read once per
/// firing, never per poll.
fn read_smaps_hints(proc_root: &Path, pid: u32) -> Option<SmapsHints> {
    let content =
        std::fs::read_to_string(proc_root.join(pid.to_string()).join("smaps_rollup")).ok()?;
    fn kb(content: &str, key: &str) -> Option<u64> {
        for line in content.lines() {
            let mut parts = line.split_whitespace();
            if parts.next() == Some(key) {
                return parts.next()?.parse::<u64>().ok();
            }
        }
        None
    }
    Some(SmapsHints {
        rss_kb: kb(&content, "Rss:")?,
        anon_kb: kb(&content, "Anonymous:")?,
        private_dirty_kb: kb(&content, "Private_Dirty:")?,
    })
}

/// Per-process RSS history for the leak-trend fit.
struct ProcBaseline {
    comm: Option<String>,
    /// `(sampled_at, rss_bytes)` within the sliding window, plus the anchor.
    samples: VecDeque<(Instant, u64)>,
    last_seen: Instant,
}

/// Stateful memory-leak-trend monitor.
pub struct MemoryLeakMonitor {
    proc_root: PathBuf,
    interval: Duration,
    baselines: HashMap<(u32, u64), ProcBaseline>,
    warn_cooldown: Duration,
    max_iterations: Option<u64>,
    /// When each process-incarnation+verdict was last warned about.
    last_warned: HashMap<(String, LeakVerdict), Instant>,
    /// Whether the last incident-record attempt failed (warn-once, then
    /// debug until a record succeeds — `handle_finding` retries every scan).
    record_unhealthy: bool,
    /// Where findings are recorded so they are visible through the API
    /// and MCP tools, not just the daemon logs. `None` keeps the monitor
    /// log-only.
    incident_store: Option<Arc<IncidentStore>>,
}

impl MemoryLeakMonitor {
    pub fn new(interval: Duration) -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            interval,
            baselines: HashMap::new(),
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

    /// Quiet period between repeat warnings for the same process+verdict.
    /// `Duration::ZERO` warns on every occurrence (useful for tests).
    pub fn with_warn_cooldown(mut self, cooldown: Duration) -> Self {
        self.warn_cooldown = cooldown;
        self
    }

    /// Records findings as `memory_leak` incidents so they surface through
    /// `/incidents` and the MCP tools, not just the daemon logs. Takes
    /// `Option` to mirror the other monitors: the store may be unavailable
    /// (no DB path), in which case the monitor stays log-only.
    pub fn with_incident_store(mut self, store: Option<Arc<IncidentStore>>) -> Self {
        self.incident_store = store;
        self
    }

    /// Log-reporting gate: true the first time a process reports a given
    /// verdict, and again once the cooldown has elapsed. This gates the log
    /// line only — incident recording is decided separately against the
    /// store (see `handle_finding`), so a failed insert is retried on the
    /// next scan instead of being swallowed by this cooldown.
    fn should_warn(&mut self, finding: &MemoryLeak) -> bool {
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

    /// Folds one poll's RSS reading into the process's baseline. A missing
    /// `statm` leaves the baseline untouched — absence is not zero, and the
    /// fit simply runs on fewer samples.
    ///
    /// The newest sample at or before the window cutoff is retained as the
    /// baseline anchor (same discipline as the runqueue monitor): polls
    /// land slightly more than 30s apart, so without the anchor the window
    /// would silently shrink and the fitted growth would understate the
    /// real trend.
    fn update_baseline(&mut self, pid: u32, starttime: u64, now: Instant, rss_bytes: u64) {
        let baseline = self
            .baselines
            .entry((pid, starttime))
            .or_insert_with(|| ProcBaseline {
                comm: None,
                samples: VecDeque::new(),
                last_seen: now,
            });
        baseline.last_seen = now;
        baseline.samples.push_back((now, rss_bytes));
        let cutoff = now.checked_sub(WINDOW).unwrap_or(now);
        // Prune aged samples but keep the anchor: pop the front only while
        // the *second* sample is still at or before the cutoff, so the
        // front remains the newest sample on or before the cutoff.
        while baseline.samples.len() > 1 && baseline.samples[1].0 <= cutoff {
            baseline.samples.pop_front();
        }
    }

    /// One poll: sample every process's RSS, refresh baselines, fit the
    /// in-window trend for processes with enough history, and return a
    /// finding for the worst sustained grower when it is actionable. The
    /// first sightings of a process only establish its baseline.
    pub fn tick(&mut self) -> Option<MemoryLeak> {
        self.tick_at(Instant::now())
    }

    fn tick_at(&mut self, now: Instant) -> Option<MemoryLeak> {
        // `(pid, starttime)` pairs observed alive this poll. A PID seen
        // under a *different* starttime than a baseline's means that
        // incarnation is dead (PID reuse) — its trend must not linger or,
        // worse, keep firing from frozen samples.
        let mut live: HashMap<u32, u64> = HashMap::new();
        for pid in list_pids(&self.proc_root) {
            // starttime is the incarnation identity: a recycled PID gets a
            // fresh baseline instead of inheriting the dead process's
            // trend. Unreadable stat ⇒ skip the process this poll.
            let Some(starttime) = read_starttime(&self.proc_root, pid) else {
                continue;
            };
            live.insert(pid, starttime);
            let key = (pid, starttime);
            // Touch last_seen for live processes even when statm is
            // unreadable, so a transient read failure doesn't age out a
            // live baseline.
            match self.baselines.get_mut(&key) {
                Some(baseline) => {
                    baseline.last_seen = now;
                    if let Some(comm) = read_comm(&self.proc_root, pid) {
                        baseline.comm = Some(comm);
                    }
                }
                None => {
                    self.baselines.insert(
                        key,
                        ProcBaseline {
                            comm: read_comm(&self.proc_root, pid),
                            samples: VecDeque::new(),
                            last_seen: now,
                        },
                    );
                }
            }
            // Absence is not zero: no sample this poll, baseline intact.
            if let Some(rss) = read_rss_bytes(&self.proc_root, pid) {
                self.update_baseline(pid, starttime, now, rss);
            }
        }

        // Drop baselines for dead incarnations and long-gone processes so
        // the map stays bounded and stale trends never fire.
        self.baselines.retain(|&(pid, starttime), baseline| {
            match live.get(&pid) {
                // Same incarnation still alive: age out only when idle.
                Some(&cur) if cur == starttime => {
                    now.duration_since(baseline.last_seen) < STALE_BASELINE
                }
                // PID alive under a new starttime: the old incarnation is
                // gone — drop its trend immediately.
                Some(_) => {
                    debug!(
                        "[memleak] pid={pid} reused (starttime {starttime} gone); \
                         dropping its RSS baseline"
                    );
                    false
                }
                // Not observed this poll (unreadable stat or exited):
                // age it out.
                None => now.duration_since(baseline.last_seen) < STALE_BASELINE,
            }
        });

        // Fit every *live* process with enough in-window history. Dead
        // incarnations keep their samples for transient read failures, but
        // a frozen trend from an exited process must not select it as the
        // finding — or crowd out a smaller live trend.
        let mut worst: Option<MemoryLeak> = None;
        for (&(pid, starttime), baseline) in &self.baselines {
            if live.get(&pid) != Some(&starttime) {
                continue;
            }
            if baseline.samples.len() < MIN_SAMPLES {
                continue;
            }
            let t0 = baseline.samples[0].0;
            let xs: Vec<f64> = baseline
                .samples
                .iter()
                .map(|(t, _)| t.duration_since(t0).as_secs_f64())
                .collect();
            let ys: Vec<f64> = baseline
                .samples
                .iter()
                .map(|(_, rss)| *rss as f64)
                .collect();
            let Some((slope, r2)) = linear_fit(&xs, &ys) else {
                continue;
            };
            let span_secs = xs[xs.len() - 1] - xs[0];
            // Fitted growth over the in-window span: a partial window
            // under-reports by construction, never inflates.
            let growth_bytes = (slope * span_secs).max(0.0) as u64;
            if !classify(slope, r2, growth_bytes).actionable() {
                continue;
            }
            let candidate = MemoryLeak {
                pid,
                starttime,
                comm: baseline.comm.clone(),
                slope_bytes_per_sec: slope,
                r_squared: r2,
                growth_bytes,
                window_secs: WINDOW.as_secs_f64(),
                sample_count: baseline.samples.len(),
                // Allocator hints are read once per firing, not per poll.
                smaps: read_smaps_hints(&self.proc_root, pid),
                verdict: LeakVerdict::LeakWarning,
            };
            let worse = match &worst {
                None => true,
                Some(prev) => candidate.growth_bytes > prev.growth_bytes,
            };
            if worse {
                worst = Some(candidate);
            }
        }
        worst
    }

    pub async fn run(mut self) {
        info!("[memleak] starting memory leak trend monitor");
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
    /// Logging rides `should_warn`'s cooldown. Recording is gated only on
    /// the store itself, which is the source of truth for what was
    /// persisted: the log cooldown never suppresses a record attempt, so a
    /// transient insert failure is retried on the next scan instead of
    /// vanishing for the whole cooldown.
    async fn handle_finding(&mut self, finding: &MemoryLeak) {
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
            .recent_incident_keys("memory_leak", self.warn_cooldown.as_secs())
            .await
        {
            Ok(keys) => keys,
            Err(e) => {
                warn!("[memleak] couldn't check recent incidents: {e}");
                HashSet::new()
            }
        }
    }

    /// Best-effort: a failing store must not break the monitoring loop.
    /// The first failure logs at warn level; repeats stay at debug until a
    /// record succeeds, since `handle_finding` retries the insert on every
    /// scan while the trend continues.
    async fn record_incident(&mut self, finding: &MemoryLeak) {
        let Some(store) = &self.incident_store else {
            return;
        };
        let incident = incident_from_finding(finding);
        match store.insert(&incident).await {
            Ok(id) => {
                debug!(
                    "[memleak] recorded incident #{id} for {}",
                    finding.victim_label()
                );
                self.record_unhealthy = false;
            }
            Err(e) => {
                if self.record_unhealthy {
                    debug!(
                        "[memleak] still failing to record incident for {}: {e}",
                        finding.victim_label()
                    );
                } else {
                    warn!(
                        "[memleak] failed to record incident for {}: {e}",
                        finding.victim_label()
                    );
                    self.record_unhealthy = true;
                }
            }
        }
    }
}

/// Builds the `memory_leak` incident row for one finding.
///
/// Field mapping, kept honest about what this monitor measures:
/// * `psi_cpu` / `psi_memory` / `cpu_percent` / `load_avg` are host-level
///   fields this monitor doesn't sample, so they're zero/empty; the
///   triggering reading is the RSS trend, carried in `system_snapshot`.
/// * `target_pid` / `target_name` name the growing process incarnation.
/// * The trend is `inferred` — RSS growth is consistent with a leak, not
///   proof of one. The smaps hints are `measured` kernel accounting when
///   readable, `unavailable` otherwise.
fn incident_from_finding(finding: &MemoryLeak) -> Incident {
    let smaps = finding.smaps.as_ref().map(|h| {
        serde_json::json!({
            "rss_kb": h.rss_kb,
            "anon_kb": h.anon_kb,
            "private_dirty_kb": h.private_dirty_kb,
        })
    });
    let snapshot = serde_json::json!({
        "pid": finding.pid,
        "starttime": finding.starttime,
        "comm": finding.comm,
        "slope_mib_per_hr": finding.slope_mib_per_hr(),
        "r_squared": finding.r_squared,
        "growth_mib": finding.growth_mib(),
        "window_secs": finding.window_secs,
        "sample_count": finding.sample_count,
        "smaps": smaps,
        "source_tier": "polling",
        "verdict": format!("{:?}", finding.verdict),
        // RSS growth is consistent with a leak, not proof of one; the
        // smaps breakdown is measured kernel accounting when readable.
        "evidence": {
            "rss_trend": "inferred",
            "smaps": if finding.smaps.is_some() { "measured" } else { "unavailable" },
        },
    });
    Incident {
        id: None,
        timestamp: chrono::Utc::now().timestamp(),
        event_type: "memory_leak".to_string(),
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

/// One human- and agent-readable line per actionable finding. The trend is
/// `inferred` — the line says "consistent with a leak", never "leak".
fn report(finding: &MemoryLeak) {
    let victim = match finding.comm.as_deref() {
        Some(comm) => format!("{comm} (pid={})", finding.pid),
        None => format!("pid={}", finding.pid),
    };
    let smaps_note = match &finding.smaps {
        Some(h) => format!(
            "; smaps_rollup: rss={}MB anon={}MB private_dirty={}MB",
            h.rss_kb / 1024,
            h.anon_kb / 1024,
            h.private_dirty_kb / 1024,
        ),
        None => "; smaps_rollup unavailable".to_string(),
    };
    if finding.verdict.actionable() {
        warn!(
            "[memleak] WARNING: process {victim} shows a growth trend consistent with a leak: \
             +{:.0}MB over {:.0}s ({:.0} samples, slope {:.1}MiB/hr, R²={:.2}) \
             [rss trend inferred]{smaps_note}",
            finding.growth_mib(),
            finding.window_secs,
            finding.sample_count,
            finding.slope_mib_per_hr(),
            finding.r_squared,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// MiB → resident pages, using the same page size the monitor reads.
    /// Whole MiB values are exact on any power-of-two page size.
    fn mib_pages(mib: u64) -> u64 {
        mib * 1024 * 1024 / page_size_bytes()
    }

    struct FakeProc {
        dir: TempDir,
    }

    impl FakeProc {
        fn new() -> Self {
            Self {
                dir: TempDir::new().unwrap(),
            }
        }

        /// (Re)places a fake process: `<pid>/stat` (starttime in field 22),
        /// `<pid>/statm` (resident pages), `<pid>/comm`, and optionally
        /// `<pid>/smaps_rollup`.
        fn set_proc(
            &self,
            pid: u32,
            comm: &str,
            starttime: u64,
            resident_pages: u64,
            smaps: Option<(u64, u64, u64)>,
        ) {
            let d = self.dir.path().join(pid.to_string());
            fs::create_dir_all(&d).unwrap();
            // Fields after the last `)`: index 0 is field 3 (state), so
            // field 22 (starttime) is index 19.
            fs::write(
                d.join("stat"),
                format!("{pid} ({comm}) R 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {starttime}\n"),
            )
            .unwrap();
            fs::write(d.join("statm"), format!("0 {resident_pages} 0 0 0 0 0\n")).unwrap();
            fs::write(d.join("comm"), format!("{comm}\n")).unwrap();
            if let Some((rss_kb, anon_kb, pd_kb)) = smaps {
                fs::write(
                    d.join("smaps_rollup"),
                    format!(
                        "Rss:                  {rss_kb} kB\n\
                         Anonymous:            {anon_kb} kB\n\
                         Private_Dirty:        {pd_kb} kB\n"
                    ),
                )
                .unwrap();
            }
        }

        fn remove_statm(&self, pid: u32) {
            fs::remove_file(self.dir.path().join(pid.to_string()).join("statm")).unwrap();
        }

        fn monitor(&self) -> MemoryLeakMonitor {
            MemoryLeakMonitor::new(Duration::from_secs(30)).with_proc_root(self.dir.path())
        }
    }

    fn warning_finding(comm: &str) -> MemoryLeak {
        MemoryLeak {
            pid: 4242,
            starttime: 999,
            comm: Some(comm.to_string()),
            slope_bytes_per_sec: 100_000.0,
            r_squared: 0.95,
            growth_bytes: 60 * 1024 * 1024,
            window_secs: 900.0,
            sample_count: 30,
            smaps: None,
            verdict: LeakVerdict::LeakWarning,
        }
    }

    #[test]
    fn classify_matrix() {
        // Sustained growth above all gates fires.
        assert_eq!(
            classify(1000.0, 0.9, 60 * 1024 * 1024),
            LeakVerdict::LeakWarning
        );
        // Flat, shrinking, noisy, or small growth stays healthy.
        assert_eq!(classify(0.0, 0.99, 100 * 1024 * 1024), LeakVerdict::Healthy);
        assert_eq!(classify(-1000.0, 0.99, 0), LeakVerdict::Healthy);
        assert_eq!(
            classify(1000.0, 0.5, 60 * 1024 * 1024),
            LeakVerdict::Healthy
        );
        assert_eq!(
            classify(1000.0, 0.9, 10 * 1024 * 1024),
            LeakVerdict::Healthy
        );
        // Boundary: exactly at the gates fires.
        assert_eq!(
            classify(1.0, MIN_R_SQUARED, MIN_GROWTH_BYTES),
            LeakVerdict::LeakWarning
        );
    }

    #[test]
    fn linear_fit_math() {
        // Perfect line: exact slope, R² = 1.
        let xs: Vec<f64> = (0..10).map(|i| i as f64).collect();
        let ys: Vec<f64> = xs.iter().map(|x| 2.0 * x + 1.0).collect();
        let (slope, r2) = linear_fit(&xs, &ys).unwrap();
        assert!((slope - 2.0).abs() < 1e-9);
        assert!((r2 - 1.0).abs() < 1e-9);
        // Constant series: zero slope, R² = 0 (not a spurious perfect fit).
        let flat = vec![5.0; 10];
        let (slope, r2) = linear_fit(&xs, &flat).unwrap();
        assert_eq!(slope, 0.0);
        assert_eq!(r2, 0.0);
        // Sawtooth churn: poor fit despite net drift.
        let saw: Vec<f64> = (0..20)
            .map(|i| if i % 2 == 0 { 0.0 } else { 10.0 })
            .collect();
        let xs2: Vec<f64> = (0..20).map(|i| i as f64).collect();
        let (_, r2) = linear_fit(&xs2, &saw).unwrap();
        assert!(r2 < MIN_R_SQUARED, "sawtooth must not look sustained");
        // Degenerate inputs.
        assert!(linear_fit(&[1.0], &[2.0]).is_none());
        assert!(linear_fit(&[1.0, 1.0], &[2.0, 3.0]).is_none());
    }

    #[test]
    fn fires_on_sustained_growth() {
        let fake = FakeProc::new();
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        // 100MB of linear growth over the 15-min window: 30 samples.
        let mut last = None;
        for i in 0..30u64 {
            let mib = 100 + i * 100 / 29;
            fake.set_proc(7, "leaky", 1000, mib_pages(mib), None);
            last = mon.tick_at(t0 + Duration::from_secs(30 * i));
            if i < 14 {
                assert!(last.is_none(), "needs {MIN_SAMPLES} samples first");
            }
        }
        let finding = last.expect("sustained 100MB+ growth must fire");
        assert_eq!(finding.verdict, LeakVerdict::LeakWarning);
        assert_eq!(finding.pid, 7);
        assert!(finding.r_squared > 0.99);
        assert!(finding.growth_bytes >= MIN_GROWTH_BYTES);
        assert_eq!(finding.sample_count, 30, "window holds 30 samples");
        assert!(finding.smaps.is_none(), "no smaps_rollup in fixture");
    }

    #[test]
    fn noisy_rss_does_not_fire() {
        let fake = FakeProc::new();
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        // Sawtooth with net upward drift: the R² gate must hold it back.
        let mut finding = None;
        for i in 0..30u64 {
            let mib = 100 + (i % 2) * 40 + i / 3;
            fake.set_proc(9, "churny", 2000, mib_pages(mib), None);
            finding = mon.tick_at(t0 + Duration::from_secs(30 * i));
        }
        assert!(
            finding.is_none(),
            "churn must not fire: R² gate, not just net drift"
        );
    }

    #[test]
    fn partial_window_never_inflates() {
        let fake = FakeProc::new();
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        // Steep growth but only 10 samples (< MIN_SAMPLES): silence, not a
        // finding scaled up from a short span.
        for i in 0..10u64 {
            fake.set_proc(11, "fast", 3000, mib_pages(100 + i * 20), None);
            assert!(mon.tick_at(t0 + Duration::from_secs(30 * i)).is_none());
        }
    }

    #[test]
    fn pid_reuse_starts_a_fresh_baseline() {
        let fake = FakeProc::new();
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        // Incarnation 1 grows for 20 samples (enough to fire on its own).
        for i in 0..20u64 {
            fake.set_proc(13, "recycled", 4000, mib_pages(100 + i * 5), None);
            mon.tick_at(t0 + Duration::from_secs(30 * i));
        }
        // The PID is reused: new starttime, flat RSS. The old trend must
        // not leak into the new incarnation's baseline.
        for i in 20..40u64 {
            fake.set_proc(13, "recycled", 9999, mib_pages(100), None);
            let finding = mon.tick_at(t0 + Duration::from_secs(30 * i));
            assert!(
                finding.is_none() || finding.unwrap().starttime == 9999,
                "old incarnation's growth must not fire for the new one"
            );
        }
        assert_eq!(
            mon.baselines.len(),
            1,
            "old incarnation pruned or never refit"
        );
        assert!(mon.baselines.contains_key(&(13, 9999)));
    }

    #[test]
    fn unreadable_statm_skips_the_sample() {
        let fake = FakeProc::new();
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        for i in 0..20u64 {
            fake.set_proc(15, "flaky", 5000, mib_pages(100 + i * 5), None);
            if i == 10 {
                fake.remove_statm(15);
            }
            mon.tick_at(t0 + Duration::from_secs(30 * i));
            if i == 10 {
                // Restore for the next poll; the missed sample is just gone.
                fake.set_proc(15, "flaky", 5000, mib_pages(100 + i * 5), None);
            }
        }
        let baseline = &mon.baselines[&(15, 5000)];
        assert_eq!(
            baseline.samples.len(),
            19,
            "one missed sample, baseline intact"
        );
    }

    #[test]
    fn smaps_hints_ride_along_when_readable() {
        let fake = FakeProc::new();
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        for i in 0..30u64 {
            fake.set_proc(
                17,
                "leaky",
                6000,
                mib_pages(100 + i * 100 / 29),
                Some((200 * 1024, 150 * 1024, 140 * 1024)),
            );
            mon.tick_at(t0 + Duration::from_secs(30 * i));
        }
        fake.set_proc(
            17,
            "leaky",
            6000,
            mib_pages(205),
            Some((205 * 1024, 155 * 1024, 145 * 1024)),
        );
        let finding = mon
            .tick_at(t0 + Duration::from_secs(30 * 30))
            .expect("must fire");
        let hints = finding.smaps.expect("smaps_rollup readable in fixture");
        assert_eq!(hints.anon_kb, 155 * 1024);
    }

    #[test]
    fn smaps_rollup_kernel_format_parses() {
        // Verbatim 6.x kernel layout: a `[rollup]` header line, then the
        // real field names. The kernel's field is `Anonymous:`, not
        // `Anon:` — a fixture using the wrong name masks a production
        // failure where every firing reports hints as unavailable.
        let fake = FakeProc::new();
        let d = fake.dir.path().join("42");
        fs::create_dir_all(&d).unwrap();
        fs::write(
            d.join("smaps_rollup"),
            "58d32c280000-7ffe54261000 ---p 00000000 00:00 0                          [rollup]\n\
             Rss:                1668 kB\n\
             Pss:                 558 kB\n\
             Shared_Clean:       1520 kB\n\
             Private_Clean:        40 kB\n\
             Private_Dirty:       108 kB\n\
             Referenced:         1668 kB\n\
             Anonymous:           108 kB\n\
             KSM:                   0 kB\n",
        )
        .unwrap();
        let hints = read_smaps_hints(fake.dir.path(), 42).expect("kernel-format rollup must parse");
        assert_eq!(hints.rss_kb, 1668);
        assert_eq!(hints.anon_kb, 108);
        assert_eq!(hints.private_dirty_kb, 108);
    }

    #[test]
    fn dead_process_does_not_crowd_out_live_trend() {
        // Two growing processes; the bigger trend exits mid-window. Its
        // baseline is retained for transient read failures, but the frozen
        // trend must not be selected as the finding — the smaller *live*
        // trend must win instead.
        let fake = FakeProc::new();
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        for i in 0..20u64 {
            // pid 21: fast grower (~190 MiB over the window).
            fake.set_proc(21, "big", 7000, mib_pages(100 + i * 10), None);
            // pid 23: slower but actionable (~76 MiB).
            fake.set_proc(23, "small", 8000, mib_pages(100 + i * 4), None);
            mon.tick_at(t0 + Duration::from_secs(30 * i));
        }
        // pid 21 exits: its whole proc dir vanishes.
        fs::remove_dir_all(fake.dir.path().join("21")).unwrap();
        fake.set_proc(23, "small", 8000, mib_pages(100 + 20 * 4), None);
        let finding = mon
            .tick_at(t0 + Duration::from_secs(30 * 20))
            .expect("live trend must still fire");
        assert_eq!(
            finding.pid, 23,
            "dead process's frozen trend must not be selected"
        );
        // And it keeps not firing for the dead incarnation on later polls.
        fake.set_proc(23, "small", 8000, mib_pages(100 + 21 * 4), None);
        let finding = mon.tick_at(t0 + Duration::from_secs(30 * 21));
        assert!(
            finding.is_none() || finding.unwrap().pid == 23,
            "no refire for the dead process"
        );
    }

    #[test]
    fn incident_mapping_labels_evidence_honestly() {
        let mut finding = warning_finding("leaky");
        finding.smaps = Some(SmapsHints {
            rss_kb: 100,
            anon_kb: 80,
            private_dirty_kb: 70,
        });
        let incident = incident_from_finding(&finding);
        assert_eq!(incident.event_type, "memory_leak");
        assert_eq!(incident.action, "alert");
        assert_eq!(incident.target_pid, Some(4242));
        assert_eq!(
            incident.target_name.as_deref(),
            Some("leaky (pid=4242, start=999)")
        );
        assert_eq!(incident.psi_cpu, 0.0);
        let snapshot: serde_json::Value =
            serde_json::from_str(incident.system_snapshot.as_deref().unwrap()).unwrap();
        assert_eq!(snapshot["verdict"], "LeakWarning");
        // The trend is inferred — RSS growth is consistent with a leak,
        // never proof of one.
        assert_eq!(snapshot["evidence"]["rss_trend"], "inferred");
        assert_eq!(snapshot["evidence"]["smaps"], "measured");
        assert!((snapshot["growth_mib"].as_f64().unwrap() - 60.0).abs() < 1e-9);

        // Without smaps_rollup the label is unavailable, not fabricated.
        let bare = incident_from_finding(&warning_finding("leaky"));
        let snapshot: serde_json::Value =
            serde_json::from_str(bare.system_snapshot.as_deref().unwrap()).unwrap();
        assert_eq!(snapshot["evidence"]["smaps"], "unavailable");
        assert!(snapshot["smaps"].is_null());
    }

    #[test]
    fn warn_cooldown_suppresses_repeat_logs_not_records() {
        let mut mon = MemoryLeakMonitor::new(Duration::from_secs(30));
        let finding = warning_finding("leaky");
        assert!(mon.should_warn(&finding), "first sighting warns");
        assert!(!mon.should_warn(&finding), "cooldown suppresses the log");
        // A *different* process incarnation is a different victim.
        let mut other = warning_finding("leaky");
        other.pid = 7777;
        assert!(
            mon.should_warn(&other),
            "distinct victims warn independently"
        );
    }

    #[tokio::test]
    async fn finding_is_recorded_as_incident() {
        let fake = FakeProc::new();
        let db_dir = TempDir::new().unwrap();
        let store = Arc::new(
            IncidentStore::new(db_dir.path().join("incidents.db"))
                .await
                .unwrap(),
        );
        let mut mon = fake.monitor().with_incident_store(Some(Arc::clone(&store)));
        let finding = warning_finding("leaky");
        mon.handle_finding(&finding).await;

        let incidents = store
            .recent_filtered(10, Some("memory_leak"), None)
            .await
            .unwrap();
        assert_eq!(incidents.len(), 1, "one finding, one incident");
        assert_eq!(incidents[0].event_type, "memory_leak");
        assert_eq!(
            incidents[0].target_name.as_deref(),
            Some("leaky (pid=4242, start=999)")
        );

        // The store already has this finding: handling it again must not
        // write a second row. Recording is decided against the store, not
        // the log cooldown.
        mon.handle_finding(&finding).await;
        let incidents = store
            .recent_filtered(10, Some("memory_leak"), None)
            .await
            .unwrap();
        assert_eq!(incidents.len(), 1, "repeat findings must not duplicate");

        // A fresh monitor — the daemon restarted, so the bounded in-memory
        // cooldown map is empty — must not re-record either.
        let mut mon2 = fake.monitor().with_incident_store(Some(Arc::clone(&store)));
        mon2.handle_finding(&finding).await;
        let incidents = store
            .recent_filtered(10, Some("memory_leak"), None)
            .await
            .unwrap();
        assert_eq!(
            incidents.len(),
            1,
            "a restarted monitor must not duplicate incidents the store already has"
        );
    }

    #[tokio::test]
    async fn failed_insert_is_retried_on_the_next_scan() {
        let db_dir = TempDir::new().unwrap();
        let db_path = db_dir.path().join("incidents.db");
        let finding = warning_finding("leaky");

        // The store is down: the finding is logged, but the failed insert
        // must not poison future record attempts — recording has no
        // in-memory cooldown, only the store's own contents.
        let down_store = Arc::new(IncidentStore::new(&db_path).await.unwrap());
        down_store.close_pool_for_test().await;
        let mut mon = MemoryLeakMonitor::new(Duration::from_secs(30))
            .with_incident_store(Some(Arc::clone(&down_store)));
        mon.handle_finding(&finding).await;

        // The store recovers (fresh pool on the same file). The next scan
        // must retry the insert instead of sitting out a cooldown.
        let up_store = Arc::new(IncidentStore::new(&db_path).await.unwrap());
        mon.incident_store = Some(Arc::clone(&up_store));
        mon.handle_finding(&finding).await;
        let incidents = up_store
            .recent_filtered(10, Some("memory_leak"), None)
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
            .recent_filtered(10, Some("memory_leak"), None)
            .await
            .unwrap();
        assert_eq!(incidents.len(), 1, "a recorded finding must not duplicate");
    }

    #[tokio::test]
    async fn monitor_without_store_stays_log_only() {
        // No incident store configured: handle_finding must not fail, just log.
        let mut mon =
            MemoryLeakMonitor::new(Duration::from_secs(30)).with_warn_cooldown(Duration::ZERO);
        mon.handle_finding(&warning_finding("leaky")).await;
    }
}
