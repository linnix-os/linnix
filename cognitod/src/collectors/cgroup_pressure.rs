//! Generic cgroup pressure monitor: userspace per-cgroup stall attribution.
//!
//! [`PsiMonitor`](super::psi::PsiMonitor) tracks pressure for Kubernetes pods
//! (paths under `kubepods`), and only runs when a K8s context exists. This
//! monitor covers everything else: systemd slices (`system.slice`,
//! `user.slice`), container runtimes outside K8s, and hand-rolled cgroups on a
//! plain Linux host. It needs no eBPF, no tracepoints, and no privileges
//! beyond reading cgroupfs.
//!
//! The measurement primitive is the `total=` counter in each
//! `{cpu,memory,io}.pressure` file: microseconds of stall accrued since the
//! cgroup was created. Deltas over the scan window give exact per-cgroup stall
//! percentages. `cpu.stat`'s `throttled_usec` separates two cases operators
//! constantly confuse:
//!
//! * pressure **without** throttling -> genuine contention (noisy neighbor,
//!   undersized CPU). Fix the workload placement.
//! * throttling **without** pressure -> the `cpu.max` limit itself is the
//!   bottleneck. Fix the limit, not the neighbors.
//!
//! Every finding is a kernel counter delta, so the confidence is `measured`;
//! the *verdict* (contended vs throttled) is `inferred` from the combination
//! and is labeled as such in log output.
//!
//! Two honesty mechanisms keep the signal clean:
//!
//! * A restarted unit destroys and recreates its cgroup (same name, new
//!   inode, counters reset). The directory inode is the instance identity —
//!   the way [`PsiMonitor`](super::psi::PsiMonitor) keys pods by UID — so a
//!   recreated cgroup re-baselines instead of diffing the new counters against
//!   the dead instance's and clamping to a bogus Healthy.
//! * Repeat warnings for the same cgroup+verdict are cooled down (15min
//!   default), mirroring `AttributionSink::claim_report_slot`; a verdict
//!   *change* always reports. `AttributionSink` itself isn't reused because it
//!   speaks K8s offender/victim pairs — inventing fake pods for systemd units
//!   would violate the evidence labeling above.
//!
//! Two hierarchy rules keep Kubernetes hosts clean:
//!
//! * `kubepods` subtrees are pruned from the directory walk before descending
//!   (those belong to [`PsiMonitor`](super::psi::PsiMonitor)).
//! * On Kubernetes hosts the monitor also drops *aggregate ancestors* of
//!   kubepods subtrees (e.g. the root cgroup): cgroup v2 pressure counters
//!   are hierarchical, so the root sample includes every pod's stalls, and
//!   reporting it here would double-count `PsiMonitor`'s per-pod findings.

use log::{debug, info, warn};
use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use walkdir::WalkDir;

use crate::incidents::{Incident, IncidentStore};

use super::psi::parse_psi_file;

/// Window stall percentage at or above which a cgroup is called contended.
const CONTENDED_STALL_PCT: f64 = 20.0;
/// Throttled seconds per window at or above which a cgroup is called throttled.
const THROTTLED_SECS: f64 = 1.0;
/// Stall percentage below which throttling is considered "without pressure".
const NO_PRESSURE_STALL_PCT: f64 = 10.0;
/// Default walk depth: root -> slice -> unit (e.g. `system.slice/nginx.service`).
const DEFAULT_MAX_DEPTH: usize = 3;
/// Default quiet period between repeat warnings for the same cgroup+verdict,
/// so a stall that lasts an hour doesn't emit ~360 near-identical warn! lines.
const DEFAULT_WARN_COOLDOWN: Duration = Duration::from_secs(15 * 60);
/// Cap on the warn-cooldown map; entries older than the cooldown are pruned
/// before it can grow past this on hosts with churny cgroups.
const MAX_COOLDOWN_ENTRIES: usize = 1024;

/// What the combination of pressure and throttling signals means for a cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StallVerdict {
    Healthy,
    /// CPU PSI pressure without throttling: genuine CPU contention (noisy
    /// neighbor, undersized CPU).
    CpuContended,
    /// IO PSI pressure without CPU pressure: storage contention (slow disk,
    /// noisy neighbor on the block device) — not a CPU problem.
    IoContended,
    /// Throttled by `cpu.max` without pressure: the limit is the bottleneck.
    Throttled,
    /// Both at once: capped *and* still contending for what's left.
    ThrottledAndContended,
    MemoryPressure,
    OomKill,
}

impl StallVerdict {
    /// `false` for `Healthy`; used to filter log/report noise.
    pub fn actionable(self) -> bool {
        !matches!(self, StallVerdict::Healthy)
    }
}

/// Per-cgroup stall report for one scan window.
#[derive(Debug, Clone)]
pub struct CgroupStall {
    /// Path relative to the cgroup root, e.g. `system.slice/nginx.service`.
    /// `/` for the root cgroup itself.
    pub cgroup: String,
    /// % of the window with at least one task stalled waiting for CPU.
    pub cpu_stall_pct: f64,
    /// % of the window with *all* tasks stalled waiting for CPU.
    pub cpu_full_pct: f64,
    /// % of the window with at least one task stalled on memory.
    pub mem_stall_pct: f64,
    /// % of the window with at least one task stalled on IO.
    pub io_stall_pct: f64,
    /// Seconds of CPU time throttled away by `cpu.max` in the window.
    pub throttled_secs: f64,
    /// Times `memory.high` was breached in the window.
    pub mem_high_events: u64,
    /// OOM kills in the window.
    pub oom_kills: u64,
    pub verdict: StallVerdict,
}

/// Cumulative counters read from one cgroup directory in a single scan.
///
/// Every counter is `Option`: a file that is missing or unreadable is `None`,
/// never zero — zero is a real reading, absence is not. Treating absence as
/// zero would poison the baseline: the next good reading would look like it
/// all accrued in one window, fabricating huge stall rates or reporting
/// historical `oom_kill` counts as new.
#[derive(Debug, Clone, Default)]
struct CgroupTotals {
    /// Inode of the cgroup directory: the instance identity. A systemd unit
    /// restart destroys and recreates the cgroup (new inode, same name), so
    /// the inode tells a live instance apart from a recycled name.
    ino: u64,
    cpu_some_total: Option<u64>,
    cpu_full_total: Option<u64>,
    mem_some_total: Option<u64>,
    io_some_total: Option<u64>,
    throttled_usec: Option<u64>,
    mem_high: Option<u64>,
    oom_kill: Option<u64>,
}

impl CgroupTotals {
    /// Adopts `cur` as the new baseline, except for counters that were
    /// unreadable this scan (`None`): they keep their previous value. A
    /// transient read failure must not reset a baseline to nothing. The one
    /// imprecision this accepts: after a blip, the next delta spans two
    /// windows but is divided by one window's seconds, overstating that
    /// single window up to 2x — bounded, rare, and in the safe direction
    /// (it can only surface a real, sustained stall slightly early).
    fn merge(&mut self, cur: CgroupTotals) {
        // A failed metadata read (ino 0) must not clobber a known identity.
        if cur.ino != 0 {
            self.ino = cur.ino;
        }
        if cur.cpu_some_total.is_some() {
            self.cpu_some_total = cur.cpu_some_total;
        }
        if cur.cpu_full_total.is_some() {
            self.cpu_full_total = cur.cpu_full_total;
        }
        if cur.mem_some_total.is_some() {
            self.mem_some_total = cur.mem_some_total;
        }
        if cur.io_some_total.is_some() {
            self.io_some_total = cur.io_some_total;
        }
        if cur.throttled_usec.is_some() {
            self.throttled_usec = cur.throttled_usec;
        }
        if cur.mem_high.is_some() {
            self.mem_high = cur.mem_high;
        }
        if cur.oom_kill.is_some() {
            self.oom_kill = cur.oom_kill;
        }
    }
}

/// Reads the `total=` stall microseconds for the `some` and `full` lines of a
/// `.pressure` file. Returns `None` when the file is missing or unparseable;
/// a cgroup is never required to expose every pressure file.
fn read_pressure_totals(dir: &Path, name: &str) -> Option<(u64, u64)> {
    let content = std::fs::read_to_string(dir.join(name)).ok()?;
    let snapshot = parse_psi_file(&content).ok()?;
    Some((snapshot.some_total, snapshot.full_total))
}

/// Reads one `key value` counter from a cgroup stat-style file
/// (`cpu.stat`, `memory.events`). Missing file or key -> `None`, never zero:
/// zero is a real reading, absence is not.
fn read_stat_counter(dir: &Path, file: &str, key: &str) -> Option<u64> {
    let content = std::fs::read_to_string(dir.join(file)).ok()?;
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some(key)
            && let Some(value) = parts.next()
            && let Ok(v) = value.parse::<u64>()
        {
            return Some(v);
        }
    }
    None
}

fn read_cgroup_totals(dir: &Path) -> CgroupTotals {
    let cpu = read_pressure_totals(dir, "cpu.pressure");
    let mem = read_pressure_totals(dir, "memory.pressure");
    let io = read_pressure_totals(dir, "io.pressure");
    CgroupTotals {
        ino: std::fs::metadata(dir).map(|m| m.ino()).unwrap_or(0),
        cpu_some_total: cpu.map(|(some, _)| some),
        cpu_full_total: cpu.map(|(_, full)| full),
        mem_some_total: mem.map(|(some, _)| some),
        io_some_total: io.map(|(some, _)| some),
        throttled_usec: read_stat_counter(dir, "cpu.stat", "throttled_usec"),
        mem_high: read_stat_counter(dir, "memory.events", "high"),
        oom_kill: read_stat_counter(dir, "memory.events", "oom_kill"),
    }
}

/// Kubernetes pod slices are `PsiMonitor`'s territory; this monitor skips
/// them. Matched on the full path string so nested slices like
/// `kubepods.slice/kubepods-besteffort.slice/...` are pruned as a unit.
fn is_kubepods_path(path: &Path) -> bool {
    path.to_string_lossy().contains("kubepods")
}

/// Finds cgroup directories (depth-limited) that expose `cpu.pressure`,
/// skipping Kubernetes pod slices — those belong to `PsiMonitor`.
/// Returns `(relative_path, absolute_dir)` pairs.
///
/// When `exclude_kubepods_ancestors` is set (Kubernetes hosts), directories
/// that *contain* kubepods subtrees are excluded too: cgroup v2 pressure
/// counters are hierarchical, so e.g. the root `/` sample includes stalls
/// from every pod underneath it. Reporting that aggregate here would
/// double-count what `PsiMonitor` already attributes per pod.
fn find_cgroup_dirs(
    root: &Path,
    max_depth: usize,
    exclude_kubepods_ancestors: bool,
) -> Vec<(String, PathBuf)> {
    // Kubepods roots pruned from the walk, recorded so their ancestors can be
    // excluded below without a second walk.
    let mut kubepods_roots: Vec<PathBuf> = Vec::new();
    let mut dirs: Vec<(String, PathBuf)> = WalkDir::new(root)
        .max_depth(max_depth)
        .into_iter()
        // Prune kubepods subtrees *before* descending into them: on a node
        // with hundreds of pods a full deep readdir/stat walk every 10s is
        // pure waste when every entry under it is discarded anyway.
        .filter_entry(|e| {
            if e.file_type().is_dir() && is_kubepods_path(e.path()) {
                kubepods_roots.push(e.path().to_path_buf());
                return false;
            }
            true
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_dir())
        .filter(|e| e.path().join("cpu.pressure").is_file())
        .map(|e| {
            let rel = e
                .path()
                .strip_prefix(root)
                .ok()
                .map(|p| p.to_string_lossy().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "/".to_string());
            (rel, e.path().to_path_buf())
        })
        .collect();
    if exclude_kubepods_ancestors {
        dirs.retain(|(_, abs)| !kubepods_roots.iter().any(|k| k.starts_with(abs)));
    }
    dirs
}

fn classify(
    cpu_stall_pct: f64,
    throttled_secs: f64,
    mem_stall_pct: f64,
    io_stall_pct: f64,
    oom_kills: u64,
) -> StallVerdict {
    if oom_kills > 0 {
        return StallVerdict::OomKill;
    }
    if mem_stall_pct >= CONTENDED_STALL_PCT {
        return StallVerdict::MemoryPressure;
    }
    let cpu_contended = cpu_stall_pct >= CONTENDED_STALL_PCT;
    let io_contended = io_stall_pct >= CONTENDED_STALL_PCT;
    let throttled = throttled_secs >= THROTTLED_SECS;
    let no_pressure = cpu_stall_pct < NO_PRESSURE_STALL_PCT;
    match (cpu_contended || io_contended, throttled, no_pressure) {
        (true, true, _) => StallVerdict::ThrottledAndContended,
        // CPU and IO get their own verdicts: an IO-only stall diagnosed as
        // "CPU contention, check for a noisy neighbor" sends the operator to
        // fix the wrong resource.
        (true, false, _) if cpu_contended => StallVerdict::CpuContended,
        (true, false, _) => StallVerdict::IoContended,
        (false, true, true) => StallVerdict::Throttled,
        (false, true, false) => StallVerdict::ThrottledAndContended,
        (false, false, _) => StallVerdict::Healthy,
    }
}

/// A cumulative counter moved backwards: only possible across recreation
/// (counters never decrease within one cgroup instance). Missing readings
/// are not regressions — absence is not a value.
fn counter_regressed(prev: Option<u64>, cur: Option<u64>) -> bool {
    matches!((prev, cur), (Some(p), Some(c)) if c < p)
}

/// True when `cur` cannot be the same cgroup instance `prev` was read from.
///
/// A systemd unit restart destroys and recreates the cgroup: same unit name,
/// new inode, counters reset to zero. Diffing the new instance's counters
/// against the dead instance's would clamp to a bogus Healthy via
/// `saturating_sub` (or understate the real delta), so the caller re-baselines
/// instead. The inode is the instance identity here, the way `PsiMonitor`
/// keys pods by UID (compared only when both sides actually have one); a
/// backwards-moving cumulative counter is the independent backstop signal.
fn is_recreated(prev: &CgroupTotals, cur: &CgroupTotals) -> bool {
    (prev.ino != 0 && cur.ino != 0 && cur.ino != prev.ino)
        || counter_regressed(prev.cpu_some_total, cur.cpu_some_total)
        || counter_regressed(prev.cpu_full_total, cur.cpu_full_total)
        || counter_regressed(prev.mem_some_total, cur.mem_some_total)
        || counter_regressed(prev.io_some_total, cur.io_some_total)
        || counter_regressed(prev.throttled_usec, cur.throttled_usec)
        || counter_regressed(prev.mem_high, cur.mem_high)
        || counter_regressed(prev.oom_kill, cur.oom_kill)
}

/// Stateful per-cgroup pressure monitor. Keeps the previous scan's cumulative
/// counters so each [`CgroupPressureMonitor::tick`] returns window deltas.
pub struct CgroupPressureMonitor {
    root: PathBuf,
    max_depth: usize,
    interval: Duration,
    previous: HashMap<String, CgroupTotals>,
    previous_at: Option<Instant>,
    max_iterations: Option<u64>,
    warn_cooldown: Duration,
    /// When a Kubernetes context exists, `PsiMonitor` owns kubepods pressure;
    /// aggregates whose hierarchical counters include kubepods stalls (e.g.
    /// the root cgroup) are then excluded from this monitor's scan so the
    /// same stall isn't reported twice.
    exclude_kubepods_ancestors: bool,
    /// When each cgroup+verdict was last warned about. Keyed per
    /// cgroup+verdict rather than per cgroup, mirroring
    /// `AttributionSink::claim_report_slot`: a cgroup flipping verdicts
    /// mid-incident is new information, not a repeat.
    last_warned: HashMap<(String, StallVerdict), Instant>,
    /// Where stall findings are recorded so they are visible through the API
    /// and MCP tools (`linnix_recent_incidents`, `linnix_explain_incident`),
    /// not just the daemon logs. `None` keeps the monitor log-only.
    incident_store: Option<Arc<IncidentStore>>,
}

impl CgroupPressureMonitor {
    pub fn new(interval: Duration) -> Self {
        Self {
            root: PathBuf::from("/sys/fs/cgroup"),
            max_depth: DEFAULT_MAX_DEPTH,
            interval,
            previous: HashMap::new(),
            previous_at: None,
            max_iterations: None,
            warn_cooldown: DEFAULT_WARN_COOLDOWN,
            exclude_kubepods_ancestors: false,
            last_warned: HashMap::new(),
            incident_store: None,
        }
    }

    /// Points the monitor at a fixture tree instead of the live kernel.
    /// Test-only in practice; mirrors `PsiMonitor::with_cgroup_root`.
    pub fn with_cgroup_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.root = root.into();
        self
    }

    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Bounds the scan loop so it terminates. Only useful for tests.
    pub fn with_max_iterations(mut self, iterations: u64) -> Self {
        self.max_iterations = Some(iterations);
        self
    }

    /// Quiet period between repeat warnings for the same cgroup+verdict.
    /// `Duration::ZERO` warns on every occurrence (useful for tests).
    pub fn with_warn_cooldown(mut self, cooldown: Duration) -> Self {
        self.warn_cooldown = cooldown;
        self
    }

    /// Tells the monitor a Kubernetes context exists on this host. `PsiMonitor`
    /// then owns kubepods pressure, so this monitor excludes aggregate
    /// cgroups whose hierarchical counters include kubepods stalls (e.g. the
    /// root cgroup) instead of reporting the same stall twice.
    pub fn with_kubernetes(mut self, exists: bool) -> Self {
        self.exclude_kubepods_ancestors = exists;
        self
    }

    /// Records stall findings as `cgroup_pressure` incidents so they surface
    /// through `/incidents` and the MCP tools, not just the daemon logs.
    /// Takes `Option` to mirror `PsiMonitor`: the store may be unavailable
    /// (no DB path), in which case the monitor stays log-only.
    pub fn with_incident_store(mut self, store: Option<Arc<IncidentStore>>) -> Self {
        self.incident_store = store;
        self
    }

    /// Reporting gate for [`CgroupPressureMonitor::run`]: true the first time
    /// a cgroup reports a given verdict, and again once the cooldown has
    /// elapsed. A verdict *change* for the same cgroup always reports — that's
    /// new information, not a repeat. `tick()` itself is unthrottled so tests
    /// and future API consumers see every window's measurement.
    fn should_warn(&mut self, stall: &CgroupStall) -> bool {
        if self.warn_cooldown.is_zero() {
            return true;
        }
        let key = (stall.cgroup.clone(), stall.verdict);
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
            // cooldown — precisely the high-cardinality burst this cap exists
            // for. Evict the oldest entries instead, so the map stays bounded.
            // The victim is the entry closest to leaving cooldown anyway, so
            // it is the one whose early re-report costs least. This is an
            // O(n) scan, but only while at the cap, and only over 1024 entries.
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

    /// One scan: read current counters, diff against the previous scan, and
    /// return per-cgroup stall reports. The first call only establishes the
    /// baseline and returns an empty vec — deltas need two samples.
    pub fn tick(&mut self) -> Vec<CgroupStall> {
        let now = Instant::now();
        let dirs = find_cgroup_dirs(&self.root, self.max_depth, self.exclude_kubepods_ancestors);
        debug!("[cgroup-pressure] scanning {} cgroups", dirs.len());

        let mut stalls = Vec::new();
        // `None` on the very first scan: no previous sample exists yet, so
        // this round only establishes baselines.
        let window_secs = self
            .previous_at
            .map(|prev_at| now.duration_since(prev_at).as_secs_f64().max(1e-9));

        let mut seen = HashSet::new();
        for (rel, dir) in &dirs {
            seen.insert(rel.clone());
            let cur = read_cgroup_totals(dir);
            match self.previous.entry(rel.clone()) {
                Entry::Vacant(slot) => {
                    // A cgroup new since the previous scan has no baseline;
                    // establish it rather than diffing against nothing.
                    slot.insert(cur);
                }
                Entry::Occupied(mut slot) => {
                    let prev = slot.get().clone();
                    let Some(ws) = window_secs else {
                        continue;
                    };
                    if is_recreated(&prev, &cur) {
                        // Destroyed-and-recreated cgroup (e.g. a restarted
                        // systemd unit): the name survived but the instance
                        // didn't. Replace the baseline wholesale instead of
                        // diffing or merging across instances.
                        debug!("[cgroup-pressure] {rel} recreated; re-baselining");
                        slot.insert(cur);
                        continue;
                    }
                    // A counter unreadable on either side yields no delta for
                    // that counter rather than a fabricated one; it counts as
                    // no evidence (0) for classification this window.
                    let delta_us = |c: Option<u64>, p: Option<u64>| match (c, p) {
                        (Some(c), Some(p)) => Some(c.saturating_sub(p)),
                        _ => None,
                    };
                    let pct =
                        |d: Option<u64>| d.map(|d| d as f64 / 1e6 / ws * 100.0).unwrap_or(0.0);
                    let cpu_stall_pct = pct(delta_us(cur.cpu_some_total, prev.cpu_some_total));
                    let cpu_full_pct = pct(delta_us(cur.cpu_full_total, prev.cpu_full_total));
                    let mem_stall_pct = pct(delta_us(cur.mem_some_total, prev.mem_some_total));
                    let io_stall_pct = pct(delta_us(cur.io_some_total, prev.io_some_total));
                    let throttled_secs = delta_us(cur.throttled_usec, prev.throttled_usec)
                        .map(|d| d as f64 / 1e6)
                        .unwrap_or(0.0);
                    let mem_high_events = delta_us(cur.mem_high, prev.mem_high).unwrap_or(0);
                    let oom_kills = delta_us(cur.oom_kill, prev.oom_kill).unwrap_or(0);
                    let verdict = classify(
                        cpu_stall_pct,
                        throttled_secs,
                        mem_stall_pct,
                        io_stall_pct,
                        oom_kills,
                    );
                    if verdict.actionable() {
                        stalls.push(CgroupStall {
                            cgroup: rel.clone(),
                            cpu_stall_pct,
                            cpu_full_pct,
                            mem_stall_pct,
                            io_stall_pct,
                            throttled_secs,
                            mem_high_events,
                            oom_kills,
                            verdict,
                        });
                    }
                    // Adopt the new readings, except counters that were
                    // unreadable this scan: they keep their previous value so
                    // a transient failure doesn't poison the next delta.
                    slot.get_mut().merge(cur);
                }
            }
        }
        // Drop state for cgroups that vanished so the map doesn't grow
        // unbounded on hosts with churny slices.
        self.previous.retain(|k, _| seen.contains(k));

        self.previous_at = Some(now);
        stalls.sort_by(|a, b| {
            b.cpu_stall_pct
                .partial_cmp(&a.cpu_stall_pct)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        stalls
    }

    pub async fn run(mut self) {
        info!("[cgroup-pressure] starting generic cgroup pressure monitor");
        let mut iterations = 0u64;
        loop {
            let stalls = self.tick();
            self.handle_stalls(&stalls).await;
            iterations += 1;
            if let Some(max) = self.max_iterations
                && iterations >= max
            {
                break;
            }
            sleep(self.interval).await;
        }
    }

    /// Reports one scan's actionable findings: log the warning and, when an
    /// incident store is configured, record it. Both are gated on
    /// `should_warn`, so the 15-minute cooldown dedups incident rows exactly
    /// like it dedups log lines — every logged warning has a matching
    /// incident, and a verdict flip is new information in both places.
    async fn handle_stalls(&mut self, stalls: &[CgroupStall]) {
        for stall in stalls {
            if self.should_warn(stall) {
                report(stall);
                self.record_incident(stall).await;
            }
        }
    }

    /// Best-effort: a failing store must not break the monitoring loop.
    async fn record_incident(&self, stall: &CgroupStall) {
        let Some(store) = &self.incident_store else {
            return;
        };
        let incident = incident_from_stall(stall);
        match store.insert(&incident).await {
            Ok(id) => debug!(
                "[cgroup-pressure] recorded incident #{id} for {}",
                stall.cgroup
            ),
            Err(e) => warn!(
                "[cgroup-pressure] failed to record incident for {}: {e}",
                stall.cgroup
            ),
        }
    }
}

/// Builds the `cgroup_pressure` incident row for one stall finding.
///
/// Field mapping, kept honest about what this monitor measures:
/// * `psi_cpu` / `psi_memory` carry the cgroup's own stall percentages — the
///   triggering readings, and what `linnix_recent_incidents` shows.
/// * `cpu_percent` / `load_avg` are host-level fields this monitor doesn't
///   sample, so they're zero/empty; the per-cgroup truth lives in
///   `system_snapshot`.
fn incident_from_stall(stall: &CgroupStall) -> Incident {
    let snapshot = serde_json::json!({
        "cgroup": stall.cgroup,
        "verdict": format!("{:?}", stall.verdict),
        "cpu_stall_pct": stall.cpu_stall_pct,
        "cpu_full_pct": stall.cpu_full_pct,
        "mem_stall_pct": stall.mem_stall_pct,
        "io_stall_pct": stall.io_stall_pct,
        "throttled_secs": stall.throttled_secs,
        "mem_high_events": stall.mem_high_events,
        "oom_kills": stall.oom_kills,
        // The percentages are measured kernel counters; the verdict is
        // inferred from their combination.
        "evidence": {
            "stall_percentages": "measured",
            "throttled_secs": "measured",
            "event_counts": "measured",
            "verdict": "inferred",
        },
    });
    Incident {
        id: None,
        timestamp: chrono::Utc::now().timestamp(),
        event_type: "cgroup_pressure".to_string(),
        psi_cpu: stall.cpu_stall_pct as f32,
        psi_memory: stall.mem_stall_pct as f32,
        cpu_percent: 0.0,
        load_avg: String::new(),
        action: "alert".to_string(),
        target_pid: None,
        target_name: Some(stall.cgroup.clone()),
        system_snapshot: serde_json::to_string(&snapshot).ok(),
        llm_analysis: None,
        llm_analyzed_at: None,
        investigation: None,
        recovery_time_ms: None,
        psi_after: None,
    }
}

/// One human- and agent-readable line per actionable finding. Verdicts are
/// `inferred` from counter combinations; the percentages themselves are
/// `measured` kernel counters.
fn report(stall: &CgroupStall) {
    match stall.verdict {
        StallVerdict::CpuContended => warn!(
            "[cgroup-pressure] {} CPU-stalled {:.0}% (full {:.0}%), IO-stalled {:.0}% with no throttling -- genuine CPU contention, likely a noisy neighbor or undersized CPU [inferred]",
            stall.cgroup, stall.cpu_stall_pct, stall.cpu_full_pct, stall.io_stall_pct
        ),
        StallVerdict::IoContended => warn!(
            "[cgroup-pressure] {} IO-stalled {:.0}% with no CPU stall -- storage contention (slow disk or noisy neighbor on the block device), not a CPU problem [inferred]",
            stall.cgroup, stall.io_stall_pct
        ),
        StallVerdict::Throttled => warn!(
            "[cgroup-pressure] {} throttled {:.1}s by cpu.max with only {:.0}% CPU stall -- the CPU limit itself is the bottleneck, not contention [inferred]",
            stall.cgroup, stall.throttled_secs, stall.cpu_stall_pct
        ),
        StallVerdict::ThrottledAndContended => warn!(
            "[cgroup-pressure] {} throttled {:.1}s by cpu.max with {:.0}% CPU stall / {:.0}% IO stall -- capped and still contending for what's left [inferred]",
            stall.cgroup, stall.throttled_secs, stall.cpu_stall_pct, stall.io_stall_pct
        ),
        StallVerdict::MemoryPressure => warn!(
            "[cgroup-pressure] {} memory-stalled {:.0}% of window ({} memory.high events) [measured]",
            stall.cgroup, stall.mem_stall_pct, stall.mem_high_events
        ),
        StallVerdict::OomKill => warn!(
            "[cgroup-pressure] {} OOM-killed {} process(es) this window [measured]",
            stall.cgroup, stall.oom_kills
        ),
        StallVerdict::Healthy => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Builds a fake cgroup tree:
    ///   root/
    ///     cpu.pressure, memory.pressure, io.pressure, cpu.stat, memory.events
    ///     system.slice/nginx.service/ (same files)
    ///     kubepods.slice/.../ (must be skipped)
    fn fixture_tree() -> TempDir {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        write_cgroup(root, 1_000_000, 0, 0, 0, 0, 0, 0);
        let svc = root.join("system.slice/nginx.service");
        fs::create_dir_all(&svc).unwrap();
        write_cgroup(&svc, 2_000_000, 100_000, 0, 0, 0, 0, 0);
        let pod = root.join("kubepods.slice/kubepods-besteffort.slice/payload.scope");
        fs::create_dir_all(&pod).unwrap();
        write_cgroup(&pod, 9_000_000, 0, 0, 0, 0, 0, 0);
        tmp
    }

    #[allow(clippy::too_many_arguments)]
    fn write_cgroup(
        dir: &Path,
        cpu_some: u64,
        cpu_full: u64,
        mem_some: u64,
        io_some: u64,
        throttled_usec: u64,
        mem_high: u64,
        oom_kill: u64,
    ) {
        fs::write(
            dir.join("cpu.pressure"),
            format!("some avg10=0.00 avg60=0.00 avg300=0.00 total={cpu_some}\nfull avg10=0.00 avg60=0.00 avg300=0.00 total={cpu_full}\n"),
        )
        .unwrap();
        fs::write(
            dir.join("memory.pressure"),
            format!("some avg10=0.00 avg60=0.00 avg300=0.00 total={mem_some}\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"),
        )
        .unwrap();
        fs::write(
            dir.join("io.pressure"),
            format!("some avg10=0.00 avg60=0.00 avg300=0.00 total={io_some}\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"),
        )
        .unwrap();
        fs::write(
            dir.join("cpu.stat"),
            format!("usage_usec 1000\nuser_usec 800\nsystem_usec 200\nnr_periods 10\nnr_throttled 2\nthrottled_usec {throttled_usec}\n"),
        )
        .unwrap();
        fs::write(
            dir.join("memory.events"),
            format!("low 0\nhigh {mem_high}\nmax 0\noom 0\noom_kill {oom_kill}\n"),
        )
        .unwrap();
    }

    #[test]
    fn skips_kubepods_and_reads_totals() {
        let tmp = fixture_tree();
        let dirs = find_cgroup_dirs(tmp.path(), 5, false);
        let names: Vec<_> = dirs.iter().map(|(r, _)| r.as_str()).collect();
        assert!(names.contains(&"/"), "root cgroup missing: {names:?}");
        assert!(
            names.contains(&"system.slice/nginx.service"),
            "slice missing: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("kubepods")),
            "kubepods must be skipped: {names:?}"
        );

        let totals = read_cgroup_totals(&tmp.path().join("system.slice/nginx.service"));
        assert_eq!(totals.cpu_some_total, Some(2_000_000));
        assert_eq!(totals.cpu_full_total, Some(100_000));
    }

    #[test]
    fn first_tick_establishes_baseline() {
        let tmp = fixture_tree();
        let mut mon = CgroupPressureMonitor::new(Duration::from_secs(2))
            .with_cgroup_root(tmp.path())
            .with_max_depth(5);
        assert!(mon.tick().is_empty(), "first tick must be baseline-only");
    }

    #[test]
    fn detects_cpu_contention_from_total_deltas() {
        let tmp = fixture_tree();
        let mut mon = CgroupPressureMonitor::new(Duration::from_secs(2))
            .with_cgroup_root(tmp.path())
            .with_max_depth(5);
        mon.tick(); // baseline
        // Simulate 10s at 90% CPU stall on nginx.service: +9_000_000us.
        std::thread::sleep(Duration::from_millis(50));
        write_cgroup(
            &tmp.path().join("system.slice/nginx.service"),
            2_000_000 + 9_000_000,
            100_000,
            0,
            0,
            0,
            0,
            0,
        );
        let stalls = mon.tick();
        let nginx = stalls
            .iter()
            .find(|s| s.cgroup == "system.slice/nginx.service")
            .expect("nginx.service should be reported");
        // 9s of stall over a ~50ms+ window clamps well above the threshold;
        // assert the verdict and that the percentage is sane, not the exact
        // wall-clock ratio.
        assert_eq!(nginx.verdict, StallVerdict::CpuContended);
        assert!(nginx.cpu_stall_pct >= CONTENDED_STALL_PCT);
    }

    #[test]
    fn throttling_without_pressure_is_limit_not_contention() {
        let tmp = fixture_tree();
        let mut mon = CgroupPressureMonitor::new(Duration::from_secs(2))
            .with_cgroup_root(tmp.path())
            .with_max_depth(5);
        mon.tick(); // baseline
        std::thread::sleep(Duration::from_millis(50));
        // +2s throttled, no additional stall.
        write_cgroup(
            &tmp.path().join("system.slice/nginx.service"),
            2_000_000,
            100_000,
            0,
            0,
            2_000_000,
            0,
            0,
        );
        let stalls = mon.tick();
        let nginx = stalls
            .iter()
            .find(|s| s.cgroup == "system.slice/nginx.service")
            .expect("nginx.service should be reported");
        assert_eq!(nginx.verdict, StallVerdict::Throttled);
        assert!(nginx.throttled_secs >= THROTTLED_SECS);
    }

    #[test]
    fn oom_kill_is_measured() {
        let tmp = fixture_tree();
        let mut mon = CgroupPressureMonitor::new(Duration::from_secs(2))
            .with_cgroup_root(tmp.path())
            .with_max_depth(5);
        mon.tick(); // baseline
        std::thread::sleep(Duration::from_millis(50));
        write_cgroup(
            &tmp.path().join("system.slice/nginx.service"),
            2_000_000,
            100_000,
            0,
            0,
            0,
            0,
            3,
        );
        let stalls = mon.tick();
        let nginx = stalls
            .iter()
            .find(|s| s.cgroup == "system.slice/nginx.service")
            .expect("nginx.service should be reported");
        assert_eq!(nginx.verdict, StallVerdict::OomKill);
        assert_eq!(nginx.oom_kills, 3);
    }

    #[test]
    fn healthy_cgroups_are_silent() {
        let tmp = fixture_tree();
        let mut mon = CgroupPressureMonitor::new(Duration::from_secs(2))
            .with_cgroup_root(tmp.path())
            .with_max_depth(5);
        mon.tick(); // baseline
        std::thread::sleep(Duration::from_millis(50));
        // Rewrite identical counters: no deltas.
        write_cgroup(
            &tmp.path().join("system.slice/nginx.service"),
            2_000_000,
            100_000,
            0,
            0,
            0,
            0,
            0,
        );
        assert!(mon.tick().is_empty(), "no deltas means no reports");
    }

    #[test]
    fn missing_files_are_tolerated() {
        let tmp = TempDir::new().unwrap();
        // A cgroup dir with cpu.pressure but nothing else.
        fs::write(
            tmp.path().join("cpu.pressure"),
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=5000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        )
        .unwrap();
        let totals = read_cgroup_totals(tmp.path());
        assert_eq!(totals.cpu_some_total, Some(5000));
        // Absent files are None, never zero: zero would poison the baseline.
        assert_eq!(totals.throttled_usec, None);
        assert_eq!(totals.oom_kill, None);
    }

    #[test]
    fn classify_matrix() {
        assert_eq!(classify(50.0, 0.0, 0.0, 0.0, 0), StallVerdict::CpuContended);
        assert_eq!(classify(5.0, 2.0, 0.0, 0.0, 0), StallVerdict::Throttled);
        assert_eq!(
            classify(50.0, 2.0, 0.0, 0.0, 0),
            StallVerdict::ThrottledAndContended
        );
        assert_eq!(
            classify(0.0, 0.0, 30.0, 0.0, 0),
            StallVerdict::MemoryPressure
        );
        assert_eq!(classify(0.0, 0.0, 0.0, 0.0, 1), StallVerdict::OomKill);
        assert_eq!(classify(1.0, 0.0, 0.0, 0.0, 0), StallVerdict::Healthy);
        // Throttled but with real pressure too: both, not just throttled.
        assert_eq!(
            classify(15.0, 2.0, 0.0, 0.0, 0),
            StallVerdict::ThrottledAndContended
        );
        // IO-only stall gets its own verdict: diagnosing storage contention
        // as "CPU contention, check for a noisy neighbor" fixes the wrong
        // resource.
        assert_eq!(classify(0.0, 0.0, 0.0, 50.0, 0), StallVerdict::IoContended);
        // CPU contention keeps the CPU verdict when IO also stalls; the
        // report still carries the IO number, so nothing is hidden.
        assert_eq!(
            classify(50.0, 0.0, 0.0, 50.0, 0),
            StallVerdict::CpuContended
        );
    }

    #[test]
    fn recreation_detection() {
        let base = CgroupTotals {
            ino: 42,
            cpu_some_total: Some(100),
            ..Default::default()
        };
        // Same instance, counters advancing: not recreated.
        let advanced = CgroupTotals {
            ino: 42,
            cpu_some_total: Some(200),
            ..Default::default()
        };
        assert!(!is_recreated(&base, &advanced));
        // New inode: recreated even with plausible-looking counters.
        let new_ino = CgroupTotals {
            ino: 43,
            cpu_some_total: Some(200),
            ..Default::default()
        };
        assert!(is_recreated(&base, &new_ino));
        // Same inode but a cumulative counter moved backwards: recreation.
        let regressed = CgroupTotals {
            ino: 42,
            cpu_some_total: Some(50),
            ..Default::default()
        };
        assert!(is_recreated(&base, &regressed));
        // Missing readings are not regressions: a transiently unreadable
        // file must not look like a restart.
        let missing = CgroupTotals {
            ino: 42,
            cpu_some_total: None,
            ..Default::default()
        };
        assert!(!is_recreated(&base, &missing));
        // Identity unknown on both sides (metadata read failed): the
        // regression check is the backstop, and it still works.
        let unknown_ino = CgroupTotals {
            ino: 0,
            cpu_some_total: Some(50),
            ..Default::default()
        };
        let unknown_base = CgroupTotals {
            ino: 0,
            cpu_some_total: Some(100),
            ..Default::default()
        };
        assert!(is_recreated(&unknown_base, &unknown_ino));
    }

    #[test]
    fn restarted_cgroup_rebaselines_instead_of_diffing_stale_counters() {
        let tmp = fixture_tree();
        let mut mon = CgroupPressureMonitor::new(Duration::from_secs(2))
            .with_cgroup_root(tmp.path())
            .with_max_depth(5);
        mon.tick(); // baseline
        // Simulate a unit restart: the cgroup dir is destroyed and recreated
        // (new inode) with fresh low counters, then stalls hard in the window.
        // Diffing 9M against the dead instance's 2M would report Contended
        // with an understated delta; the correct behavior is to adopt the new
        // baseline silently this round.
        let svc = tmp.path().join("system.slice/nginx.service");
        fs::remove_dir_all(&svc).unwrap();
        fs::create_dir_all(&svc).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        write_cgroup(&svc, 9_000_000, 0, 0, 0, 0, 0, 0);
        let stalls = mon.tick();
        assert!(
            stalls
                .iter()
                .all(|s| s.cgroup != "system.slice/nginx.service"),
            "restarted cgroup must re-baseline, not diff stale counters: {stalls:?}"
        );
        // The next window has a real baseline for the new instance, so
        // reporting recovers on its own.
        std::thread::sleep(Duration::from_millis(50));
        write_cgroup(&svc, 18_000_000, 0, 0, 0, 0, 0, 0);
        let stalls = mon.tick();
        let nginx = stalls
            .iter()
            .find(|s| s.cgroup == "system.slice/nginx.service")
            .expect("recovered monitor should report the new instance stalling");
        assert_eq!(nginx.verdict, StallVerdict::CpuContended);
    }

    fn contended_stall(cgroup: &str) -> CgroupStall {
        CgroupStall {
            cgroup: cgroup.to_string(),
            cpu_stall_pct: 90.0,
            cpu_full_pct: 10.0,
            mem_stall_pct: 0.0,
            io_stall_pct: 0.0,
            throttled_secs: 0.0,
            mem_high_events: 0,
            oom_kills: 0,
            verdict: StallVerdict::CpuContended,
        }
    }

    #[test]
    fn warn_cooldown_dedups_repeat_verdicts() {
        let mut mon = CgroupPressureMonitor::new(Duration::from_secs(2));
        let stall = contended_stall("system.slice/nginx.service");
        assert!(mon.should_warn(&stall), "first occurrence must warn");
        assert!(
            !mon.should_warn(&stall),
            "immediate repeat must be cooled down"
        );
        // A verdict change for the same cgroup is new information, not a repeat.
        let flipped = CgroupStall {
            verdict: StallVerdict::ThrottledAndContended,
            ..stall.clone()
        };
        assert!(mon.should_warn(&flipped));
        // A different cgroup is unaffected by the first one's cooldown.
        assert!(mon.should_warn(&contended_stall("user.slice/app.service")));
    }

    #[test]
    fn warn_cooldown_expires() {
        let mut mon = CgroupPressureMonitor::new(Duration::from_secs(2))
            .with_warn_cooldown(Duration::from_millis(30));
        let stall = contended_stall("system.slice/nginx.service");
        assert!(mon.should_warn(&stall));
        assert!(!mon.should_warn(&stall));
        std::thread::sleep(Duration::from_millis(60));
        assert!(mon.should_warn(&stall), "cooldown must expire");
    }

    #[test]
    fn zero_warn_cooldown_warns_every_time() {
        let mut mon =
            CgroupPressureMonitor::new(Duration::from_secs(2)).with_warn_cooldown(Duration::ZERO);
        let stall = contended_stall("system.slice/nginx.service");
        assert!(mon.should_warn(&stall));
        assert!(mon.should_warn(&stall));
    }

    #[test]
    fn warn_cooldown_map_is_bounded() {
        // Fill the map past the cap with distinct cgroups, all inside the
        // cooldown: expiry alone frees nothing, so oldest-eviction must keep
        // the map bounded.
        let mut mon = CgroupPressureMonitor::new(Duration::from_secs(2))
            .with_warn_cooldown(Duration::from_secs(3600));
        for i in 0..(MAX_COOLDOWN_ENTRIES + 50) {
            let stall = contended_stall(&format!("system.slice/svc-{i}.service"));
            assert!(mon.should_warn(&stall), "new cgroup must warn");
        }
        assert!(
            mon.last_warned.len() <= MAX_COOLDOWN_ENTRIES,
            "cooldown map grew past its cap: {}",
            mon.last_warned.len()
        );
    }

    #[test]
    fn transiently_unreadable_counters_dont_fabricate_events() {
        // A file that is unreadable for one scan (teardown race) but readable
        // again on the next must not poison the baseline: the baseline keeps
        // the last good value, so the next delta is computed against reality
        // instead of zero.
        let tmp = fixture_tree();
        let svc = tmp.path().join("system.slice/nginx.service");
        // Historical OOM kills already accounted for in the baseline.
        write_cgroup(&svc, 2_000_000, 100_000, 0, 0, 0, 0, 3);
        let mut mon = CgroupPressureMonitor::new(Duration::from_secs(2))
            .with_cgroup_root(tmp.path())
            .with_max_depth(5);
        assert!(mon.tick().is_empty());
        // Transient: memory.events unreadable this scan.
        std::fs::remove_file(svc.join("memory.events")).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let stalls = mon.tick();
        assert!(
            stalls
                .iter()
                .all(|s| s.cgroup != "system.slice/nginx.service"),
            "no signal should be fabricated from missing readings: {stalls:?}"
        );
        // File back, counters unchanged: the 3 historical kills must NOT be
        // reported as new. (Storing zero for the missing scan would have made
        // the baseline 0 and fabricated an OomKill verdict here.)
        write_cgroup(&svc, 2_000_000, 100_000, 0, 0, 0, 0, 3);
        std::thread::sleep(Duration::from_millis(50));
        let stalls = mon.tick();
        assert!(
            stalls
                .iter()
                .all(|s| s.cgroup != "system.slice/nginx.service"),
            "historical oom_kills must not be reported as new: {stalls:?}"
        );
        // And a genuinely new kill on top is still caught.
        write_cgroup(&svc, 2_000_000, 100_000, 0, 0, 0, 0, 4);
        std::thread::sleep(Duration::from_millis(50));
        let stalls = mon.tick();
        let nginx = stalls
            .iter()
            .find(|s| s.cgroup == "system.slice/nginx.service")
            .expect("new oom_kill must be reported");
        assert_eq!(nginx.verdict, StallVerdict::OomKill);
        assert_eq!(nginx.oom_kills, 1);
    }

    #[test]
    fn kubernetes_mode_skips_aggregates_containing_kubepods() {
        // cgroup v2 pressure is hierarchical: the root sample includes stalls
        // from every kubepods descendant. On Kubernetes hosts PsiMonitor owns
        // pod pressure, so this monitor must not report the contaminated
        // aggregate on top of it.
        let tmp = fixture_tree();
        for k8s in [false, true] {
            let mut mon = CgroupPressureMonitor::new(Duration::from_secs(2))
                .with_cgroup_root(tmp.path())
                .with_max_depth(5)
                .with_kubernetes(k8s);
            assert!(mon.tick().is_empty());
            std::thread::sleep(Duration::from_millis(50));
            // The root stalls hard (its counter includes kubepods pressure).
            write_cgroup(tmp.path(), 1_000_000 + 9_000_000, 0, 0, 0, 0, 0, 0);
            let stalls = mon.tick();
            let root_reported = stalls.iter().any(|s| s.cgroup == "/");
            assert_eq!(
                root_reported, !k8s,
                "k8s={k8s}: the root aggregate must be omitted exactly when \
                 PsiMonitor owns the kubepods pressure it contains"
            );
        }
    }

    #[test]
    fn incident_from_stall_maps_fields() {
        let stall = CgroupStall {
            cgroup: "system.slice/nginx.service".to_string(),
            cpu_stall_pct: 87.3,
            cpu_full_pct: 12.1,
            mem_stall_pct: 0.0,
            io_stall_pct: 5.2,
            throttled_secs: 0.0,
            mem_high_events: 0,
            oom_kills: 0,
            verdict: StallVerdict::CpuContended,
        };
        let incident = incident_from_stall(&stall);
        assert_eq!(incident.event_type, "cgroup_pressure");
        assert_eq!(incident.action, "alert");
        assert_eq!(
            incident.target_name.as_deref(),
            Some("system.slice/nginx.service")
        );
        assert_eq!(incident.target_pid, None);
        // The triggering readings ride the psi scalars.
        assert!((incident.psi_cpu - 87.3).abs() < 0.01);
        let snapshot: serde_json::Value =
            serde_json::from_str(incident.system_snapshot.as_deref().unwrap()).unwrap();
        assert_eq!(snapshot["cgroup"], "system.slice/nginx.service");
        assert_eq!(snapshot["verdict"], "CpuContended");
        assert!((snapshot["cpu_stall_pct"].as_f64().unwrap() - 87.3).abs() < 1e-9);
        assert_eq!(snapshot["evidence"]["verdict"], "inferred");
        assert_eq!(snapshot["evidence"]["stall_percentages"], "measured");
    }

    #[tokio::test]
    async fn contended_cgroup_is_recorded_as_incident() {
        let tmp = fixture_tree();
        let db_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            IncidentStore::new(db_dir.path().join("incidents.db"))
                .await
                .unwrap(),
        );
        let mut mon = CgroupPressureMonitor::new(Duration::from_secs(2))
            .with_cgroup_root(tmp.path())
            .with_max_depth(5)
            .with_incident_store(Some(Arc::clone(&store)));
        assert!(mon.tick().is_empty());
        // nginx stalls hard on CPU.
        write_cgroup(
            &tmp.path().join("system.slice/nginx.service"),
            2_000_000 + 9_000_000,
            100_000,
            0,
            0,
            0,
            0,
            0,
        );
        std::thread::sleep(Duration::from_millis(50));
        let stalls = mon.tick();
        assert!(!stalls.is_empty());
        mon.handle_stalls(&stalls).await;

        let incidents = store
            .recent_filtered(10, Some("cgroup_pressure"), None)
            .await
            .unwrap();
        assert_eq!(incidents.len(), 1, "one stall finding, one incident");
        let incident = &incidents[0];
        assert_eq!(
            incident.target_name.as_deref(),
            Some("system.slice/nginx.service")
        );
        let snapshot: serde_json::Value =
            serde_json::from_str(incident.system_snapshot.as_deref().unwrap()).unwrap();
        assert_eq!(snapshot["verdict"], "CpuContended");

        // The cooldown gates recording like it gates logging: handling the
        // same stalls again must not write a second row.
        mon.handle_stalls(&stalls).await;
        let incidents = store
            .recent_filtered(10, Some("cgroup_pressure"), None)
            .await
            .unwrap();
        assert_eq!(
            incidents.len(),
            1,
            "repeat findings inside the cooldown must not duplicate incidents"
        );
    }

    #[tokio::test]
    async fn monitor_without_store_stays_log_only() {
        // No incident store configured: handle_stalls must not fail, just log.
        let mut mon =
            CgroupPressureMonitor::new(Duration::from_secs(2)).with_warn_cooldown(Duration::ZERO);
        mon.handle_stalls(&[contended_stall("system.slice/nginx.service")])
            .await;
    }
}
