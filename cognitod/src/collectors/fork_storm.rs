//! Userspace fork-storm detector: no eBPF, no privileges beyond /proc.
//!
//! A fork storm — a runaway loop, a fork bomb, a supervisor respawning a
//! crashing child hundreds of times a second — is one of the few host-wide
//! failure modes visible *exactly* from userspace: the kernel keeps a
//! cumulative fork counter in `/proc/stat` (`processes`), so the system-wide
//! fork rate over a window is a measured number, not an estimate.
//!
//! This monitor runs at the spec's tier B (polling):
//!
//! * **Rate (measured):** `/proc/stat` `processes` is sampled every 0.5s and
//!   the rate is computed over a 10s sliding window. Warn at >= 15 forks/s,
//!   critical at >= 60 forks/s — the prototype-validated defaults from the
//!   userspace detector spec (D3). While the window is still filling
//!   (startup, re-baseline) the delta is normalized against the full
//!   window, so warm-up noise can't inflate into a storm verdict.
//! * **Attribution (inferred, best-effort):** while the measured rate is
//!   elevated, each poll diffs the PID set against the previous poll and
//!   attributes new PIDs to their parents. Children that live less than the
//!   poll interval are missed, so the named parent is a lower bound on the
//!   truth, never an assertion — the incident snapshot labels it `inferred`
//!   and says so. Tier A (proc connector, exact per-fork events) is the
//!   documented upgrade path; it needs a dedicated netlink event thread and
//!   `CONFIG_PROC_EVENTS`, so it is not wired here. The rate is the firing
//!   signal and it is exact at either tier.
//!
//! Two cost/honesty mechanisms:
//!
//! * The PID-set diff (~1-2% of a core at 300 pids every 0.5s) only runs
//!   while the measured rate is at least half the warn threshold. Idle hosts
//!   pay one file read per poll. The first active poll establishes the
//!   attribution baseline; births are counted from the next poll on.
//! * A regressing `processes` counter (wrap) re-baselines instead of
//!   fabricating a negative delta, and an unreadable `/proc/stat` skips the
//!   poll without poisoning the baseline.
//!
//! Findings become `fork_storm` incidents via the same store-backed dedup
//! discipline as the cgroup pressure monitor: the incident store — not the
//! bounded in-memory warn map — is the source of truth for what was already
//! persisted, so map eviction and daemon restarts cannot duplicate rows.

use log::{debug, info, warn};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::incidents::{Incident, IncidentStore};

/// Sliding window over which the fork rate is computed.
const WINDOW: Duration = Duration::from_secs(10);
/// Sustained fork rate at or above which a warning fires (prototype default).
const WARN_FORKS_PER_SEC: f64 = 15.0;
/// Sustained fork rate at or above which a critical fires (prototype default).
const CRIT_FORKS_PER_SEC: f64 = 60.0;
/// The PID-set diff only runs while the measured rate is at least this high:
/// the counter read is the cheap always-on signal, the /proc scan is the
/// expensive attribution signal.
const ATTRIBUTION_ACTIVATION_RATE: f64 = WARN_FORKS_PER_SEC / 2.0;
/// Default quiet period between repeat warnings for the same parent+verdict,
/// mirroring the cgroup pressure monitor.
const DEFAULT_WARN_COOLDOWN: Duration = Duration::from_secs(15 * 60);
/// Cap on the warn-cooldown map; oldest entries are evicted past this.
const MAX_COOLDOWN_ENTRIES: usize = 1024;

/// What the measured fork rate means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForkVerdict {
    Healthy,
    /// Sustained fork rate above the warn threshold: something is spawning
    /// processes far faster than normal operation.
    StormWarning,
    /// Sustained fork rate above the critical threshold: a runaway loop or
    /// fork bomb until proven otherwise.
    StormCritical,
}

impl ForkVerdict {
    /// `false` for `Healthy`; used to filter log/report noise.
    pub fn actionable(self) -> bool {
        !matches!(self, ForkVerdict::Healthy)
    }
}

/// One actionable fork-storm finding for a scan window.
#[derive(Debug, Clone)]
pub struct ForkStorm {
    /// Measured forks/second over the window (kernel counter delta).
    pub forks_per_sec: f64,
    /// Seconds the window actually covered.
    pub window_secs: f64,
    /// Forks counted in the window.
    pub window_forks: u64,
    /// Parent the most births were attributed to, if any were observed.
    pub parent_pid: Option<i32>,
    pub parent_comm: Option<String>,
    /// Births attributed to that parent inside the window.
    pub parent_forks: u64,
    pub verdict: ForkVerdict,
}

impl ForkStorm {
    /// Stable identity for cooldown and incident-dedup keys. PIDs recycle
    /// fast during a storm; the command name is the identity that survives.
    fn parent_label(&self) -> String {
        self.parent_comm
            .clone()
            .unwrap_or_else(|| "unknown".to_string())
    }
}

fn classify(forks_per_sec: f64) -> ForkVerdict {
    if forks_per_sec >= CRIT_FORKS_PER_SEC {
        ForkVerdict::StormCritical
    } else if forks_per_sec >= WARN_FORKS_PER_SEC {
        ForkVerdict::StormWarning
    } else {
        ForkVerdict::Healthy
    }
}

/// Reads the cumulative `processes` counter from `<proc_root>/stat`.
/// `None` when the file is missing or unparseable — absence is not zero.
fn read_fork_counter(proc_root: &Path) -> Option<u64> {
    let content = std::fs::read_to_string(proc_root.join("stat")).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("processes ") {
            return rest.split_whitespace().next()?.parse::<u64>().ok();
        }
    }
    None
}

/// Reads a PID's parent from `<proc_root>/<pid>/stat`. The comm field may
/// itself contain spaces or parens, so the parent is parsed from after the
/// *last* `)`, exactly like the Python prototype.
fn read_ppid(proc_root: &Path, pid: i32) -> Option<i32> {
    let content = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    let after_comm = content.rsplit(')').next()?;
    after_comm.split_whitespace().nth(1)?.parse::<i32>().ok()
}

fn read_comm(proc_root: &Path, pid: i32) -> Option<String> {
    std::fs::read_to_string(proc_root.join(pid.to_string()).join("comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Snapshot of `{pid: ppid}` for attribution diffing. Best-effort: PIDs that
/// vanish mid-scan are skipped, not fatal.
fn snapshot_pids(proc_root: &Path) -> HashMap<i32, i32> {
    let mut out = HashMap::new();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid_str) = name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<i32>() else {
            continue;
        };
        if let Some(ppid) = read_ppid(proc_root, pid) {
            out.insert(pid, ppid);
        }
    }
    out
}

/// Stateful fork-storm monitor. Keeps the previous scans' counter samples so
/// each [`ForkStormMonitor::tick`] computes a windowed rate.
pub struct ForkStormMonitor {
    proc_root: PathBuf,
    interval: Duration,
    /// `(sampled_at, processes_counter)` within the sliding window.
    samples: VecDeque<(Instant, u64)>,
    /// `(observed_at, parent_pid)` births inside the sliding window.
    births: VecDeque<(Instant, i32)>,
    /// Previous poll's PID set, for birth diffing. `None` while the rate is
    /// quiet — the attribution scan is dormant then.
    prev_pids: Option<HashMap<i32, i32>>,
    warn_cooldown: Duration,
    max_iterations: Option<u64>,
    /// When each parent+verdict was last warned about. Keyed per
    /// parent+verdict, mirroring the cgroup pressure monitor: a verdict
    /// *change* is new information, not a repeat.
    last_warned: HashMap<(String, ForkVerdict), Instant>,
    /// Whether the last incident-record attempt failed. A failing store
    /// during a storm would otherwise log every 500 ms poll; the first
    /// failure logs at warn level and repeats stay at debug until a
    /// record succeeds again.
    record_unhealthy: bool,
    /// Where storm findings are recorded so they are visible through the API
    /// and MCP tools, not just the daemon logs. `None` keeps the monitor
    /// log-only.
    incident_store: Option<Arc<IncidentStore>>,
}

impl ForkStormMonitor {
    pub fn new(interval: Duration) -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            interval,
            samples: VecDeque::new(),
            births: VecDeque::new(),
            prev_pids: None,
            warn_cooldown: DEFAULT_WARN_COOLDOWN,
            max_iterations: None,
            last_warned: HashMap::new(),
            record_unhealthy: false,
            incident_store: None,
        }
    }

    /// Points the monitor at a fixture tree instead of the live `/proc`.
    /// Test-only in practice; mirrors `CgroupPressureMonitor::with_cgroup_root`.
    pub fn with_proc_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.proc_root = root.into();
        self
    }

    /// Bounds the scan loop so it terminates. Only useful for tests.
    pub fn with_max_iterations(mut self, iterations: u64) -> Self {
        self.max_iterations = Some(iterations);
        self
    }

    /// Quiet period between repeat warnings for the same parent+verdict.
    /// `Duration::ZERO` warns on every occurrence (useful for tests).
    pub fn with_warn_cooldown(mut self, cooldown: Duration) -> Self {
        self.warn_cooldown = cooldown;
        self
    }

    /// Records storm findings as `fork_storm` incidents so they surface
    /// through `/incidents` and the MCP tools, not just the daemon logs.
    /// Takes `Option` to mirror the other monitors: the store may be
    /// unavailable (no DB path), in which case the monitor stays log-only.
    pub fn with_incident_store(mut self, store: Option<Arc<IncidentStore>>) -> Self {
        self.incident_store = store;
        self
    }

    /// Log-reporting gate for [`ForkStormMonitor::run`]: true the first time
    /// a parent reports a given verdict, and again once the cooldown has
    /// elapsed. A verdict *change* for the same parent always reports.
    /// This gates the log line only — incident recording is decided
    /// separately against the store (see `handle_burst`), so a failed
    /// insert is retried on the next scan instead of being swallowed by
    /// this cooldown. `tick()` itself is unthrottled so tests and future
    /// API consumers see every window's measurement.
    fn should_warn(&mut self, burst: &ForkStorm) -> bool {
        if self.warn_cooldown.is_zero() {
            return true;
        }
        let key = (burst.parent_label(), burst.verdict);
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
            // Mirrors the cgroup pressure monitor's cap discipline.
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

    /// `(rate, forks_in_window, window_secs)` from the samples inside the
    /// sliding window. `None` until at least two samples exist — the first
    /// poll only establishes the baseline.
    ///
    /// The rate is normalized against the full [`WINDOW`], not the shorter
    /// span the samples cover while the window is still filling (right
    /// after startup or a counter-regression re-baseline). Dividing a
    /// warm-up delta by its short span would inflate a handful of ordinary
    /// forks into a storm: eight forks in the first 500 ms are 0.8
    /// forks/s over the intended 10-second window, not 16. Normalizing
    /// underestimates during warm-up and converges to the true rate as the
    /// window fills — a real storm still trips the warn threshold within
    /// seconds, while warm-up noise never does.
    fn window_rate(&self) -> Option<(f64, u64, f64)> {
        let &(first_t, first_n) = self.samples.front()?;
        let &(last_t, last_n) = self.samples.back()?;
        // Distinct samples: `tick` always pushes a fresh `now`, but tests
        // drive `tick_at` directly and may reuse a timestamp.
        if self.samples.len() < 2 || last_t <= first_t {
            return None;
        }
        let window_forks = last_n.saturating_sub(first_n);
        let window_secs = WINDOW.as_secs_f64();
        Some((window_forks as f64 / window_secs, window_forks, window_secs))
    }

    /// Runs the PID-set diff while the measured rate is elevated, recording
    /// births against their parents. Dormant while the rate is quiet — the
    /// counter read is the cheap always-on signal.
    fn update_attribution(&mut self, now: Instant, rate: f64) {
        if rate < ATTRIBUTION_ACTIVATION_RATE {
            self.prev_pids = None;
            return;
        }
        let cur = snapshot_pids(&self.proc_root);
        match self.prev_pids.take() {
            Some(prev) => {
                for (pid, ppid) in &cur {
                    if !prev.contains_key(pid) {
                        self.births.push_back((now, *ppid));
                    }
                }
                self.prev_pids = Some(cur);
            }
            // First active poll: establish the baseline. Births are counted
            // from the next poll — this pass cannot tell new PIDs from
            // pre-existing ones.
            None => self.prev_pids = Some(cur),
        }
    }

    /// The parent with the most attributed births in the window, if any were
    /// observed. Best-effort by construction: see the module docs.
    fn top_parent(&self) -> Option<(i32, Option<String>, u64)> {
        let mut counts: HashMap<i32, u64> = HashMap::new();
        for &(_, ppid) in &self.births {
            *counts.entry(ppid).or_default() += 1;
        }
        let (ppid, n) = counts.into_iter().max_by_key(|&(_, n)| n)?;
        let comm = read_comm(&self.proc_root, ppid);
        Some((ppid, comm, n))
    }

    /// One poll: sample the fork counter, maintain the sliding windows, and
    /// return a finding when the measured rate is actionable. The first call
    /// only establishes the baseline and returns `None`.
    pub fn tick(&mut self) -> Option<ForkStorm> {
        self.tick_at(Instant::now())
    }

    fn tick_at(&mut self, now: Instant) -> Option<ForkStorm> {
        let Some(counter) = read_fork_counter(&self.proc_root) else {
            debug!("[fork-storm] couldn't read processes counter; skipping poll");
            return None;
        };
        // A regressing cumulative counter (wrap) re-baselines instead of
        // fabricating a negative delta.
        if self.samples.back().is_some_and(|&(_, last)| counter < last) {
            debug!("[fork-storm] processes counter regressed; re-baselining");
            self.samples.clear();
        }
        self.samples.push_back((now, counter));
        let cutoff = now.checked_sub(WINDOW).unwrap_or(now);
        while self.samples.front().is_some_and(|&(t, _)| t < cutoff) {
            self.samples.pop_front();
        }
        // Births are pruned every poll — not just while attribution is
        // active — so a quiet period can't leave stale births behind to be
        // misattributed to the next storm.
        while self.births.front().is_some_and(|&(t, _)| t < cutoff) {
            self.births.pop_front();
        }
        let (rate, window_forks, window_secs) = self.window_rate()?;
        self.update_attribution(now, rate);
        let verdict = classify(rate);
        if !verdict.actionable() {
            return None;
        }
        let (parent_pid, parent_comm, parent_forks) = match self.top_parent() {
            Some((pid, comm, n)) => (Some(pid), comm, n),
            None => (None, None, 0),
        };
        Some(ForkStorm {
            forks_per_sec: rate,
            window_secs,
            window_forks,
            parent_pid,
            parent_comm,
            parent_forks,
            verdict,
        })
    }

    pub async fn run(mut self) {
        info!("[fork-storm] starting fork storm monitor (polling tier)");
        let mut iterations = 0u64;
        loop {
            if let Some(burst) = self.tick() {
                self.handle_burst(&burst).await;
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
    /// Logging rides `should_warn`'s cooldown — a storm is one log line,
    /// not one per poll. Recording is gated only on the store itself,
    /// which is the source of truth for what was persisted: the log
    /// cooldown never suppresses a record attempt, so a transient insert
    /// failure is retried on the next scan instead of vanishing for the
    /// whole cooldown. A storm the store already has — because the bounded
    /// cooldown map evicted it, or a daemon restart cleared the map — is
    /// still logged above (the storm is real and ongoing) but is not
    /// recorded twice.
    async fn handle_burst(&mut self, burst: &ForkStorm) {
        if self.should_warn(burst) {
            report(burst);
        }
        let recorded = self.recently_recorded_keys().await;
        let key = (burst.parent_label(), format!("{:?}", burst.verdict));
        if recorded.contains(&key) {
            return;
        }
        self.record_incident(burst).await;
    }

    /// `(parent, verdict)` pairs already incidented within the cooldown
    /// window. Empty when no store is configured; fail-open when the store
    /// can't be read — a store that won't answer the dedup query probably
    /// won't take the insert either, and a duplicate row beats a silently
    /// dropped incident.
    async fn recently_recorded_keys(&self) -> HashSet<(String, String)> {
        let Some(store) = &self.incident_store else {
            return HashSet::new();
        };
        match store
            .recent_incident_keys("fork_storm", self.warn_cooldown.as_secs())
            .await
        {
            Ok(keys) => keys,
            Err(e) => {
                warn!("[fork-storm] couldn't check recent incidents: {e}");
                HashSet::new()
            }
        }
    }

    /// Best-effort: a failing store must not break the monitoring loop.
    /// The first failure logs at warn level; repeats stay at debug until a
    /// record succeeds, since `handle_burst` retries the insert on every
    /// scan while the storm continues.
    async fn record_incident(&mut self, burst: &ForkStorm) {
        let Some(store) = &self.incident_store else {
            return;
        };
        let incident = incident_from_burst(burst);
        match store.insert(&incident).await {
            Ok(id) => {
                debug!(
                    "[fork-storm] recorded incident #{id} for {}",
                    burst.parent_label()
                );
                self.record_unhealthy = false;
            }
            Err(e) => {
                if self.record_unhealthy {
                    debug!(
                        "[fork-storm] still failing to record incident for {}: {e}",
                        burst.parent_label()
                    );
                } else {
                    warn!(
                        "[fork-storm] failed to record incident for {}: {e}",
                        burst.parent_label()
                    );
                    self.record_unhealthy = true;
                }
            }
        }
    }
}

/// Builds the `fork_storm` incident row for one finding.
///
/// Field mapping, kept honest about what this monitor measures:
/// * `psi_cpu` / `psi_memory` / `cpu_percent` / `load_avg` are host-level
///   fields this monitor doesn't sample, so they're zero/empty; the
///   triggering reading is the fork rate, carried in `system_snapshot`.
/// * `target_pid` / `target_name` name the *inferred* parent — the snapshot's
///   evidence labels say exactly how much to trust that attribution.
fn incident_from_burst(burst: &ForkStorm) -> Incident {
    let snapshot = serde_json::json!({
        "forks_per_sec": burst.forks_per_sec,
        "window_secs": burst.window_secs,
        "window_forks": burst.window_forks,
        "parent_pid": burst.parent_pid,
        "parent_comm": burst.parent_comm,
        "parent_forks_in_window": burst.parent_forks,
        "source_tier": "polling",
        "verdict": format!("{:?}", burst.verdict),
        // The rate is a measured kernel counter; the offending parent is
        // inferred from PID-set diffs, which miss children that live less
        // than the poll interval.
        "evidence": {
            "fork_rate": "measured",
            "offending_parent": "inferred",
        },
    });
    Incident {
        id: None,
        timestamp: chrono::Utc::now().timestamp(),
        event_type: "fork_storm".to_string(),
        psi_cpu: 0.0,
        psi_memory: 0.0,
        cpu_percent: 0.0,
        load_avg: String::new(),
        action: "alert".to_string(),
        target_pid: burst.parent_pid,
        target_name: Some(burst.parent_label()),
        system_snapshot: serde_json::to_string(&snapshot).ok(),
        llm_analysis: None,
        llm_analyzed_at: None,
        investigation: None,
        recovery_time_ms: None,
        psi_after: None,
    }
}

/// One human- and agent-readable line per actionable finding. The rate is
/// `measured`; the named parent is `inferred` — the tags say which is which.
fn report(burst: &ForkStorm) {
    let parent = match (burst.parent_pid, burst.parent_comm.as_deref()) {
        (Some(pid), Some(comm)) => format!("pid={pid} ({comm})"),
        _ => "unknown parent".to_string(),
    };
    match burst.verdict {
        ForkVerdict::StormWarning => warn!(
            "[fork-storm] WARNING: {:.0} forks/sec over the last {:.0}s -- likely parent: {} ({} forks attributed this window) [rate measured, parent inferred]",
            burst.forks_per_sec, burst.window_secs, parent, burst.parent_forks
        ),
        ForkVerdict::StormCritical => warn!(
            "[fork-storm] CRITICAL: {:.0} forks/sec over the last {:.0}s -- likely parent: {} ({} forks attributed this window); possible runaway loop or fork bomb [rate measured, parent inferred]",
            burst.forks_per_sec, burst.window_secs, parent, burst.parent_forks
        ),
        ForkVerdict::Healthy => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// A fake `/proc` tree: `<dir>/stat` carries the `processes` counter and
    /// `<dir>/<pid>/{stat,comm}` fake processes for attribution tests.
    struct FakeProc {
        dir: TempDir,
    }

    impl FakeProc {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            let fake = Self { dir };
            fake.set_counter(0);
            fake
        }

        fn set_counter(&self, n: u64) {
            fs::write(
                self.dir.path().join("stat"),
                format!("cpu  100 0 100 1000 0 0 0 0 0 0\nprocesses {n}\nprocs_running 1\n"),
            )
            .unwrap();
        }

        fn remove_counter(&self) {
            fs::remove_file(self.dir.path().join("stat")).unwrap();
        }

        /// `pids` are `(pid, ppid, comm)`. Replaces any previous fake pids.
        fn set_pids(&self, pids: &[(i32, i32, &str)]) {
            for entry in fs::read_dir(self.dir.path()).unwrap().flatten() {
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|s| s.parse::<i32>().is_ok())
                {
                    fs::remove_dir_all(entry.path()).unwrap();
                }
            }
            for (pid, ppid, comm) in pids {
                let dir = self.dir.path().join(pid.to_string());
                fs::create_dir(&dir).unwrap();
                fs::write(
                    dir.join("stat"),
                    format!("{pid} ({comm}) S {ppid} 0 0 0 -1 4194304 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0\n"),
                )
                .unwrap();
                fs::write(dir.join("comm"), format!("{comm}\n")).unwrap();
            }
        }

        fn monitor(&self) -> ForkStormMonitor {
            ForkStormMonitor::new(Duration::from_millis(500)).with_proc_root(self.dir.path())
        }
    }

    #[test]
    fn first_tick_establishes_baseline() {
        let fake = FakeProc::new();
        fake.set_counter(1000);
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        assert!(
            mon.tick_at(t0).is_none(),
            "first tick must be baseline-only"
        );
        // Still no forks: healthy, no finding.
        fake.set_counter(1000);
        assert!(
            mon.tick_at(t0 + Duration::from_secs(10)).is_none(),
            "no new forks means no finding"
        );
    }

    #[test]
    fn classify_matrix() {
        assert_eq!(classify(0.0), ForkVerdict::Healthy);
        assert_eq!(classify(14.99), ForkVerdict::Healthy);
        assert_eq!(classify(15.0), ForkVerdict::StormWarning);
        assert_eq!(classify(59.99), ForkVerdict::StormWarning);
        assert_eq!(classify(60.0), ForkVerdict::StormCritical);
        assert_eq!(classify(10_000.0), ForkVerdict::StormCritical);
    }

    #[test]
    fn detects_warning_and_critical_rates() {
        let t0 = Instant::now();
        // 150 forks over 10s = 15/s -> warning.
        let fake = FakeProc::new();
        let mut mon = fake.monitor();
        assert!(mon.tick_at(t0).is_none());
        fake.set_counter(150);
        let burst = mon
            .tick_at(t0 + Duration::from_secs(10))
            .expect("15 forks/s must warn");
        assert_eq!(burst.verdict, ForkVerdict::StormWarning);
        assert!((burst.forks_per_sec - 15.0).abs() < 1e-9);
        assert_eq!(burst.window_forks, 150);

        // 600 forks over 10s = 60/s -> critical.
        let fake = FakeProc::new();
        let mut mon = fake.monitor();
        assert!(mon.tick_at(t0).is_none());
        fake.set_counter(600);
        let burst = mon
            .tick_at(t0 + Duration::from_secs(10))
            .expect("60 forks/s must be critical");
        assert_eq!(burst.verdict, ForkVerdict::StormCritical);
        assert!((burst.forks_per_sec - 60.0).abs() < 1e-9);
    }

    #[test]
    fn attributes_storm_to_top_parent() {
        let fake = FakeProc::new();
        fake.set_pids(&[(1, 0, "init"), (100, 1, "runaway.sh")]);
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        assert!(mon.tick_at(t0).is_none());
        // The first active poll establishes the attribution baseline; births
        // are counted from the next poll on.
        fake.set_counter(300);
        fake.set_pids(&[(1, 0, "init"), (100, 1, "runaway.sh"), (200, 100, "true")]);
        mon.tick_at(t0 + Duration::from_secs(5));
        // Storm: 600 forks; two more children of pid 100 appear.
        fake.set_counter(600);
        fake.set_pids(&[
            (1, 0, "init"),
            (100, 1, "runaway.sh"),
            (200, 100, "true"),
            (201, 100, "true"),
            (202, 100, "true"),
        ]);
        let burst = mon
            .tick_at(t0 + Duration::from_secs(10))
            .expect("storm must fire");
        assert_eq!(burst.verdict, ForkVerdict::StormCritical);
        assert_eq!(burst.parent_pid, Some(100));
        assert_eq!(burst.parent_comm.as_deref(), Some("runaway.sh"));
        assert_eq!(burst.parent_forks, 2);
    }

    #[test]
    fn unknown_parent_when_no_births_observed() {
        // Storm with no observable births (e.g. children died between polls):
        // the measured rate still fires, the parent is honestly unknown.
        let fake = FakeProc::new();
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        assert!(mon.tick_at(t0).is_none());
        fake.set_counter(600);
        let burst = mon
            .tick_at(t0 + Duration::from_secs(10))
            .expect("storm must fire on the rate alone");
        assert_eq!(burst.parent_pid, None);
        assert_eq!(burst.parent_label(), "unknown");
    }

    #[test]
    fn counter_regression_rebaselines() {
        let fake = FakeProc::new();
        fake.set_counter(5000);
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        assert!(mon.tick_at(t0).is_none());
        // Counter wrapped: must not fabricate a storm, just re-baseline.
        fake.set_counter(10);
        assert!(
            mon.tick_at(t0 + Duration::from_secs(10)).is_none(),
            "a regressing counter must re-baseline, not fire"
        );
        // The next window measures forward from the new baseline.
        fake.set_counter(610);
        let burst = mon
            .tick_at(t0 + Duration::from_secs(20))
            .expect("600 forks/10s after re-baseline must fire");
        assert_eq!(burst.verdict, ForkVerdict::StormCritical);
    }

    #[test]
    fn unreadable_counter_is_tolerated() {
        let fake = FakeProc::new();
        fake.set_counter(100);
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        assert!(mon.tick_at(t0).is_none());
        // Transient: /proc/stat unreadable this poll. No panic, no finding,
        // and the baseline is kept — absence is not zero.
        fake.remove_counter();
        assert!(
            mon.tick_at(t0 + Duration::from_secs(5)).is_none(),
            "unreadable counter must skip the poll, not fail"
        );
        // Counter back with a storm-sized jump from the kept baseline.
        fake.set_counter(700);
        let burst = mon
            .tick_at(t0 + Duration::from_secs(10))
            .expect("storm must still be detected after a transient read failure");
        assert_eq!(burst.verdict, ForkVerdict::StormCritical);
    }

    #[test]
    fn stale_births_are_not_misattributed_to_the_next_storm() {
        let fake = FakeProc::new();
        fake.set_pids(&[(1, 0, "init"), (100, 1, "runaway.sh")]);
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        assert!(mon.tick_at(t0).is_none());
        // First storm, attributed to runaway.sh: the intermediate poll
        // establishes the attribution baseline, then three children appear.
        fake.set_counter(300);
        fake.set_pids(&[(1, 0, "init"), (100, 1, "runaway.sh"), (200, 100, "true")]);
        mon.tick_at(t0 + Duration::from_secs(5));
        fake.set_counter(600);
        fake.set_pids(&[
            (1, 0, "init"),
            (100, 1, "runaway.sh"),
            (200, 100, "true"),
            (201, 100, "true"),
            (202, 100, "true"),
            (203, 100, "true"),
        ]);
        let burst = mon.tick_at(t0 + Duration::from_secs(10)).expect("storm");
        assert_eq!(burst.parent_comm.as_deref(), Some("runaway.sh"));
        assert_eq!(burst.parent_forks, 3);
        // Long quiet period: births must age out of the window.
        fake.set_counter(600);
        assert!(
            mon.tick_at(t0 + Duration::from_secs(60)).is_none(),
            "quiet period must not fire"
        );
        // A new storm from a different parent with *fewer* births: if the
        // first storm's births leaked, runaway.sh (3) would still win over
        // other.sh (2).
        fake.set_counter(1200);
        fake.set_pids(&[
            (1, 0, "init"),
            (300, 1, "other.sh"),
            (400, 300, "true"),
            (401, 300, "true"),
        ]);
        let burst = mon
            .tick_at(t0 + Duration::from_secs(70))
            .expect("second storm must fire");
        assert_eq!(
            burst.parent_comm.as_deref(),
            Some("other.sh"),
            "stale births from the first storm must not be attributed to the second"
        );
        assert_eq!(burst.parent_forks, 2);
    }

    fn warning_burst(parent_comm: &str) -> ForkStorm {
        ForkStorm {
            forks_per_sec: 20.0,
            window_secs: 10.0,
            window_forks: 200,
            parent_pid: Some(4242),
            parent_comm: Some(parent_comm.to_string()),
            parent_forks: 180,
            verdict: ForkVerdict::StormWarning,
        }
    }

    #[test]
    fn warn_cooldown_dedups_repeat_verdicts() {
        let mut mon = ForkStormMonitor::new(Duration::from_millis(500));
        let burst = warning_burst("runaway.sh");
        assert!(mon.should_warn(&burst), "first occurrence must warn");
        assert!(
            !mon.should_warn(&burst),
            "immediate repeat must be cooled down"
        );
        // A verdict change for the same parent is new information, not a repeat.
        let escalated = ForkStorm {
            verdict: ForkVerdict::StormCritical,
            ..burst.clone()
        };
        assert!(mon.should_warn(&escalated));
        // A different parent is unaffected by the first one's cooldown.
        assert!(mon.should_warn(&warning_burst("other.sh")));
    }

    #[test]
    fn warn_cooldown_expires() {
        let mut mon = ForkStormMonitor::new(Duration::from_millis(500))
            .with_warn_cooldown(Duration::from_millis(30));
        let burst = warning_burst("runaway.sh");
        assert!(mon.should_warn(&burst));
        assert!(!mon.should_warn(&burst));
        std::thread::sleep(Duration::from_millis(60));
        assert!(mon.should_warn(&burst), "cooldown must expire");
    }

    #[test]
    fn zero_warn_cooldown_warns_every_time() {
        let mut mon =
            ForkStormMonitor::new(Duration::from_millis(500)).with_warn_cooldown(Duration::ZERO);
        let burst = warning_burst("runaway.sh");
        assert!(mon.should_warn(&burst));
        assert!(mon.should_warn(&burst));
    }

    #[test]
    fn warn_cooldown_map_is_bounded() {
        let mut mon = ForkStormMonitor::new(Duration::from_millis(500))
            .with_warn_cooldown(Duration::from_secs(3600));
        for i in 0..(MAX_COOLDOWN_ENTRIES + 50) {
            let burst = warning_burst(&format!("runaway-{i}.sh"));
            assert!(mon.should_warn(&burst), "new parent must warn");
        }
        assert!(
            mon.last_warned.len() <= MAX_COOLDOWN_ENTRIES,
            "cooldown map grew past its cap: {}",
            mon.last_warned.len()
        );
    }

    #[test]
    fn incident_from_burst_maps_fields() {
        let burst = ForkStorm {
            forks_per_sec: 87.5,
            window_secs: 10.0,
            window_forks: 875,
            parent_pid: Some(4242),
            parent_comm: Some("runaway.sh".to_string()),
            parent_forks: 800,
            verdict: ForkVerdict::StormCritical,
        };
        let incident = incident_from_burst(&burst);
        assert_eq!(incident.event_type, "fork_storm");
        assert_eq!(incident.action, "alert");
        assert_eq!(incident.target_pid, Some(4242));
        assert_eq!(incident.target_name.as_deref(), Some("runaway.sh"));
        // Host-level fields this monitor doesn't sample stay zero/empty;
        // the triggering reading lives in the snapshot.
        assert_eq!(incident.psi_cpu, 0.0);
        assert_eq!(incident.cpu_percent, 0.0);
        let snapshot: serde_json::Value =
            serde_json::from_str(incident.system_snapshot.as_deref().unwrap()).unwrap();
        assert_eq!(snapshot["verdict"], "StormCritical");
        assert_eq!(snapshot["source_tier"], "polling");
        assert!((snapshot["forks_per_sec"].as_f64().unwrap() - 87.5).abs() < 1e-9);
        assert_eq!(snapshot["parent_comm"], "runaway.sh");
        assert_eq!(snapshot["parent_forks_in_window"], 800);
        assert_eq!(snapshot["evidence"]["fork_rate"], "measured");
        assert_eq!(snapshot["evidence"]["offending_parent"], "inferred");
    }

    #[tokio::test]
    async fn storm_is_recorded_as_incident() {
        let fake = FakeProc::new();
        let db_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            IncidentStore::new(db_dir.path().join("incidents.db"))
                .await
                .unwrap(),
        );
        let mut mon = fake.monitor().with_incident_store(Some(Arc::clone(&store)));
        let t0 = Instant::now();
        assert!(mon.tick_at(t0).is_none());
        fake.set_counter(600);
        let burst = mon
            .tick_at(t0 + Duration::from_secs(10))
            .expect("storm must fire");
        mon.handle_burst(&burst).await;

        let incidents = store
            .recent_filtered(10, Some("fork_storm"), None)
            .await
            .unwrap();
        assert_eq!(incidents.len(), 1, "one storm finding, one incident");
        let incident = &incidents[0];
        assert_eq!(incident.event_type, "fork_storm");
        assert_eq!(incident.action, "alert");
        let snapshot: serde_json::Value =
            serde_json::from_str(incident.system_snapshot.as_deref().unwrap()).unwrap();
        assert_eq!(snapshot["verdict"], "StormCritical");

        // The store already has this finding: handling it again must not
        // write a second row. Recording is decided against the store, not
        // the log cooldown.
        mon.handle_burst(&burst).await;
        let incidents = store
            .recent_filtered(10, Some("fork_storm"), None)
            .await
            .unwrap();
        assert_eq!(
            incidents.len(),
            1,
            "repeat findings inside the cooldown must not duplicate incidents"
        );

        // A fresh monitor — the daemon restarted, so the bounded in-memory
        // cooldown map is empty — must not re-record either. The store, not
        // the map, is the source of truth for what was persisted.
        let mut mon2 = fake.monitor().with_incident_store(Some(Arc::clone(&store)));
        assert!(mon2.tick_at(t0).is_none());
        fake.set_counter(1200);
        let burst2 = mon2
            .tick_at(t0 + Duration::from_secs(10))
            .expect("storm must fire");
        mon2.handle_burst(&burst2).await;
        let incidents = store
            .recent_filtered(10, Some("fork_storm"), None)
            .await
            .unwrap();
        assert_eq!(
            incidents.len(),
            1,
            "a restarted monitor must not duplicate incidents the store already has"
        );
    }

    #[test]
    fn warmup_deltas_are_normalized_against_full_window() {
        // Eight ordinary forks in the first 500 ms are 0.8 forks/s over the
        // intended 10-second window — not 16/s, not a storm.
        let fake = FakeProc::new();
        let mut mon = fake.monitor();
        let t0 = Instant::now();
        assert!(mon.tick_at(t0).is_none());
        fake.set_counter(8);
        assert!(
            mon.tick_at(t0 + Duration::from_millis(500)).is_none(),
            "warm-up forks must be normalized against the full window"
        );
        // Thirty forks in the first second: 3/s normalized, not critical.
        fake.set_counter(30);
        assert!(
            mon.tick_at(t0 + Duration::from_secs(1)).is_none(),
            "a short burst must not read as critical during warm-up"
        );
        // A genuinely sustained storm still fires: 600 forks over the
        // full 10 s window is 60/s.
        fake.set_counter(600);
        let burst = mon
            .tick_at(t0 + Duration::from_secs(10))
            .expect("sustained 60 forks/s must be critical");
        assert_eq!(burst.verdict, ForkVerdict::StormCritical);
        assert!((burst.forks_per_sec - 60.0).abs() < 1e-9);
    }

    #[tokio::test]
    async fn failed_insert_is_retried_on_the_next_scan() {
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("incidents.db");
        let burst = warning_burst("runaway.sh");

        // The store is down: the finding is logged, but the failed insert
        // must not poison future record attempts — recording has no
        // in-memory cooldown, only the store's own contents.
        let down_store = Arc::new(IncidentStore::new(&db_path).await.unwrap());
        down_store.close_pool_for_test().await;
        let mut mon = ForkStormMonitor::new(Duration::from_millis(500))
            .with_incident_store(Some(Arc::clone(&down_store)));
        mon.handle_burst(&burst).await;

        // The store recovers (fresh pool on the same file). The next scan
        // must retry the insert instead of sitting out a cooldown.
        let up_store = Arc::new(IncidentStore::new(&db_path).await.unwrap());
        mon.incident_store = Some(Arc::clone(&up_store));
        mon.handle_burst(&burst).await;
        let incidents = up_store
            .recent_filtered(10, Some("fork_storm"), None)
            .await
            .unwrap();
        assert_eq!(
            incidents.len(),
            1,
            "a failed insert must be retried once the store recovers"
        );

        // And the now-recorded finding dedups against the store: no second row.
        mon.handle_burst(&burst).await;
        let incidents = up_store
            .recent_filtered(10, Some("fork_storm"), None)
            .await
            .unwrap();
        assert_eq!(incidents.len(), 1, "a recorded finding must not duplicate");
    }

    #[tokio::test]
    async fn monitor_without_store_stays_log_only() {
        // No incident store configured: handle_burst must not fail, just log.
        let mut mon =
            ForkStormMonitor::new(Duration::from_millis(500)).with_warn_cooldown(Duration::ZERO);
        mon.handle_burst(&warning_burst("runaway.sh")).await;
    }
}
