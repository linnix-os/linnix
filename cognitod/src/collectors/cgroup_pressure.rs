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

use log::{debug, info, warn};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use walkdir::WalkDir;

use super::psi::parse_psi_file;

/// Window stall percentage at or above which a cgroup is called contended.
const CONTENDED_STALL_PCT: f64 = 20.0;
/// Throttled seconds per window at or above which a cgroup is called throttled.
const THROTTLED_SECS: f64 = 1.0;
/// Stall percentage below which throttling is considered "without pressure".
const NO_PRESSURE_STALL_PCT: f64 = 10.0;
/// Default walk depth: root -> slice -> unit (e.g. `system.slice/nginx.service`).
const DEFAULT_MAX_DEPTH: usize = 3;

/// What the combination of pressure and throttling signals means for a cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StallVerdict {
    Healthy,
    /// PSI pressure without throttling: real contention for the resource.
    Contended,
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
#[derive(Debug, Clone, Default)]
struct CgroupTotals {
    cpu_some_total: u64,
    cpu_full_total: u64,
    mem_some_total: u64,
    io_some_total: u64,
    throttled_usec: u64,
    mem_high: u64,
    oom_kill: u64,
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
    let mut t = CgroupTotals::default();
    if let Some((some, full)) = read_pressure_totals(dir, "cpu.pressure") {
        t.cpu_some_total = some;
        t.cpu_full_total = full;
    }
    if let Some((some, _)) = read_pressure_totals(dir, "memory.pressure") {
        t.mem_some_total = some;
    }
    if let Some((some, _)) = read_pressure_totals(dir, "io.pressure") {
        t.io_some_total = some;
    }
    if let Some(v) = read_stat_counter(dir, "cpu.stat", "throttled_usec") {
        t.throttled_usec = v;
    }
    if let Some(v) = read_stat_counter(dir, "memory.events", "high") {
        t.mem_high = v;
    }
    if let Some(v) = read_stat_counter(dir, "memory.events", "oom_kill") {
        t.oom_kill = v;
    }
    t
}

/// Finds cgroup directories (depth-limited) that expose `cpu.pressure`,
/// skipping Kubernetes pod slices — those belong to `PsiMonitor`.
/// Returns `(relative_path, absolute_dir)` pairs.
fn find_cgroup_dirs(root: &Path, max_depth: usize) -> Vec<(String, PathBuf)> {
    WalkDir::new(root)
        .max_depth(max_depth)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_dir())
        .filter(|e| e.path().join("cpu.pressure").is_file())
        .filter(|e| !e.path().to_string_lossy().contains("kubepods"))
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
        .collect()
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
        (true, false, _) => StallVerdict::Contended,
        (false, true, true) => StallVerdict::Throttled,
        (false, true, false) => StallVerdict::ThrottledAndContended,
        (false, false, _) => StallVerdict::Healthy,
    }
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

    /// One scan: read current counters, diff against the previous scan, and
    /// return per-cgroup stall reports. The first call only establishes the
    /// baseline and returns an empty vec — deltas need two samples.
    pub fn tick(&mut self) -> Vec<CgroupStall> {
        let now = Instant::now();
        let dirs = find_cgroup_dirs(&self.root, self.max_depth);
        debug!("[cgroup-pressure] scanning {} cgroups", dirs.len());

        let mut current: HashMap<String, CgroupTotals> = HashMap::new();
        for (rel, dir) in &dirs {
            current.insert(rel.clone(), read_cgroup_totals(dir));
        }

        let mut stalls = Vec::new();
        if let Some(prev_at) = self.previous_at {
            let window_secs = now.duration_since(prev_at).as_secs_f64().max(1e-9);
            for (rel, cur) in &current {
                // A cgroup created after the previous scan has no baseline;
                // skip it this round rather than diffing against zero.
                let Some(prev) = self.previous.get(rel) else {
                    continue;
                };
                let pct = |delta_us: u64| delta_us as f64 / 1e6 / window_secs * 100.0;
                let cpu_stall_pct = pct(cur.cpu_some_total.saturating_sub(prev.cpu_some_total));
                let cpu_full_pct = pct(cur.cpu_full_total.saturating_sub(prev.cpu_full_total));
                let mem_stall_pct = pct(cur.mem_some_total.saturating_sub(prev.mem_some_total));
                let io_stall_pct = pct(cur.io_some_total.saturating_sub(prev.io_some_total));
                let throttled_secs =
                    cur.throttled_usec.saturating_sub(prev.throttled_usec) as f64 / 1e6;
                let mem_high_events = cur.mem_high.saturating_sub(prev.mem_high);
                let oom_kills = cur.oom_kill.saturating_sub(prev.oom_kill);
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
            }
            // Drop state for cgroups that vanished so the map doesn't grow
            // unbounded on hosts with churny slices.
            self.previous.retain(|k, _| current.contains_key(k));
        }

        self.previous = current;
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
            for stall in self.tick() {
                report(&stall);
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
}

/// One human- and agent-readable line per actionable finding. Verdicts are
/// `inferred` from counter combinations; the percentages themselves are
/// `measured` kernel counters.
fn report(stall: &CgroupStall) {
    match stall.verdict {
        StallVerdict::Contended => warn!(
            "[cgroup-pressure] {} CPU-stalled {:.0}% (full {:.0}%), IO-stalled {:.0}% with no throttling -- genuine contention, likely a noisy neighbor or undersized CPU [inferred]",
            stall.cgroup, stall.cpu_stall_pct, stall.cpu_full_pct, stall.io_stall_pct
        ),
        StallVerdict::Throttled => warn!(
            "[cgroup-pressure] {} throttled {:.1}s by cpu.max with only {:.0}% CPU stall -- the CPU limit itself is the bottleneck, not contention [inferred]",
            stall.cgroup, stall.throttled_secs, stall.cpu_stall_pct
        ),
        StallVerdict::ThrottledAndContended => warn!(
            "[cgroup-pressure] {} throttled {:.1}s AND CPU-stalled {:.0}% -- capped and still contending for what's left [inferred]",
            stall.cgroup, stall.throttled_secs, stall.cpu_stall_pct
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
        let dirs = find_cgroup_dirs(tmp.path(), 5);
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
        assert_eq!(totals.cpu_some_total, 2_000_000);
        assert_eq!(totals.cpu_full_total, 100_000);
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
        assert_eq!(nginx.verdict, StallVerdict::Contended);
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
        assert_eq!(totals.cpu_some_total, 5000);
        assert_eq!(totals.throttled_usec, 0);
        assert_eq!(totals.oom_kill, 0);
    }

    #[test]
    fn classify_matrix() {
        assert_eq!(classify(50.0, 0.0, 0.0, 0.0, 0), StallVerdict::Contended);
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
    }
}
