//! Userspace OOM-kill witness: no eBPF, no privileges beyond /proc, sysfs,
//! and (best-effort) the kernel ring buffer.
//!
//! When the OOM killer fires, the interesting questions are: did it happen,
//! in which cgroup, and *who* did it take? Userspace can answer the first
//! two with counters and the third on a good day:
//!
//! * **Kill happened (measured):** `/proc/vmstat`'s `oom_kill` counter Δ,
//!   host-wide. This fires even when cgroup attribution is unavailable.
//! * **Which cgroup (measured):** per-cgroup `memory.events` `max` Δ. The
//!   counter is hierarchical, so the witness attributes the kill to the
//!   *deepest* cgroup(s) whose counter moved — the leaf-most selection
//!   keeps one kill from being reported once per ancestor. Unlike the
//!   pressure monitor, kubepods subtrees are *included*: nothing else
//!   attributes pod OOM kills, and leaf-most selection avoids the
//!   double-counting that motivated the pressure monitor's skip.
//! * **Victim (best-effort):** the kernel logs
//!   `Out of memory: Killed process <pid> (<comm>)` to the ring buffer.
//!   The victim name is `inferred` — the ring may have rotated, and
//!   `dmesg` may be restricted — and `unavailable` when it can't be read.
//!   It is never fabricated.
//!
//! Relationship to the cgroup pressure monitor: that monitor already
//! classifies a per-cgroup `OomKill` *stall verdict* when `memory.events`
//! `max` moves. The witness is complementary, not duplicative — it adds
//! the host-wide counter, the victim identity from `dmesg`, and a
//! dedicated `oom_kill` incident type. One burst of kills in a window is
//! one finding (the kills are counted, not emitted N times); the 15-min
//! cooldown and store-backed dedup prevent refires.
//!
//! Design:
//!
//! * **Poll:** 10s. Counter reads only — `dmesg` is consulted only on
//!   polls where a kill was actually detected, via an injectable
//!   [`DmesgSource`], so the common case costs nothing and tests can fake
//!   the ring buffer.
//! * **Degradation:** on cgroup-v1-only hosts (no `memory.events`) the
//!   cgroup half is `unavailable` but the host counter still fires. A
//!   regressing counter (cgroup recreation) re-baselines instead of
//!   producing a bogus delta. Unreadable files skip the poll without
//!   poisoning baselines.
//! * **eBPF upgrade:** none needed — the OOM killer is already fully
//!   visible from userspace counters; eBPF would only add per-allocation
//!   *why* (which this monitor deliberately does not claim).

use log::{debug, info, warn};
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use walkdir::WalkDir;

use crate::incidents::{Incident, IncidentStore};

/// How deep the cgroup walk goes looking for `memory.events`.
const CGROUP_MAX_DEPTH: usize = 3;
/// Default quiet period between repeat warnings for the same
/// cgroup+victim, mirroring the other monitors.
const DEFAULT_WARN_COOLDOWN: Duration = Duration::from_secs(15 * 60);
/// Cap on the warn-cooldown map; oldest entries are evicted past this.
const MAX_COOLDOWN_ENTRIES: usize = 1024;

/// What an OOM-kill observation means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OomVerdict {
    Healthy,
    /// The OOM killer fired at least once since the last poll.
    OomKillObserved,
}

impl OomVerdict {
    /// `false` for `Healthy`; used to filter log/report noise.
    pub fn actionable(self) -> bool {
        !matches!(self, OomVerdict::Healthy)
    }
}

/// Where the victim identity came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VictimSource {
    /// Parsed from the kernel ring buffer: the kernel's own kill record,
    /// but best-effort — the ring may have rotated past it.
    Dmesg,
    /// `dmesg` unreadable, restricted, or no matching line.
    Unavailable,
}

/// The process the OOM killer took, when the ring buffer says.
#[derive(Debug, Clone)]
pub struct OomVictim {
    pub pid: Option<u32>,
    pub comm: Option<String>,
    pub source: VictimSource,
}

/// One OOM-kill observation for a scan window. A burst of kills in one
/// window is a single finding: `kill_count` counts them.
#[derive(Debug, Clone)]
pub struct OomKill {
    /// Deepest cgroup whose `memory.events:max` moved, as a path relative
    /// to the cgroup root (`/` for the root). `None` when unattributable
    /// (v1 host, or the walk found nothing).
    pub cgroup: Option<String>,
    /// That cgroup's `max` Δ; `None` when the cgroup is unattributed.
    pub cgroup_max_delta: Option<u64>,
    /// Host-wide `/proc/vmstat` `oom_kill` Δ; `None` when unreadable.
    pub host_oom_kill_delta: Option<u64>,
    /// Kills observed this window: the host Δ when readable, else the sum
    /// of attributed leaf-cgroup Δs.
    pub kill_count: u64,
    /// Every leaf cgroup whose counter moved, deepest-first, for snapshot
    /// context: `(rel_path, max_delta)`.
    pub attributed_cgroups: Vec<(String, u64)>,
    pub victim: OomVictim,
    pub verdict: OomVerdict,
}

impl OomKill {
    /// Stable identity for cooldown and incident-dedup keys: the cgroup
    /// plus what is known of the victim. An unknown victim can't be told
    /// apart from another unknown victim in the same cgroup — the key says
    /// so honestly instead of pretending otherwise.
    fn victim_label(&self) -> String {
        let cgroup = self.cgroup.as_deref().unwrap_or("unknown cgroup");
        let victim = match (&self.victim.comm, self.victim.pid) {
            (Some(comm), Some(pid)) => format!("{comm} (pid={pid})"),
            (Some(comm), None) => comm.clone(),
            (None, Some(pid)) => format!("pid={pid}"),
            (None, None) => "victim unavailable".to_string(),
        };
        format!("oom in {cgroup} ({victim})")
    }
}

/// Source of kernel-ring-buffer OOM victim lines. Injectable so tests can
/// fake the ring buffer and production degrades silently when `dmesg` is
/// restricted.
pub trait DmesgSource: Send + Sync {
    /// The most recent `Killed process` victim in the ring buffer, if any.
    fn recent_oom_victim(&self) -> Option<(u32, String)>;
}

/// Production source: shells out to `dmesg` and takes the last matching
/// line. Only consulted on polls where a kill was detected, so the
/// subprocess cost lands exactly when it matters.
pub struct SystemDmesg;

impl DmesgSource for SystemDmesg {
    fn recent_oom_victim(&self) -> Option<(u32, String)> {
        let output = std::process::Command::new("dmesg").output().ok()?;
        if !output.status.success() {
            debug!("[oom] dmesg exited unsuccessfully; victim unavailable");
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        text.lines().filter_map(parse_dmesg_kill).next_back()
    }
}

/// Parses one `Out of memory: Killed process <pid> (<comm>) ...` line.
/// `None` for anything else — the ring is full of unrelated lines.
fn parse_dmesg_kill(line: &str) -> Option<(u32, String)> {
    let rest = line.split("Killed process ").nth(1)?;
    let mut parts = rest.splitn(2, ' ');
    let pid: u32 = parts.next()?.parse().ok()?;
    let comm = parts.next()?.strip_prefix('(')?.split(')').next()?;
    if comm.is_empty() {
        return None;
    }
    Some((pid, comm.to_string()))
}

/// Host-wide OOM-kill count from `/proc/vmstat`. `None` when the file or
/// key is missing — absence is not zero.
fn read_vmstat_oom_kill(proc_root: &Path) -> Option<u64> {
    let content = std::fs::read_to_string(proc_root.join("vmstat")).ok()?;
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some("oom_kill") {
            return parts.next()?.parse::<u64>().ok();
        }
    }
    None
}

/// One `key value` counter from a cgroup `memory.events` file. Missing
/// file or key -> `None`, never zero: zero is a real reading, absence is
/// not. (Mirrors the pressure monitor's reader.)
fn read_memory_events_max(dir: &Path) -> Option<u64> {
    let content = std::fs::read_to_string(dir.join("memory.events")).ok()?;
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some("max")
            && let Some(value) = parts.next()
            && let Ok(v) = value.parse::<u64>()
        {
            return Some(v);
        }
    }
    None
}

/// Cgroup directories (depth-limited) exposing `memory.events`. Returns
/// `(rel_path, abs_dir)`; the root itself is `/`.
fn find_cgroup_dirs(root: &Path) -> Vec<(String, PathBuf)> {
    WalkDir::new(root)
        .max_depth(CGROUP_MAX_DEPTH)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_dir())
        .filter(|e| e.path().join("memory.events").is_file())
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

/// Keeps only the deepest cgroups with a positive Δ: `memory.events`
/// counters are hierarchical, so a kill in a leaf also moves every
/// ancestor. String-prefix matching with a trailing separator keeps
/// `svc` from shadowing `svc2`.
fn leaf_cgroups(deltas: &[(String, u64)]) -> Vec<(String, u64)> {
    deltas
        .iter()
        .filter(|(path, _)| {
            let prefix = if path == "/" {
                "/".to_string()
            } else {
                format!("{path}/")
            };
            !deltas
                .iter()
                .any(|(other, _)| other != path && other.starts_with(&prefix))
        })
        .cloned()
        .collect()
}

/// Stateful OOM-kill witness.
pub struct OomWitnessMonitor {
    proc_root: PathBuf,
    cgroup_root: PathBuf,
    interval: Duration,
    vmstat_baseline: Option<u64>,
    /// rel_path -> (dir inode, last `max` counter). The inode is the
    /// instance identity: a recreated cgroup (new inode, counters reset)
    /// re-baselines instead of diffing against the dead instance.
    cgroup_baselines: HashMap<String, (u64, u64)>,
    dmesg: Box<dyn DmesgSource>,
    warn_cooldown: Duration,
    max_iterations: Option<u64>,
    /// When each cgroup+victim was last warned about.
    last_warned: HashMap<(String, OomVerdict), Instant>,
    /// Whether the last incident-record attempt failed (warn-once, then
    /// debug until a record succeeds — `handle_finding` retries every scan).
    record_unhealthy: bool,
    /// Where findings are recorded so they are visible through the API
    /// and MCP tools, not just the daemon logs. `None` keeps the monitor
    /// log-only.
    incident_store: Option<Arc<IncidentStore>>,
}

impl OomWitnessMonitor {
    pub fn new(interval: Duration) -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            interval,
            vmstat_baseline: None,
            cgroup_baselines: HashMap::new(),
            dmesg: Box::new(SystemDmesg),
            warn_cooldown: DEFAULT_WARN_COOLDOWN,
            max_iterations: None,
            last_warned: HashMap::new(),
            record_unhealthy: false,
            incident_store: None,
        }
    }

    /// Points the monitor at fixture trees instead of the live `/proc` and
    /// `/sys/fs/cgroup`. Test-only in practice; mirrors the other monitors.
    pub fn with_proc_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.proc_root = root.into();
        self
    }

    pub fn with_cgroup_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.cgroup_root = root.into();
        self
    }

    /// Swaps the ring-buffer source (tests inject a fake; production uses
    /// `dmesg`).
    pub fn with_dmesg_source(mut self, source: Box<dyn DmesgSource>) -> Self {
        self.dmesg = source;
        self
    }

    /// Bounds the scan loop so it terminates. Only useful for tests.
    pub fn with_max_iterations(mut self, iterations: u64) -> Self {
        self.max_iterations = Some(iterations);
        self
    }

    /// Quiet period between repeat warnings for the same cgroup+victim.
    /// `Duration::ZERO` warns on every occurrence (useful for tests).
    pub fn with_warn_cooldown(mut self, cooldown: Duration) -> Self {
        self.warn_cooldown = cooldown;
        self
    }

    /// Records findings as `oom_kill` incidents so they surface through
    /// `/incidents` and the MCP tools, not just the daemon logs. Takes
    /// `Option` to mirror the other monitors: the store may be unavailable
    /// (no DB path), in which case the monitor stays log-only.
    pub fn with_incident_store(mut self, store: Option<Arc<IncidentStore>>) -> Self {
        self.incident_store = store;
        self
    }

    /// Log-reporting gate: true the first time a cgroup+victim reports,
    /// and again once the cooldown has elapsed. This gates the log line
    /// only — incident recording is decided separately against the store
    /// (see `handle_finding`), so a failed insert is retried on the next
    /// scan instead of being swallowed by this cooldown.
    fn should_warn(&mut self, finding: &OomKill) -> bool {
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

    /// One poll: Δ the host counter and every cgroup's `max` counter,
    /// attribute kills to the deepest cgroups, and return a single finding
    /// when at least one kill was observed. First sightings only establish
    /// baselines. `dmesg` is consulted only when a kill was detected.
    pub fn tick(&mut self) -> Option<OomKill> {
        self.tick_at(Instant::now())
    }

    fn tick_at(&mut self, _now: Instant) -> Option<OomKill> {
        // Host counter: the kill definitely happened (measured).
        let host_delta = match (self.vmstat_baseline, read_vmstat_oom_kill(&self.proc_root)) {
            (_, None) => {
                debug!("[oom] /proc/vmstat unreadable; host kill count unavailable");
                None
            }
            (None, Some(cur)) => {
                self.vmstat_baseline = Some(cur);
                None
            }
            (Some(prev), Some(cur)) if cur < prev => {
                debug!("[oom] host oom_kill regressed ({prev} -> {cur}); re-baselining");
                self.vmstat_baseline = Some(cur);
                None
            }
            (Some(prev), Some(cur)) => {
                self.vmstat_baseline = Some(cur);
                Some(cur.saturating_sub(prev))
            }
        };

        // Per-cgroup `max` Δs, with recreation-aware baselines.
        let mut deltas: Vec<(String, u64)> = Vec::new();
        for (rel, dir) in find_cgroup_dirs(&self.cgroup_root) {
            let Some(cur) = read_memory_events_max(&dir) else {
                continue;
            };
            let ino = std::fs::metadata(&dir).map(|m| m.ino()).unwrap_or(0);
            match self.cgroup_baselines.get(&rel) {
                None => {
                    self.cgroup_baselines.insert(rel, (ino, cur));
                }
                Some(&(prev_ino, _prev)) if prev_ino != 0 && ino != 0 && prev_ino != ino => {
                    debug!("[oom] cgroup {rel} recreated; re-baselining max counter");
                    self.cgroup_baselines.insert(rel, (ino, cur));
                }
                Some(&(_, prev)) if cur < prev => {
                    debug!("[oom] cgroup {rel} max regressed ({prev} -> {cur}); re-baselining");
                    self.cgroup_baselines.insert(rel, (ino, cur));
                }
                Some(_) => {
                    let delta = cur.saturating_sub(self.cgroup_baselines[&rel].1);
                    self.cgroup_baselines.insert(rel.clone(), (ino, cur));
                    if delta > 0 {
                        deltas.push((rel, delta));
                    }
                }
            }
        }

        let attributed = leaf_cgroups(&deltas);
        // The host counter is authoritative, but a cgroup Δ without a host
        // Δ is still a kill the cgroup counter saw — take the max rather
        // than trusting one source blindly.
        let cgroup_sum: u64 = attributed.iter().map(|(_, d)| d).sum();
        let kill_count = match host_delta {
            Some(d) => d.max(cgroup_sum),
            // vmstat unreadable: the attributed cgroup Δs are the count.
            None => cgroup_sum,
        };
        if kill_count == 0 {
            return None;
        }

        // The kill happened — now ask the ring buffer who it took. This
        // runs at most once per kill-bearing poll.
        let victim = match self.dmesg.recent_oom_victim() {
            Some((pid, comm)) => OomVictim {
                pid: Some(pid),
                comm: Some(comm),
                source: VictimSource::Dmesg,
            },
            None => OomVictim {
                pid: None,
                comm: None,
                source: VictimSource::Unavailable,
            },
        };

        let (cgroup, cgroup_max_delta) = attributed
            .iter()
            .max_by_key(|(_, d)| d)
            .map(|(path, d)| (Some(path.clone()), Some(*d)))
            .unwrap_or((None, None));

        Some(OomKill {
            cgroup,
            cgroup_max_delta,
            host_oom_kill_delta: host_delta,
            kill_count,
            attributed_cgroups: attributed,
            victim,
            verdict: OomVerdict::OomKillObserved,
        })
    }

    pub async fn run(mut self) {
        info!("[oom] starting OOM kill witness");
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
    async fn handle_finding(&mut self, finding: &OomKill) {
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
            .recent_incident_keys("oom_kill", self.warn_cooldown.as_secs())
            .await
        {
            Ok(keys) => keys,
            Err(e) => {
                warn!("[oom] couldn't check recent incidents: {e}");
                HashSet::new()
            }
        }
    }

    /// Best-effort: a failing store must not break the monitoring loop.
    /// The first failure logs at warn level; repeats stay at debug until a
    /// record succeeds, since `handle_finding` retries the insert on every
    /// scan while kills keep being observed.
    async fn record_incident(&mut self, finding: &OomKill) {
        let Some(store) = &self.incident_store else {
            return;
        };
        let incident = incident_from_finding(finding);
        match store.insert(&incident).await {
            Ok(id) => {
                debug!(
                    "[oom] recorded incident #{id} for {}",
                    finding.victim_label()
                );
                self.record_unhealthy = false;
            }
            Err(e) => {
                if self.record_unhealthy {
                    debug!(
                        "[oom] still failing to record incident for {}: {e}",
                        finding.victim_label()
                    );
                } else {
                    warn!(
                        "[oom] failed to record incident for {}: {e}",
                        finding.victim_label()
                    );
                    self.record_unhealthy = true;
                }
            }
        }
    }
}

/// Builds the `oom_kill` incident row for one finding.
///
/// Field mapping, kept honest about what this monitor measures:
/// * `psi_cpu` / `psi_memory` / `cpu_percent` / `load_avg` are host-level
///   fields this monitor doesn't sample, so they're zero/empty; the
///   triggering reading is the kill count, carried in `system_snapshot`.
/// * `target_pid` / `target_name` name the cgroup and, when known, the
///   victim the ring buffer reported.
/// * That a kill happened, and in which cgroup, is `measured` counter
///   data. The victim name is `inferred` (best-effort ring-buffer parse)
///   or `unavailable`.
fn incident_from_finding(finding: &OomKill) -> Incident {
    let attributed: Vec<serde_json::Value> = finding
        .attributed_cgroups
        .iter()
        .map(|(path, delta)| serde_json::json!({ "cgroup": path, "max_delta": delta }))
        .collect();
    let victim = serde_json::json!({
        "pid": finding.victim.pid,
        "comm": finding.victim.comm,
        "source": match finding.victim.source {
            VictimSource::Dmesg => "dmesg",
            VictimSource::Unavailable => "unavailable",
        },
    });
    let snapshot = serde_json::json!({
        "cgroup": finding.cgroup,
        "cgroup_max_delta": finding.cgroup_max_delta,
        "host_oom_kill_delta": finding.host_oom_kill_delta,
        "kill_count": finding.kill_count,
        "attributed_cgroups": attributed,
        "victim": victim,
        "source_tier": "polling",
        "verdict": format!("{:?}", finding.verdict),
        // The kill and its cgroup are measured counters; the victim name
        // is a best-effort ring-buffer parse.
        "evidence": {
            "kill_occurred": "measured",
            "cgroup": if finding.cgroup.is_some() { "measured" } else { "unavailable" },
            "victim": match finding.victim.source {
                VictimSource::Dmesg => "inferred",
                VictimSource::Unavailable => "unavailable",
            },
        },
    });
    Incident {
        id: None,
        timestamp: chrono::Utc::now().timestamp(),
        event_type: "oom_kill".to_string(),
        psi_cpu: 0.0,
        psi_memory: 0.0,
        cpu_percent: 0.0,
        load_avg: String::new(),
        action: "alert".to_string(),
        target_pid: finding.victim.pid.map(|p| p as i32),
        target_name: Some(finding.victim_label()),
        system_snapshot: serde_json::to_string(&snapshot).ok(),
        llm_analysis: None,
        llm_analyzed_at: None,
        investigation: None,
        recovery_time_ms: None,
        psi_after: None,
    }
}

/// One human- and agent-readable line per kill observation. The victim is
/// labeled with its source — or as unavailable, never guessed.
fn report(finding: &OomKill) {
    let cgroup = finding.cgroup.as_deref().unwrap_or("unknown cgroup");
    let host = match finding.host_oom_kill_delta {
        Some(d) => format!("host Δ={d}"),
        None => "host counter unavailable".to_string(),
    };
    let victim = match (&finding.victim.comm, finding.victim.pid) {
        (Some(comm), Some(pid)) => {
            format!("victim: {comm} (pid={pid}) [via dmesg, best-effort]")
        }
        _ => "victim unavailable (dmesg unreadable or ring rotated)".to_string(),
    };
    let times = if finding.kill_count == 1 {
        "once".to_string()
    } else {
        format!("{}×", finding.kill_count)
    };
    if finding.verdict.actionable() {
        warn!("[oom] WARNING: OOM killer fired {times} in cgroup {cgroup} ({host}) — {victim}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    struct FakeDmesg(Option<(u32, String)>);

    impl DmesgSource for FakeDmesg {
        fn recent_oom_victim(&self) -> Option<(u32, String)> {
            self.0.clone()
        }
    }

    struct FakeProc {
        dir: TempDir,
    }

    impl FakeProc {
        fn new() -> Self {
            let fake = Self {
                dir: TempDir::new().unwrap(),
            };
            fs::create_dir_all(fake.dir.path().join("proc")).unwrap();
            fs::create_dir_all(fake.dir.path().join("cgroup")).unwrap();
            fake
        }

        fn set_vmstat(&self, oom_kill: u64) {
            fs::write(
                self.dir.path().join("proc").join("vmstat"),
                format!("nr_free_pages 12345\nnr_zone_inactive_anon 678\noom_kill {oom_kill}\n"),
            )
            .unwrap();
        }

        /// (Re)places `<cgroup-root>/<rel>/memory.events` with a `max`
        /// counter. `rel` is a `/`-separated path like `system.slice/svc`.
        fn set_cgroup_max(&self, rel: &str, max: u64) {
            let d = self.dir.path().join("cgroup").join(rel);
            fs::create_dir_all(&d).unwrap();
            fs::write(
                d.join("memory.events"),
                format!("low 0\nhigh 0\nmax {max}\noom 0\noom_kill {max}\n"),
            )
            .unwrap();
        }

        fn monitor(&self, dmesg: Option<(u32, String)>) -> OomWitnessMonitor {
            OomWitnessMonitor::new(Duration::from_secs(10))
                .with_proc_root(self.dir.path().join("proc"))
                .with_cgroup_root(self.dir.path().join("cgroup"))
                .with_dmesg_source(Box::new(FakeDmesg(dmesg)))
        }
    }

    fn observed_finding(cgroup: Option<&str>, victim: Option<(u32, &str)>) -> OomKill {
        OomKill {
            cgroup: cgroup.map(str::to_string),
            cgroup_max_delta: Some(2),
            host_oom_kill_delta: Some(2),
            kill_count: 2,
            attributed_cgroups: vec![("system.slice/svc".to_string(), 2)],
            victim: match victim {
                Some((pid, comm)) => OomVictim {
                    pid: Some(pid),
                    comm: Some(comm.to_string()),
                    source: VictimSource::Dmesg,
                },
                None => OomVictim {
                    pid: None,
                    comm: None,
                    source: VictimSource::Unavailable,
                },
            },
            verdict: OomVerdict::OomKillObserved,
        }
    }

    #[test]
    fn parse_dmesg_kill_matrix() {
        assert_eq!(
            parse_dmesg_kill(
                "[12345.678901] Out of memory: Killed process 31359 (myapp) total-vm:123456kB"
            ),
            Some((31359, "myapp".to_string()))
        );
        // Comm with spaces survives the paren split.
        assert_eq!(
            parse_dmesg_kill("[1.2] Out of memory: Killed process 7 (my app) total-vm:1kB"),
            Some((7, "my app".to_string()))
        );
        // Unrelated ring lines parse to nothing.
        assert_eq!(
            parse_dmesg_kill("[1.2] CPU0: Core temperature above threshold"),
            None
        );
        assert_eq!(
            parse_dmesg_kill("[1.2] Out of memory: Kill process 9 (x)"),
            None
        );
        assert_eq!(
            parse_dmesg_kill("[1.2] Out of memory: Killed process 9 () total-vm:1kB"),
            None
        );
        assert_eq!(parse_dmesg_kill(""), None);
    }

    #[test]
    fn detects_host_oom_kill_delta() {
        let fake = FakeProc::new();
        let mut mon = fake.monitor(None);
        let t0 = Instant::now();
        fake.set_vmstat(0);
        assert!(
            mon.tick_at(t0).is_none(),
            "first poll establishes baselines"
        );
        fake.set_vmstat(3);
        let finding = mon
            .tick_at(t0 + Duration::from_secs(10))
            .expect("host oom_kill Δ=3 must fire");
        assert_eq!(finding.verdict, OomVerdict::OomKillObserved);
        assert_eq!(finding.kill_count, 3);
        assert_eq!(finding.host_oom_kill_delta, Some(3));
        assert!(finding.cgroup.is_none(), "no cgroup dirs in fixture");
        assert_eq!(finding.victim.source, VictimSource::Unavailable);
        // No further kills: silence.
        assert!(mon.tick_at(t0 + Duration::from_secs(20)).is_none());
    }

    #[test]
    fn attributes_kill_to_cgroup() {
        let fake = FakeProc::new();
        let mut mon = fake.monitor(Some((4242, "hungry".to_string())));
        let t0 = Instant::now();
        fake.set_vmstat(0);
        fake.set_cgroup_max("system.slice/svc", 0);
        assert!(mon.tick_at(t0).is_none());
        fake.set_vmstat(2);
        fake.set_cgroup_max("system.slice/svc", 2);
        let finding = mon
            .tick_at(t0 + Duration::from_secs(10))
            .expect("cgroup max Δ=2 must fire");
        assert_eq!(finding.cgroup.as_deref(), Some("system.slice/svc"));
        assert_eq!(finding.cgroup_max_delta, Some(2));
        assert_eq!(finding.kill_count, 2);
        assert_eq!(finding.victim.pid, Some(4242));
        assert_eq!(finding.victim.comm.as_deref(), Some("hungry"));
        assert_eq!(finding.victim.source, VictimSource::Dmesg);
    }

    #[test]
    fn leaf_most_cgroup_wins() {
        let fake = FakeProc::new();
        let mut mon = fake.monitor(None);
        let t0 = Instant::now();
        fake.set_vmstat(0);
        fake.set_cgroup_max("app", 0);
        fake.set_cgroup_max("app/worker", 0);
        assert!(mon.tick_at(t0).is_none());
        // Hierarchical counters: the kill moves the leaf and its ancestor.
        fake.set_vmstat(1);
        fake.set_cgroup_max("app", 1);
        fake.set_cgroup_max("app/worker", 1);
        let finding = mon
            .tick_at(t0 + Duration::from_secs(10))
            .expect("must fire");
        assert_eq!(finding.cgroup.as_deref(), Some("app/worker"));
        assert_eq!(finding.attributed_cgroups.len(), 1, "one kill, one leaf");
        // A sibling prefix must not shadow: app2 is not under app/.
        fake.set_cgroup_max("app2", 0);
        assert!(mon.tick_at(t0 + Duration::from_secs(20)).is_none());
        fake.set_vmstat(2);
        fake.set_cgroup_max("app2", 1);
        let finding = mon
            .tick_at(t0 + Duration::from_secs(30))
            .expect("must fire");
        assert_eq!(finding.cgroup.as_deref(), Some("app2"));
    }

    #[test]
    fn burst_of_kills_is_one_finding() {
        let fake = FakeProc::new();
        let mut mon = fake.monitor(None);
        let t0 = Instant::now();
        fake.set_vmstat(10);
        assert!(mon.tick_at(t0).is_none());
        fake.set_vmstat(15);
        let finding = mon
            .tick_at(t0 + Duration::from_secs(10))
            .expect("Δ=5 must fire");
        assert_eq!(finding.kill_count, 5, "burst counted, not quintupled");
    }

    #[test]
    fn v1_host_still_fires_without_cgroup_attribution() {
        // No memory.events anywhere (cgroup v1): the host counter alone
        // must still witness the kill, with the cgroup honestly unknown.
        let fake = FakeProc::new();
        let mut mon = fake.monitor(None);
        let t0 = Instant::now();
        fake.set_vmstat(0);
        assert!(mon.tick_at(t0).is_none());
        fake.set_vmstat(1);
        let finding = mon
            .tick_at(t0 + Duration::from_secs(10))
            .expect("host Δ must fire without cgroups");
        assert_eq!(finding.kill_count, 1);
        assert!(finding.cgroup.is_none());
        assert!(finding.cgroup_max_delta.is_none());
    }

    #[test]
    fn regressing_cgroup_counter_rebaselines() {
        let fake = FakeProc::new();
        let mut mon = fake.monitor(None);
        let t0 = Instant::now();
        fake.set_vmstat(0);
        fake.set_cgroup_max("svc", 5);
        assert!(mon.tick_at(t0).is_none());
        // Cgroup recreated: counter reset to 2. That's a re-baseline, not
        // a negative (or wrapped) delta — and the host saw no kill.
        fake.set_cgroup_max("svc", 2);
        assert!(
            mon.tick_at(t0 + Duration::from_secs(10)).is_none(),
            "recreated cgroup must not fabricate a kill"
        );
        // …but the new instance's kills are still observed.
        fake.set_cgroup_max("svc", 3);
        let finding = mon
            .tick_at(t0 + Duration::from_secs(20))
            .expect("new instance kills must fire");
        assert_eq!(finding.cgroup_max_delta, Some(1));
    }

    #[test]
    fn incident_mapping_labels_evidence_honestly() {
        let finding = observed_finding(Some("system.slice/svc"), Some((4242, "hungry")));
        let incident = incident_from_finding(&finding);
        assert_eq!(incident.event_type, "oom_kill");
        assert_eq!(incident.action, "alert");
        assert_eq!(incident.target_pid, Some(4242));
        assert_eq!(
            incident.target_name.as_deref(),
            Some("oom in system.slice/svc (hungry (pid=4242))")
        );
        let snapshot: serde_json::Value =
            serde_json::from_str(incident.system_snapshot.as_deref().unwrap()).unwrap();
        assert_eq!(snapshot["verdict"], "OomKillObserved");
        assert_eq!(snapshot["kill_count"], 2);
        // The kill and its cgroup are measured counters; the victim name
        // is a best-effort ring-buffer parse.
        assert_eq!(snapshot["evidence"]["kill_occurred"], "measured");
        assert_eq!(snapshot["evidence"]["cgroup"], "measured");
        assert_eq!(snapshot["evidence"]["victim"], "inferred");
        assert_eq!(snapshot["victim"]["source"], "dmesg");

        // Unknown victim: unavailable, never fabricated.
        let bare = observed_finding(None, None);
        let incident = incident_from_finding(&bare);
        assert_eq!(incident.target_pid, None);
        let snapshot: serde_json::Value =
            serde_json::from_str(incident.system_snapshot.as_deref().unwrap()).unwrap();
        assert_eq!(snapshot["evidence"]["cgroup"], "unavailable");
        assert_eq!(snapshot["evidence"]["victim"], "unavailable");
        assert_eq!(
            incident.target_name.as_deref(),
            Some("oom in unknown cgroup (victim unavailable)")
        );
    }

    #[test]
    fn warn_cooldown_suppresses_repeat_logs() {
        let mut mon = OomWitnessMonitor::new(Duration::from_secs(10));
        let finding = observed_finding(Some("svc"), Some((1, "a")));
        assert!(mon.should_warn(&finding), "first sighting warns");
        assert!(!mon.should_warn(&finding), "cooldown suppresses the log");
        // A different victim is a different identity.
        let mut other = observed_finding(Some("svc"), Some((2, "b")));
        other.victim.comm = Some("b".to_string());
        other.victim.pid = Some(2);
        assert!(
            mon.should_warn(&other),
            "distinct victims warn independently"
        );
    }

    #[tokio::test]
    async fn finding_is_recorded_as_incident() {
        let db_dir = TempDir::new().unwrap();
        let store = Arc::new(
            IncidentStore::new(db_dir.path().join("incidents.db"))
                .await
                .unwrap(),
        );
        let mut mon = OomWitnessMonitor::new(Duration::from_secs(10))
            .with_incident_store(Some(Arc::clone(&store)));
        let finding = observed_finding(Some("system.slice/svc"), Some((4242, "hungry")));
        mon.handle_finding(&finding).await;

        let incidents = store
            .recent_filtered(10, Some("oom_kill"), None)
            .await
            .unwrap();
        assert_eq!(incidents.len(), 1, "one finding, one incident");
        assert_eq!(incidents[0].event_type, "oom_kill");

        // The store already has this finding: handling it again must not
        // write a second row.
        mon.handle_finding(&finding).await;
        let incidents = store
            .recent_filtered(10, Some("oom_kill"), None)
            .await
            .unwrap();
        assert_eq!(incidents.len(), 1, "repeat findings must not duplicate");

        // A fresh monitor — the daemon restarted — must not re-record.
        let mut mon2 = OomWitnessMonitor::new(Duration::from_secs(10))
            .with_incident_store(Some(Arc::clone(&store)));
        mon2.handle_finding(&finding).await;
        let incidents = store
            .recent_filtered(10, Some("oom_kill"), None)
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
        let finding = observed_finding(Some("svc"), Some((9, "x")));

        let down_store = Arc::new(IncidentStore::new(&db_path).await.unwrap());
        down_store.close_pool_for_test().await;
        let mut mon = OomWitnessMonitor::new(Duration::from_secs(10))
            .with_incident_store(Some(Arc::clone(&down_store)));
        mon.handle_finding(&finding).await;

        let up_store = Arc::new(IncidentStore::new(&db_path).await.unwrap());
        mon.incident_store = Some(Arc::clone(&up_store));
        mon.handle_finding(&finding).await;
        let incidents = up_store
            .recent_filtered(10, Some("oom_kill"), None)
            .await
            .unwrap();
        assert_eq!(
            incidents.len(),
            1,
            "a failed insert must be retried once the store recovers"
        );

        mon.handle_finding(&finding).await;
        let incidents = up_store
            .recent_filtered(10, Some("oom_kill"), None)
            .await
            .unwrap();
        assert_eq!(incidents.len(), 1, "a recorded finding must not duplicate");
    }

    #[tokio::test]
    async fn monitor_without_store_stays_log_only() {
        let mut mon =
            OomWitnessMonitor::new(Duration::from_secs(10)).with_warn_cooldown(Duration::ZERO);
        mon.handle_finding(&observed_finding(Some("svc"), None))
            .await;
    }
}
