use anyhow::Result;
use log::{debug, info, warn};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use walkdir::WalkDir;

use crate::attribution::AttributionSink;
use crate::config::EpisodeCaptureConfig;
use crate::context::ContextStore;
use crate::episode::{CandidateWindow, Episode, PodRef};
use crate::k8s::K8sContext;

#[derive(Debug, Clone, PartialEq)]
pub struct PsiSnapshot {
    pub some_total: u64,
    pub full_total: u64,
}

#[derive(Debug, Clone)]
pub struct PsiDelta {
    pub pod_name: String,
    pub namespace: String,
    pub delta_stall_us: u64,
    pub timestamp: Instant,
}

#[derive(Debug, Clone)]
pub struct CpuConsumer {
    pub pod: String,
    pub namespace: String,
    pub cpu_percent: f32,
}

#[derive(Debug, Clone)]
pub struct StallEvent {
    /// Identifies this stall event across every attribution it produces.
    ///
    /// A UUID rather than a counter: a counter restarts with the process, so
    /// two events from either side of a restart would share an id and any
    /// consumer grouping on it would silently merge them — the same undercount
    /// this field exists to remove. Ordering comes from `timestamp`, so
    /// sortability is not needed here.
    pub event_id: String,
    pub victim_pod: String,
    pub victim_namespace: String,
    pub stall_delta_us: u64,
    pub timestamp: Instant,
    pub concurrent_consumers: Vec<CpuConsumer>,
    pub fork_counts: HashMap<String, u64>,
    pub short_job_counts: HashMap<String, u64>,
    /// Memory-pressure stall accrued over the same window as `stall_delta_us`,
    /// from `memory.pressure` in the same cgroup as the triggering
    /// `cpu.pressure` read. Carried for episode capture only — the blame
    /// score in `calculate_blame_attributions` stays CPU/fork/short-job only,
    /// so this does not change what gets attributed, only what gets recorded.
    pub memory_stall_delta_us: u64,
    /// Same idea for `io.pressure`.
    pub io_stall_delta_us: u64,
    /// Snapshot of `memory.current` (bytes) at trigger time, summed across the
    /// victim pod's containers. Zero when the file was unreadable rather than
    /// `Option`, matching `stall_delta_us`'s convention elsewhere in this
    /// struct.
    pub memory_bytes: u64,
    /// Snapshot of `io.stat` (rbytes + wbytes summed across devices and
    /// containers) at trigger time.
    pub io_bytes: u64,
    /// Point-in-time snapshot of `memory.stat`'s anon/file/slab bytes, summed
    /// across the victim pod's containers at trigger time. `None` when no
    /// container exposed the field this scan — unlike `memory_bytes` above,
    /// `memory.stat`'s field set moves with kernel version, so a missing
    /// field here cannot be safely folded into zero.
    pub memory_anon_bytes: Option<u64>,
    pub memory_file_bytes: Option<u64>,
    pub memory_slab_bytes: Option<u64>,
    /// Counters from `memory.stat`, delta'd over the same window as
    /// `stall_delta_us` the same way `memory_stall_delta_us` is (current
    /// reading minus the container's previous scan). Major faults and
    /// reclaim-driven refaults are thrashing indicators — what turns "using a
    /// lot of memory" into "the kernel is fighting to keep it". `None` when
    /// no container exposed the counter, or none had a previous sample yet.
    pub memory_pgmajfault_delta: Option<u64>,
    /// Sum of `workingset_refault_anon` + `workingset_refault_file` deltas.
    pub workingset_refault_delta: Option<u64>,
    /// The victim plus every offender candidate's own signal window,
    /// captured for episode replay. The victim's `pre_window` carries its
    /// retained cpu/memory/io stall-delta series; offender candidates carry
    /// an empty `pre_window` (their per-tick CPU% is not retained as a full
    /// series, only a busy-since start time, so `first_deviation_offset_ms`
    /// is still real but there is no sample vector behind it yet).
    /// `post_window` is always empty on every candidate here — filling it
    /// needs deferred, multi-scan finalization after the trigger fires,
    /// which does not exist yet. None of this feeds `calculate_blame_attributions`.
    pub candidates: Vec<CandidateWindow>,
}

#[derive(Debug, Clone)]
pub struct BlameAttribution {
    /// The stall event this attribution belongs to. Every offender blamed for
    /// one event shares it, which is what lets a consumer group the rows of an
    /// event without inferring it from `(timestamp, stall_us)`.
    pub event_id: String,
    pub victim_pod: String,
    pub victim_namespace: String,
    pub offender_pod: String,
    pub offender_namespace: String,
    pub blame_score: f64,
    /// The victim's total stall for this window. Identical across every
    /// attribution for the same event, so summing it double-counts.
    pub stall_us: u64,
    /// This offender's share of `stall_us`, split by blame score. Summing this
    /// across an event's attributions stays within the stall that happened.
    pub attributed_stall_us: u64,
    pub timestamp: u64,
    pub cpu_share: f64,
    pub fork_count: u64,
    pub short_job_count: u64,
}

pub fn parse_psi_file(content: &str) -> Result<PsiSnapshot> {
    let mut some_total = 0u64;
    let mut full_total = 0u64;

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let prefix = parts[0];
        if prefix != "some" && prefix != "full" {
            continue;
        }

        for part in &parts[1..] {
            if let Some((key, value)) = part.split_once('=')
                && key == "total"
                && let Ok(v) = value.parse::<u64>()
            {
                if prefix == "some" {
                    some_total = v;
                } else {
                    full_total = v;
                }
            }
        }
    }

    Ok(PsiSnapshot {
        some_total,
        full_total,
    })
}

/// Sums `rbytes` + `wbytes` across every device line of a cgroup v2 `io.stat`
/// file. A cgroup only lists the devices it actually touched, so this is
/// already scoped to the container — no filtering needed.
fn parse_io_stat(content: &str) -> u64 {
    let mut total = 0u64;
    for line in content.lines() {
        for field in line.split_whitespace().skip(1) {
            if let Some((key, value)) = field.split_once('=')
                && (key == "rbytes" || key == "wbytes")
                && let Ok(v) = value.parse::<u64>()
            {
                total = total.saturating_add(v);
            }
        }
    }
    total
}

/// Reads a cgroup v2 `memory.current` file: a single integer, in bytes.
fn read_memory_current(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// Fields read from a cgroup v2 `memory.stat` file, split by shape rather
/// than kept in one undifferentiated map: `memory.stat` mixes point-in-time
/// gauges (`anon`, `file`, `slab`) with monotonic counters accrued since the
/// cgroup was created (`pgmajfault`, `workingset_refault_*`). Collapsing both
/// into one `HashMap<String, u64>` would let a reader treat a lifetime
/// counter as "bytes during the stall" — the same naming trap `io_bytes`
/// already carries elsewhere in this file. Every field is `Option` rather
/// than defaulting to zero: `memory.stat`'s field set moves with kernel
/// version (`zswap` is 5.19+, `pagetables` ~5.16+), so a missing field on an
/// older kernel must stay distinguishable from a real zero reading.
#[derive(Debug, Default, Clone, PartialEq)]
struct MemoryStat {
    anon_bytes: Option<u64>,
    file_bytes: Option<u64>,
    slab_bytes: Option<u64>,
    pgmajfault_total: Option<u64>,
    workingset_refault_anon_total: Option<u64>,
    workingset_refault_file_total: Option<u64>,
}

/// Parses a cgroup v2 `memory.stat` file (`key value` lines, one per field)
/// into the curated subset of fields tracked here. Pure so it can be tested
/// without a fixture directory. Unrecognized lines and unparseable values are
/// silently skipped rather than treated as an error — `memory.stat` carries
/// many more fields than are curated here, and a kernel adding a new one
/// should not make this parser fail.
fn parse_memory_stat(content: &str) -> MemoryStat {
    let mut values: HashMap<&str, u64> = HashMap::new();
    for line in content.lines() {
        if let Some((key, value)) = line.split_once(' ')
            && let Ok(v) = value.trim().parse::<u64>()
        {
            values.insert(key, v);
        }
    }
    MemoryStat {
        anon_bytes: values.get("anon").copied(),
        file_bytes: values.get("file").copied(),
        slab_bytes: values.get("slab").copied(),
        pgmajfault_total: values.get("pgmajfault").copied(),
        workingset_refault_anon_total: values.get("workingset_refault_anon").copied(),
        workingset_refault_file_total: values.get("workingset_refault_file").copied(),
    }
}

/// The non-CPU signals read from a single container's cgroup v2 directory in
/// one scan. `None` fields mean the file was missing or unreadable (older
/// kernels, a controller not delegated to this cgroup) rather than a real
/// zero reading.
#[derive(Debug, Default, PartialEq)]
struct CgroupSignals {
    memory_pressure: Option<PsiSnapshot>,
    io_pressure: Option<PsiSnapshot>,
    memory_bytes: Option<u64>,
    io_bytes: u64,
    memory_stat: MemoryStat,
}

/// Reads `memory.pressure`, `io.pressure`, `memory.current`, `io.stat` and
/// `memory.stat` from a cgroup v2 directory, sibling to the `cpu.pressure`
/// file the scan loop is anchored on. Pure and side-effect free so it can be
/// tested against a fixture directory without driving the async scan loop.
fn read_cgroup_signals(cgroup_dir: &Path) -> CgroupSignals {
    CgroupSignals {
        memory_pressure: std::fs::read_to_string(cgroup_dir.join("memory.pressure"))
            .ok()
            .and_then(|c| parse_psi_file(&c).ok()),
        io_pressure: std::fs::read_to_string(cgroup_dir.join("io.pressure"))
            .ok()
            .and_then(|c| parse_psi_file(&c).ok()),
        memory_bytes: read_memory_current(&cgroup_dir.join("memory.current")),
        io_bytes: std::fs::read_to_string(cgroup_dir.join("io.stat"))
            .ok()
            .map(|c| parse_io_stat(&c))
            .unwrap_or(0),
        memory_stat: std::fs::read_to_string(cgroup_dir.join("memory.stat"))
            .ok()
            .map(|c| parse_memory_stat(&c))
            .unwrap_or_default(),
    }
}

/// Adds an optional per-container reading into a pod-level accumulator.
/// `None` (field absent on this container, e.g. an older kernel) leaves the
/// accumulator untouched rather than being treated as zero — a pod is only
/// reported `None` for a field if *no* container this scan exposed it.
fn accumulate_optional(acc: &mut Option<u64>, value: Option<u64>) {
    if let Some(v) = value {
        *acc = Some(acc.unwrap_or(0).saturating_add(v));
    }
}

fn find_psi_files(base_path: &Path) -> Vec<PathBuf> {
    WalkDir::new(base_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().file_name().is_some_and(|n| n == "cpu.pressure")
                && e.path().to_string_lossy().contains("kubepods")
        })
        .map(|e| e.path().to_path_buf())
        .collect()
}

fn extract_container_id(cgroup_path: &Path) -> Option<String> {
    let parent = cgroup_path.parent()?;
    let dir_name = parent.file_name()?.to_string_lossy();
    let clean = dir_name.trim_end_matches(".scope");
    let id = clean
        .rfind('-')
        .map(|idx| &clean[idx + 1..])
        .unwrap_or(clean);

    (id.len() == 64).then(|| id.to_string())
}

const STALL_THRESHOLD_US: u64 = 100_000; // 100ms threshold for significant stall

/// A candidate offender's CPU share, at or above which it counts as "busy" for
/// onset bookkeeping (`consumer_busy_since`). Below this it is treated as idle
/// and its busy-since start time is cleared, so a pod that dips under the bar
/// and later spikes again gets a fresh onset rather than one dated to its
/// first, unrelated blip.
const CONSUMER_BUSY_CPU_PERCENT: f32 = 5.0;

/// Offender candidates captured onto a `StallEvent`, beyond the victim itself.
/// Bounds episode-capture size on a node with many concurrent consumers.
const MAX_CANDIDATE_OFFENDERS: usize = 10;

/// How many samples of history (at the scan loop's 1-second cadence) to keep
/// per signal per pod/container.
///
/// Must comfortably exceed `sustained_pressure_seconds`: the trigger fires
/// only after pressure has been sustained that long, so retained history
/// shorter than that window can never reach back to a pre-pressure baseline
/// -- onset detection would be structurally impossible regardless of how it's
/// computed. The `+ 20` pads for baseline samples before the deviation
/// starts; the `.max(15)` floors capacity even when a test or a real config
/// sets `sustained_pressure_seconds` to 0.
fn compute_history_capacity(sustained_pressure_seconds: u64) -> usize {
    (sustained_pressure_seconds.max(15) as usize) * 2 + 20
}

/// Milliseconds from `start` to `now`, negated: the deviation preceded the
/// trigger, so the offset is always zero or negative. A thin wrapper so the
/// sign convention lives in one place and call sites read as English
/// ("onset_offset_ms(now, pressure_start_time)") rather than repeating the
/// negation and the cast.
fn onset_offset_ms(now: Instant, start: Instant) -> i64 {
    -(now.duration_since(start).as_millis() as i64)
}

/// Assembles the per-candidate windows attached to a `StallEvent`: one for
/// the victim (its own retained signal series), and one per offender still
/// tracked in `consumer_busy_since`. Free-standing and pure so it can be
/// tested without driving the scan loop.
/// An offender candidate's identity plus the three signals
/// `Episode::to_stall_event` reads back via `candidate_signal` -- an episode
/// captured from a real `StallEvent` must replay to the same attribution,
/// and that equality only holds if these land in the candidate's window
/// rather than the empty windows this used to leave behind.
struct OffenderSignal {
    pod: PodRef,
    onset_ms: Option<i64>,
    cpu_percent: f32,
    fork_count: Option<u64>,
    short_job_count: Option<u64>,
}

fn build_candidate_windows(
    victim: PodRef,
    victim_owner_kind: Option<String>,
    victim_owner_name: Option<String>,
    victim_pre_window: BTreeMap<String, Vec<f64>>,
    victim_onset_ms: Option<i64>,
    sample_interval_ms: u64,
    offenders: &[OffenderSignal],
) -> Vec<CandidateWindow> {
    let mut candidates = Vec::with_capacity(1 + offenders.len());
    candidates.push(CandidateWindow {
        pod: victim,
        owner_kind: victim_owner_kind,
        owner_name: victim_owner_name,
        pre_window: victim_pre_window,
        post_window: BTreeMap::new(),
        sample_interval_ms,
        first_deviation_offset_ms: victim_onset_ms,
    });
    for offender in offenders.iter().take(MAX_CANDIDATE_OFFENDERS) {
        let mut pre_window: BTreeMap<String, Vec<f64>> = BTreeMap::new();
        pre_window.insert("cpu_percent".to_string(), vec![offender.cpu_percent as f64]);
        if let Some(fork_count) = offender.fork_count {
            pre_window.insert("fork_count".to_string(), vec![fork_count as f64]);
        }
        if let Some(short_job_count) = offender.short_job_count {
            pre_window.insert("short_job_count".to_string(), vec![short_job_count as f64]);
        }
        candidates.push(CandidateWindow {
            pod: offender.pod.clone(),
            owner_kind: None,
            owner_name: None,
            pre_window,
            post_window: BTreeMap::new(),
            sample_interval_ms,
            first_deviation_offset_ms: offender.onset_ms,
        });
    }
    candidates
}

/// Fork count over a detection window at which an offender is considered to be
/// forking as hard as the score can express. Beyond this the term saturates, so
/// a fork bomb and a very busy fork bomb rank the same on this factor alone.
const FORK_SATURATION: f64 = 100.0;

/// Same idea for short-lived jobs: churn at or above this rate contributes the
/// full weight of the term.
const SHORT_JOB_SATURATION: f64 = 50.0;

/// The fork term of the blame score, normalised to 0.0..=1.0.
///
/// This lives here, next to the score it feeds, and `BlameReason::classify`
/// calls it rather than repeating the arithmetic: the reported *reason* must
/// name whichever term actually dominated the reported *score*, and a copied
/// literal cannot hold that invariant across a change to either side.
pub fn fork_score(fork_count: u64) -> f64 {
    (fork_count as f64 / FORK_SATURATION).min(1.0)
}

/// The short-job-churn term of the blame score, normalised to 0.0..=1.0.
pub fn short_job_score(short_job_count: u64) -> f64 {
    (short_job_count as f64 / SHORT_JOB_SATURATION).min(1.0)
}

pub struct PsiMonitor {
    k8s_ctx: Arc<K8sContext>,
    context: Arc<ContextStore>,
    incident_store: Option<Arc<crate::incidents::IncidentStore>>,
    sink: Arc<AttributionSink>,
    /// Container-level CPU-pressure histories keyed by container id. PSI
    /// counters are emitted by container cgroups; pod-level stall windows are
    /// derived by summing same-scan container deltas after each container
    /// cursor advances. CPU is the sole detection signal (`STALL_THRESHOLD_US`
    /// below applies only here) — memory/io deltas are computed the same way
    /// but only ever recorded onto a `StallEvent` that CPU pressure already
    /// triggered, never used to trigger one themselves.
    history: HashMap<String, VecDeque<PsiSnapshot>>,
    memory_history: HashMap<String, VecDeque<PsiSnapshot>>,
    io_history: HashMap<String, VecDeque<PsiSnapshot>>,
    /// Pod-keyed (not container-keyed) per-scan stall-delta series, retained
    /// across scans so a trigger can attach the victim's own signal history
    /// to its `CandidateWindow`. Pushed once per scan from the same deltas
    /// `pod_deltas` already computes; unlike `history` above these are plain
    /// `f64` samples (episode series are signal-agnostic vectors) rather than
    /// cumulative `PsiSnapshot`s.
    pod_cpu_stall_series: HashMap<String, VecDeque<f64>>,
    pod_memory_stall_series: HashMap<String, VecDeque<f64>>,
    pod_io_stall_series: HashMap<String, VecDeque<f64>>,
    /// Each container's most recent `memory.stat` reading, keyed the same way
    /// as `history`. Only the counter fields are ever read back out of this
    /// (`pgmajfault_total`, `workingset_refault_*_total`) — they're needed to
    /// delta this scan's cumulative counters against the last one, the same
    /// way `history` backs `delta_stall_us`. The gauge fields are stored too
    /// only because `MemoryStat` is one struct; they are not read back.
    memory_stat_history: HashMap<String, MemoryStat>,
    /// When each concurrent CPU consumer pod most recently transitioned from
    /// idle to busy (>= `CONSUMER_BUSY_CPU_PERCENT`). Sampled once per scan,
    /// but only while some pod's `pressure_start_time` is active -- gating
    /// avoids walking the live process map every second on an otherwise-quiet
    /// node. This is deliberately start-time bookkeeping rather than a full
    /// per-tick series (see `StallEvent::candidates` doc comment): cheap, and
    /// enough to give offender candidates a real (not fabricated) onset.
    consumer_busy_since: HashMap<String, Instant>,
    pressure_start_time: HashMap<String, Instant>,
    sustained_pressure_duration: Duration,
    /// Sample cap for every history map above, sized from
    /// `sustained_pressure_duration` by `compute_history_capacity` so it can
    /// always reach back to a pre-pressure baseline.
    history_capacity: usize,
    cgroup_root: PathBuf,
    /// When set, `run` stops after this many scans instead of looping forever.
    max_iterations: Option<u64>,
    /// When set, every `StallEvent` is also written to disk as a `VmCapture`
    /// episode -- the Phase 3 kernel/topology matrix's capture path. `None`
    /// on every real customer fleet; only a matrix VM's config turns this on.
    episode_capture: Option<EpisodeCaptureConfig>,
    /// The kernel/topology cell stamped onto each captured episode. Detected
    /// once at construction, since none of it changes while the daemon runs;
    /// only computed when `episode_capture` is set, to keep the common path
    /// free of the `k3s --version` subprocess call.
    cell: Option<crate::episode::Cell>,
}

struct PodPsiDelta {
    pod_name: String,
    namespace: String,
    delta_stall_us: u64,
    has_previous_sample: bool,
    memory_delta_stall_us: u64,
    io_delta_stall_us: u64,
    memory_bytes: u64,
    io_bytes: u64,
    memory_anon_bytes: Option<u64>,
    memory_file_bytes: Option<u64>,
    memory_slab_bytes: Option<u64>,
    memory_pgmajfault_delta: Option<u64>,
    workingset_refault_delta: Option<u64>,
    owner_kind: Option<String>,
    owner_name: Option<String>,
}

impl PsiMonitor {
    pub fn new(
        k8s_ctx: Arc<K8sContext>,
        context: Arc<ContextStore>,
        incident_store: Option<Arc<crate::incidents::IncidentStore>>,
        sustained_pressure_seconds: u64,
        sink: Arc<AttributionSink>,
    ) -> Self {
        Self {
            k8s_ctx,
            context,
            incident_store,
            sink,
            history: HashMap::new(),
            memory_history: HashMap::new(),
            io_history: HashMap::new(),
            pod_cpu_stall_series: HashMap::new(),
            pod_memory_stall_series: HashMap::new(),
            pod_io_stall_series: HashMap::new(),
            memory_stat_history: HashMap::new(),
            consumer_busy_since: HashMap::new(),
            pressure_start_time: HashMap::new(),
            sustained_pressure_duration: Duration::from_secs(sustained_pressure_seconds),
            history_capacity: compute_history_capacity(sustained_pressure_seconds),
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            max_iterations: None,
            episode_capture: None,
            cell: None,
        }
    }

    /// Points the monitor at a different cgroup hierarchy. Exists so the scan
    /// loop can be driven against a fixture tree rather than the live kernel.
    pub fn with_cgroup_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.cgroup_root = root.into();
        self
    }

    /// Turns on episode capture: every `StallEvent` from here on is also
    /// written to `config.output_dir` as a `VmCapture` episode. No-op (aside
    /// from detecting the cell once) when `config.enabled` is false, so a
    /// caller can pass `config.episode_capture` unconditionally.
    pub fn with_episode_capture(mut self, config: EpisodeCaptureConfig) -> Self {
        if config.enabled {
            self.cell = Some(crate::cell::detect_cell());
            self.episode_capture = Some(config);
        }
        self
    }

    /// Bounds the scan loop so it terminates. Only useful for tests.
    pub fn with_max_iterations(mut self, iterations: u64) -> Self {
        self.max_iterations = Some(iterations);
        self
    }

    pub async fn run(mut self) {
        info!("[psi] starting PSI monitor");
        let base_path = self.cgroup_root.clone();
        let mut iterations = 0u64;

        loop {
            let psi_files = find_psi_files(&base_path);
            debug!("[psi] scanning {} cgroups", psi_files.len());

            let mut pod_deltas: HashMap<String, PodPsiDelta> = HashMap::new();

            for path in psi_files {
                if let Some(container_id) = extract_container_id(&path)
                    && let Some(meta) = self.k8s_ctx.get_metadata(&container_id)
                    && let Ok(content) = std::fs::read_to_string(&path)
                    && let Ok(snapshot) = parse_psi_file(&content)
                {
                    let key = format!("{}/{}", meta.namespace, meta.pod_name);
                    let pod_delta = pod_deltas
                        .entry(key.clone())
                        .or_insert_with(|| PodPsiDelta {
                            pod_name: meta.pod_name.clone(),
                            namespace: meta.namespace.clone(),
                            delta_stall_us: 0,
                            has_previous_sample: false,
                            memory_delta_stall_us: 0,
                            io_delta_stall_us: 0,
                            memory_bytes: 0,
                            io_bytes: 0,
                            memory_anon_bytes: None,
                            memory_file_bytes: None,
                            memory_slab_bytes: None,
                            memory_pgmajfault_delta: None,
                            workingset_refault_delta: None,
                            owner_kind: meta.owner_kind.clone(),
                            owner_name: meta.owner_name.clone(),
                        });

                    self.sink.metrics().record_victim_pressure(
                        &meta.namespace,
                        &meta.pod_name,
                        &container_id,
                        snapshot.some_total,
                    );

                    // Get or create history for this container. Pod-level
                    // deltas are aggregated after every container's own
                    // cursor has been advanced, so sibling containers never
                    // compare their cumulative counters against each other.
                    let hist = self.history.entry(container_id.clone()).or_default();

                    // Calculate delta if we have previous snapshot
                    let delta_stall_opt = hist
                        .back()
                        .map(|prev| snapshot.some_total.saturating_sub(prev.some_total));

                    // Add new snapshot to history
                    hist.push_back(snapshot);

                    // Keep only last N snapshots
                    if hist.len() > self.history_capacity {
                        hist.pop_front();
                    }

                    if let Some(delta_stall) = delta_stall_opt {
                        pod_delta.has_previous_sample = true;
                        pod_delta.delta_stall_us =
                            pod_delta.delta_stall_us.saturating_add(delta_stall);
                    }

                    // memory.pressure, io.pressure, memory.current and io.stat
                    // all sit in the same cgroup v2 directory as the
                    // cpu.pressure file this scan is anchored on, so no
                    // separate directory walk is needed. These are recorded
                    // for episode capture only — CPU pressure above remains
                    // the sole trigger, and none of this feeds
                    // `calculate_blame_attributions`.
                    if let Some(cgroup_dir) = path.parent() {
                        let signals = read_cgroup_signals(cgroup_dir);

                        if let Some(mem_snapshot) = signals.memory_pressure {
                            let mem_hist =
                                self.memory_history.entry(container_id.clone()).or_default();
                            if let Some(prev) = mem_hist.back() {
                                pod_delta.memory_delta_stall_us =
                                    pod_delta.memory_delta_stall_us.saturating_add(
                                        mem_snapshot.some_total.saturating_sub(prev.some_total),
                                    );
                            }
                            mem_hist.push_back(mem_snapshot);
                            if mem_hist.len() > self.history_capacity {
                                mem_hist.pop_front();
                            }
                        }

                        if let Some(io_snapshot) = signals.io_pressure {
                            let io_hist = self.io_history.entry(container_id.clone()).or_default();
                            if let Some(prev) = io_hist.back() {
                                pod_delta.io_delta_stall_us =
                                    pod_delta.io_delta_stall_us.saturating_add(
                                        io_snapshot.some_total.saturating_sub(prev.some_total),
                                    );
                            }
                            io_hist.push_back(io_snapshot);
                            if io_hist.len() > self.history_capacity {
                                io_hist.pop_front();
                            }
                        }

                        if let Some(mem_bytes) = signals.memory_bytes {
                            pod_delta.memory_bytes =
                                pod_delta.memory_bytes.saturating_add(mem_bytes);
                        }

                        pod_delta.io_bytes = pod_delta.io_bytes.saturating_add(signals.io_bytes);

                        // memory.stat gauges are a point-in-time snapshot
                        // (summed across containers, like memory_bytes
                        // above); its counters are cumulative since cgroup
                        // creation, so they're delta'd against this
                        // container's previous reading first, same as
                        // delta_stall_us.
                        accumulate_optional(
                            &mut pod_delta.memory_anon_bytes,
                            signals.memory_stat.anon_bytes,
                        );
                        accumulate_optional(
                            &mut pod_delta.memory_file_bytes,
                            signals.memory_stat.file_bytes,
                        );
                        accumulate_optional(
                            &mut pod_delta.memory_slab_bytes,
                            signals.memory_stat.slab_bytes,
                        );

                        let prev_stat = self.memory_stat_history.get(&container_id).cloned();

                        if let (Some(prev), Some(cur)) = (
                            prev_stat.as_ref().and_then(|p| p.pgmajfault_total),
                            signals.memory_stat.pgmajfault_total,
                        ) {
                            accumulate_optional(
                                &mut pod_delta.memory_pgmajfault_delta,
                                Some(cur.saturating_sub(prev)),
                            );
                        }

                        let refault_delta = match (
                            prev_stat
                                .as_ref()
                                .and_then(|p| p.workingset_refault_anon_total),
                            signals.memory_stat.workingset_refault_anon_total,
                            prev_stat
                                .as_ref()
                                .and_then(|p| p.workingset_refault_file_total),
                            signals.memory_stat.workingset_refault_file_total,
                        ) {
                            (Some(prev_anon), Some(cur_anon), Some(prev_file), Some(cur_file)) => {
                                Some(
                                    cur_anon.saturating_sub(prev_anon)
                                        + cur_file.saturating_sub(prev_file),
                                )
                            }
                            _ => None,
                        };
                        accumulate_optional(&mut pod_delta.workingset_refault_delta, refault_delta);

                        self.memory_stat_history
                            .insert(container_id.clone(), signals.memory_stat);
                    }
                }
            }

            // Retain this scan's per-pod deltas as a series, keyed the same
            // way as `pod_deltas` itself. Pushed unconditionally (including
            // zero-delta scans) so the series' sample spacing stays uniform
            // at the scan loop's 1-second cadence -- a series with dropped
            // quiet samples would make `sample_interval_ms` a lie.
            for (key, pod_delta) in &pod_deltas {
                if !pod_delta.has_previous_sample {
                    continue;
                }
                for (series, value) in [
                    (&mut self.pod_cpu_stall_series, pod_delta.delta_stall_us),
                    (
                        &mut self.pod_memory_stall_series,
                        pod_delta.memory_delta_stall_us,
                    ),
                    (&mut self.pod_io_stall_series, pod_delta.io_delta_stall_us),
                ] {
                    let samples = series.entry(key.clone()).or_default();
                    samples.push_back(value as f64);
                    if samples.len() > self.history_capacity {
                        samples.pop_front();
                    }
                }
            }

            for (key, pod_delta) in pod_deltas {
                if let Some(delta_stall) = pod_delta
                    .has_previous_sample
                    .then_some(pod_delta.delta_stall_us)
                    && delta_stall > 0
                {
                    info!(
                        "[psi] {}/{} delta_stall_us={}",
                        pod_delta.namespace, pod_delta.pod_name, delta_stall
                    );

                    // If stall exceeds threshold, check for sustained pressure
                    if delta_stall >= STALL_THRESHOLD_US {
                        let now = Instant::now();
                        let start_time =
                            *self.pressure_start_time.entry(key.clone()).or_insert(now);

                        // Check if pressure is sustained for > configured duration
                        if now.duration_since(start_time) >= self.sustained_pressure_duration {
                            info!(
                                "[psi] Sustained pressure detected for {}/{} (>{:?})",
                                pod_delta.namespace,
                                pod_delta.pod_name,
                                self.sustained_pressure_duration
                            );

                            // Collect metrics
                            let consumers = self.get_concurrent_cpu_consumers();
                            let (fork_counts, short_job_counts) = self
                                .context
                                .get_pod_activity_window(self.sustained_pressure_duration);

                            let mut victim_pre_window: BTreeMap<String, Vec<f64>> = BTreeMap::new();
                            victim_pre_window.insert(
                                "cpu_stall_us".to_string(),
                                self.pod_cpu_stall_series
                                    .get(&key)
                                    .map(|s| s.iter().copied().collect())
                                    .unwrap_or_default(),
                            );
                            victim_pre_window.insert(
                                "memory_stall_us".to_string(),
                                self.pod_memory_stall_series
                                    .get(&key)
                                    .map(|s| s.iter().copied().collect())
                                    .unwrap_or_default(),
                            );
                            victim_pre_window.insert(
                                "io_stall_us".to_string(),
                                self.pod_io_stall_series
                                    .get(&key)
                                    .map(|s| s.iter().copied().collect())
                                    .unwrap_or_default(),
                            );

                            // Union of everything `calculate_blame_attributions` treats
                            // as a candidate offender -- CPU consumers, forkers, and
                            // short-job spawners -- not just the CPU consumer list.
                            // A pod that forks hard without being a top CPU consumer
                            // (a fork-storm scenario) is blamed live from
                            // `event.fork_counts` alone; leaving it out here would
                            // silently drop it from the captured episode entirely.
                            let mut offender_cpu: HashMap<String, (PodRef, f32)> = HashMap::new();
                            for c in &consumers {
                                let consumer_key = format!("{}/{}", c.namespace, c.pod);
                                if consumer_key == key {
                                    continue;
                                }
                                let entry = offender_cpu.entry(consumer_key).or_insert_with(|| {
                                    (
                                        PodRef {
                                            namespace: c.namespace.clone(),
                                            pod: c.pod.clone(),
                                        },
                                        0.0,
                                    )
                                });
                                entry.1 += c.cpu_percent;
                            }
                            let mut offender_keys: std::collections::BTreeSet<String> =
                                offender_cpu.keys().cloned().collect();
                            offender_keys
                                .extend(fork_counts.keys().filter(|k| **k != key).cloned());
                            offender_keys
                                .extend(short_job_counts.keys().filter(|k| **k != key).cloned());

                            let offenders: Vec<OffenderSignal> = offender_keys
                                .into_iter()
                                .map(|offender_key| {
                                    let (pod, cpu_percent) = offender_cpu
                                        .get(&offender_key)
                                        .cloned()
                                        .unwrap_or_else(|| {
                                            let (ns, pod_name) = offender_key
                                                .split_once('/')
                                                .unwrap_or(("", offender_key.as_str()));
                                            (
                                                PodRef {
                                                    namespace: ns.to_string(),
                                                    pod: pod_name.to_string(),
                                                },
                                                0.0,
                                            )
                                        });
                                    let onset_ms = self
                                        .consumer_busy_since
                                        .get(&offender_key)
                                        .map(|start| onset_offset_ms(now, *start));
                                    OffenderSignal {
                                        pod,
                                        onset_ms,
                                        cpu_percent,
                                        fork_count: fork_counts.get(&offender_key).copied(),
                                        short_job_count: short_job_counts
                                            .get(&offender_key)
                                            .copied(),
                                    }
                                })
                                .collect();

                            let candidates = build_candidate_windows(
                                PodRef {
                                    namespace: pod_delta.namespace.clone(),
                                    pod: pod_delta.pod_name.clone(),
                                },
                                pod_delta.owner_kind.clone(),
                                pod_delta.owner_name.clone(),
                                victim_pre_window,
                                Some(onset_offset_ms(now, start_time)),
                                1000,
                                &offenders,
                            );

                            let stall_event = StallEvent {
                                event_id: uuid::Uuid::new_v4().to_string(),
                                victim_pod: pod_delta.pod_name.clone(),
                                victim_namespace: pod_delta.namespace.clone(),
                                stall_delta_us: delta_stall,
                                timestamp: now,
                                concurrent_consumers: consumers.clone(),
                                memory_stall_delta_us: pod_delta.memory_delta_stall_us,
                                io_stall_delta_us: pod_delta.io_delta_stall_us,
                                memory_bytes: pod_delta.memory_bytes,
                                io_bytes: pod_delta.io_bytes,
                                memory_anon_bytes: pod_delta.memory_anon_bytes,
                                memory_file_bytes: pod_delta.memory_file_bytes,
                                memory_slab_bytes: pod_delta.memory_slab_bytes,
                                memory_pgmajfault_delta: pod_delta.memory_pgmajfault_delta,
                                workingset_refault_delta: pod_delta.workingset_refault_delta,
                                fork_counts,
                                short_job_counts,
                                candidates,
                            };

                            info!(
                                "[psi] StallEvent: {}/{} stalled {}us (mem={}us io={}us) with {} concurrent consumers",
                                stall_event.victim_namespace,
                                stall_event.victim_pod,
                                stall_event.stall_delta_us,
                                stall_event.memory_stall_delta_us,
                                stall_event.io_stall_delta_us,
                                consumers.len()
                            );

                            // Calculate blame attributions
                            let attributions = calculate_blame_attributions(&stall_event);

                            // Log top 3 attributions
                            for (i, attr) in attributions.iter().take(3).enumerate() {
                                info!(
                                    "[psi]   blame {}: {}/{} score={:.3} (cpu={:.2}, forks={}, short={})",
                                    i + 1,
                                    attr.offender_namespace,
                                    attr.offender_pod,
                                    attr.blame_score,
                                    attr.cpu_share,
                                    attr.fork_count,
                                    attr.short_job_count
                                );
                            }

                            // Structured events, alerts and metrics all
                            // leave through here.
                            self.sink.emit(&attributions);

                            if let Some(capture) = &self.episode_capture {
                                self.write_episode_capture(capture, &stall_event);
                            }

                            // Persist to database if available
                            if let Some(ref store) = self.incident_store {
                                for attr in &attributions {
                                    if let Err(e) = store.insert_stall_attribution(attr).await {
                                        warn!("[psi] Failed to persist attribution: {}", e);
                                    }
                                }
                            }

                            // Reset start time to avoid spamming every second after 15s
                            // Or keep it to report continuous pressure?
                            // Let's reset to require another 15s block, or just update start time?
                            // For now, let's just update start time to now to report every 15s if it continues.
                            self.pressure_start_time.insert(key.clone(), now);
                        }
                    } else {
                        // Pressure dropped, reset timer
                        self.pressure_start_time.remove(&key);
                    }
                } else {
                    // No pressure, reset timer
                    self.pressure_start_time.remove(&key);
                }
            }

            // Update offender-candidate onset bookkeeping. Gated on some pod
            // already being tracked for sustained pressure so a quiet node
            // never pays the cost of walking the live process map -- see the
            // `consumer_busy_since` field doc comment.
            if !self.pressure_start_time.is_empty() {
                let now = Instant::now();
                for c in self.get_concurrent_cpu_consumers() {
                    let key = format!("{}/{}", c.namespace, c.pod);
                    if c.cpu_percent >= CONSUMER_BUSY_CPU_PERCENT {
                        self.consumer_busy_since.entry(key).or_insert(now);
                    } else {
                        self.consumer_busy_since.remove(&key);
                    }
                }
            }

            iterations += 1;
            if self.max_iterations.is_some_and(|max| iterations >= max) {
                info!("[psi] scan limit reached, stopping PSI monitor");
                return;
            }

            sleep(Duration::from_secs(1)).await;
        }
    }

    /// Writes `stall_event` to `capture.output_dir` as a `VmCapture` episode,
    /// one JSON file per stall event named `<episode_id>.json`. Best-effort:
    /// a write failure is logged, never propagated, since the scan loop must
    /// keep attributing stalls whether or not the matrix's capture disk is
    /// healthy.
    fn write_episode_capture(&self, capture: &EpisodeCaptureConfig, stall_event: &StallEvent) {
        let episode = Episode::from_capture(stall_event, self.cell.clone(), None);
        let path = Path::new(&capture.output_dir).join(format!("{}.json", episode.episode_id));

        if let Err(e) = std::fs::create_dir_all(&capture.output_dir) {
            warn!(
                "[psi] failed to create episode capture dir {}: {e}",
                capture.output_dir
            );
            return;
        }

        match serde_json::to_vec_pretty(&episode) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(&path, bytes) {
                    warn!("[psi] failed to write captured episode {path:?}: {e}");
                }
            }
            Err(e) => warn!("[psi] failed to serialize captured episode: {e}"),
        }
    }

    fn get_concurrent_cpu_consumers(&self) -> Vec<CpuConsumer> {
        let live = self.context.get_live_map();
        let mut consumers: Vec<CpuConsumer> = Vec::new();

        for (proc, meta_opt) in live.values() {
            if let Some(cpu_pct) = proc.cpu_percent()
                && cpu_pct > 0.0
                && let Some(k8s_meta) = meta_opt
            {
                consumers.push(CpuConsumer {
                    pod: k8s_meta.pod_name.clone(),
                    namespace: k8s_meta.namespace.clone(),
                    cpu_percent: cpu_pct,
                });
            }
        }

        // Sort by CPU descending
        consumers.sort_by(|a, b| {
            b.cpu_percent
                .partial_cmp(&a.cpu_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        consumers
    }
}

/// Splits a victim's stall across the pods that plausibly caused it.
///
/// Free-standing because it is pure: it needs the stall event and nothing from
/// the monitor's own state, which also means it can be exercised without a
/// Kubernetes API to talk to.
pub fn calculate_blame_attributions(event: &StallEvent) -> Vec<BlameAttribution> {
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // A pod cannot be its own noisy neighbour. CPU-bound victims show up in
        // their own consumer list, and left in they would absorb most of their
        // own stall and alert about themselves.
        let victim_key = format!("{}/{}", event.victim_namespace, event.victim_pod);

        // Consumers arrive per process, so a pod with several busy processes
        // appears several times. Fold them together before scoring: comparing
        // one process's CPU against every process's total would under-credit
        // exactly the multi-process pods most likely to be causing the stall.
        let mut cpu_by_pod: HashMap<String, f32> = HashMap::new();
        for c in &event.concurrent_consumers {
            let key = format!("{}/{}", c.namespace, c.pod);
            if key == victim_key {
                continue;
            }
            *cpu_by_pod.entry(key).or_insert(0.0) += c.cpu_percent;
        }

        let total_cpu: f32 = cpu_by_pod.values().sum();

        // Collect all potential offenders (CPU consumers + forkers + short-job creators)
        let mut offenders: HashMap<String, (String, String)> = HashMap::new(); // key -> (ns, pod)

        for key in cpu_by_pod.keys() {
            if let Some((ns, pod)) = key.split_once('/') {
                offenders.insert(key.clone(), (ns.to_string(), pod.to_string()));
            }
        }
        for key in event.fork_counts.keys() {
            if let Some((ns, pod)) = key.split_once('/')
                && key != &victim_key
            {
                offenders.insert(key.clone(), (ns.to_string(), pod.to_string()));
            }
        }
        for key in event.short_job_counts.keys() {
            if let Some((ns, pod)) = key.split_once('/')
                && key != &victim_key
            {
                offenders.insert(key.clone(), (ns.to_string(), pod.to_string()));
            }
        }

        let mut attributions = Vec::new();

        for (key, (ns, pod)) in offenders {
            let cpu_percent = cpu_by_pod.get(&key).copied().unwrap_or(0.0);

            let cpu_share = if total_cpu > 0.0 {
                (cpu_percent / total_cpu) as f64
            } else {
                0.0
            };

            // Fork Count
            let fork_count = *event.fork_counts.get(&key).unwrap_or(&0);

            // Short Job Count
            let short_job_count = *event.short_job_counts.get(&key).unwrap_or(&0);

            // Blame Score Calculation
            // Weighted sum of normalized factors, each 0.0-1.0.
            // CPU is primary, but forks/short-jobs indicate "bad behavior".
            let raw_score = cpu_share + fork_score(fork_count) + short_job_score(short_job_count);

            // Weight by stall magnitude (in seconds)
            let blame_score = raw_score * (event.stall_delta_us as f64 / 1_000_000.0);

            if blame_score > 0.0 {
                attributions.push(BlameAttribution {
                    event_id: event.event_id.clone(),
                    victim_pod: event.victim_pod.clone(),
                    victim_namespace: event.victim_namespace.clone(),
                    offender_pod: pod,
                    offender_namespace: ns,
                    blame_score,
                    stall_us: event.stall_delta_us,
                    // Filled in below, once the total blame is known.
                    attributed_stall_us: 0,
                    timestamp,
                    cpu_share,
                    fork_count,
                    short_job_count,
                });
            }
        }

        // Split the observed stall proportionally to blame. Truncating each
        // share keeps the sum at or below the stall that actually occurred, so
        // the derived counters can never claim more stall than the kernel saw.
        let total_blame: f64 = attributions.iter().map(|a| a.blame_score).sum();
        if total_blame > 0.0 {
            for attr in &mut attributions {
                attr.attributed_stall_us =
                    ((attr.blame_score / total_blame) * event.stall_delta_us as f64) as u64;
            }
        }

        // Sort by blame score descending
        attributions.sort_by(|a, b| {
            b.blame_score
                .partial_cmp(&a.blame_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        attributions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_psi_file() {
        let content = "some avg10=0.00 avg60=0.00 avg300=0.00 total=123456\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=654321";
        let snapshot = parse_psi_file(content).unwrap();

        assert_eq!(snapshot.some_total, 123456);
        assert_eq!(snapshot.full_total, 654321);
    }

    #[test]
    fn test_parse_io_stat_sums_rbytes_and_wbytes_across_devices() {
        let content = "8:0 rbytes=1000 wbytes=2000 rios=1 wios=2 dbytes=0 dios=0\n\
                        8:16 rbytes=500 wbytes=250 rios=1 wios=1 dbytes=0 dios=0\n";
        assert_eq!(parse_io_stat(content), 1000 + 2000 + 500 + 250);
    }

    #[test]
    fn test_parse_io_stat_empty_is_zero() {
        assert_eq!(parse_io_stat(""), 0);
    }

    #[test]
    fn test_read_memory_current() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("memory.current");
        std::fs::write(&path, "12345\n").unwrap();
        assert_eq!(read_memory_current(&path), Some(12345));
    }

    #[test]
    fn test_read_memory_current_missing_file_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            read_memory_current(&tmp.path().join("memory.current")),
            None
        );
    }

    #[test]
    fn test_read_cgroup_signals_reads_all_four_files() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("memory.pressure"),
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=111\n\
             full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("io.pressure"),
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=222\n\
             full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        )
        .unwrap();
        std::fs::write(tmp.path().join("memory.current"), "4096\n").unwrap();
        std::fs::write(
            tmp.path().join("io.stat"),
            "8:0 rbytes=10 wbytes=20 rios=1 wios=1 dbytes=0 dios=0\n",
        )
        .unwrap();

        let signals = read_cgroup_signals(tmp.path());

        assert_eq!(signals.memory_pressure.unwrap().some_total, 111);
        assert_eq!(signals.io_pressure.unwrap().some_total, 222);
        assert_eq!(signals.memory_bytes, Some(4096));
        assert_eq!(signals.io_bytes, 30);
    }

    #[test]
    fn test_read_cgroup_signals_missing_files_read_as_none() {
        let tmp = tempfile::tempdir().unwrap();
        let signals = read_cgroup_signals(tmp.path());
        assert_eq!(signals, CgroupSignals::default());
    }

    #[test]
    fn test_extract_container_id() {
        let path = Path::new(
            "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123.slice/cri-containerd-e4063920952d766348421832d2df465324397166164478852332152342342342.scope/cpu.pressure",
        );
        let id = extract_container_id(path).unwrap();
        assert_eq!(
            id,
            "e4063920952d766348421832d2df465324397166164478852332152342342342"
        );
    }

    #[test]
    fn test_calculate_blame_attributions_with_forks() {
        let mut fork_counts = HashMap::new();
        fork_counts.insert("default/fork-bomb".to_string(), 200);

        let mut short_job_counts = HashMap::new();
        short_job_counts.insert("default/short-job-pod".to_string(), 100);

        let event = StallEvent {
            event_id: "evt-test".to_string(),
            victim_pod: "victim".to_string(),
            victim_namespace: "default".to_string(),
            stall_delta_us: 1_000_000, // 1 second stall
            timestamp: Instant::now(),
            concurrent_consumers: vec![
                CpuConsumer {
                    pod: "cpu-hog".to_string(),
                    namespace: "default".to_string(),
                    cpu_percent: 50.0,
                },
                CpuConsumer {
                    pod: "fork-bomb".to_string(),
                    namespace: "default".to_string(),
                    cpu_percent: 10.0,
                },
            ],
            memory_stall_delta_us: 0,
            io_stall_delta_us: 0,
            memory_bytes: 0,
            io_bytes: 0,
            memory_anon_bytes: None,
            memory_file_bytes: None,
            memory_slab_bytes: None,
            memory_pgmajfault_delta: None,
            workingset_refault_delta: None,
            candidates: vec![],
            fork_counts,
            short_job_counts,
        };

        let attributions = calculate_blame_attributions(&event);

        // We expect 3 offenders: cpu-hog, fork-bomb, short-job-pod
        assert_eq!(attributions.len(), 3);

        // Verify fork-bomb score
        // CPU share: 10/60 = 0.166
        // Fork score: 200/100 = 2.0 -> capped at 1.0
        // Total raw: 1.166
        // Blame: 1.166 * 1.0 = 1.166
        let fork_attr = attributions
            .iter()
            .find(|a| a.offender_pod == "fork-bomb")
            .unwrap();
        assert!(fork_attr.blame_score > 1.0);
        assert_eq!(fork_attr.fork_count, 200);

        // Verify short-job-pod score
        // CPU share: 0
        // Short job score: 100/50 = 2.0 -> capped at 1.0
        // Total raw: 1.0
        // Blame: 1.0 * 1.0 = 1.0
        let short_attr = attributions
            .iter()
            .find(|a| a.offender_pod == "short-job-pod")
            .unwrap();
        assert!((short_attr.blame_score - 1.0).abs() < 0.001);
        assert_eq!(short_attr.short_job_count, 100);
    }

    #[test]
    fn test_compute_history_capacity_exceeds_sustained_pressure_window() {
        // The floor keeps a 0- or short-configured duration from starving
        // history entirely -- a trigger that fires almost immediately still
        // needs somewhere to record baseline samples.
        assert_eq!(compute_history_capacity(0), 50);
        assert_eq!(compute_history_capacity(15), 50);
        // Above the floor, capacity tracks the configured duration so a
        // longer sustained-pressure window still leaves room for a
        // pre-pressure baseline instead of being entirely consumed by it.
        assert_eq!(compute_history_capacity(60), 140);
        assert!(compute_history_capacity(60) > 60);
    }

    #[test]
    fn test_onset_offset_ms_is_negative_elapsed_time() {
        let start = Instant::now();
        std::thread::sleep(Duration::from_millis(5));
        let now = Instant::now();
        let offset = onset_offset_ms(now, start);
        assert!(offset <= -5, "offset was {offset}, expected <= -5");
    }

    #[test]
    fn test_onset_offset_ms_is_zero_when_start_equals_now() {
        let now = Instant::now();
        assert_eq!(onset_offset_ms(now, now), 0);
    }

    #[test]
    fn test_build_candidate_windows_carries_victim_series_and_offender_onsets() {
        let victim = PodRef {
            namespace: "prod".to_string(),
            pod: "payment-api".to_string(),
        };
        let mut victim_pre_window = BTreeMap::new();
        victim_pre_window.insert("cpu_stall_us".to_string(), vec![0.0, 50_000.0, 120_000.0]);

        let offenders = vec![
            OffenderSignal {
                pod: PodRef {
                    namespace: "prod".to_string(),
                    pod: "image-resize-worker".to_string(),
                },
                onset_ms: Some(-9_000i64),
                cpu_percent: 87.5,
                fork_count: Some(12),
                short_job_count: None,
            },
            OffenderSignal {
                pod: PodRef {
                    namespace: "prod".to_string(),
                    pod: "sidecar-proxy".to_string(),
                },
                onset_ms: None,
                cpu_percent: 3.0,
                fork_count: None,
                short_job_count: None,
            },
        ];

        let candidates = build_candidate_windows(
            victim.clone(),
            Some("Deployment".to_string()),
            Some("payment-api".to_string()),
            victim_pre_window.clone(),
            Some(-15_000),
            1000,
            &offenders,
        );

        assert_eq!(candidates.len(), 3);

        let victim_window = &candidates[0];
        assert_eq!(victim_window.pod, victim);
        assert_eq!(victim_window.owner_kind.as_deref(), Some("Deployment"));
        assert_eq!(victim_window.pre_window, victim_pre_window);
        assert_eq!(victim_window.post_window, BTreeMap::new());
        assert_eq!(victim_window.first_deviation_offset_ms, Some(-15_000));

        let hog_window = &candidates[1];
        assert_eq!(hog_window.pod.pod, "image-resize-worker");
        assert_eq!(hog_window.pre_window.get("cpu_percent"), Some(&vec![87.5]));
        assert_eq!(hog_window.pre_window.get("fork_count"), Some(&vec![12.0]));
        assert_eq!(hog_window.first_deviation_offset_ms, Some(-9_000));

        let untracked_window = &candidates[2];
        assert_eq!(untracked_window.pod.pod, "sidecar-proxy");
        assert_eq!(
            untracked_window.pre_window.get("cpu_percent"),
            Some(&vec![3.0])
        );
        assert_eq!(untracked_window.first_deviation_offset_ms, None);
    }

    #[test]
    fn test_build_candidate_windows_caps_offenders_at_the_max() {
        let victim = PodRef {
            namespace: "prod".to_string(),
            pod: "payment-api".to_string(),
        };
        let offenders: Vec<OffenderSignal> = (0..MAX_CANDIDATE_OFFENDERS + 5)
            .map(|i| OffenderSignal {
                pod: PodRef {
                    namespace: "prod".to_string(),
                    pod: format!("neighbour-{i}"),
                },
                onset_ms: None,
                cpu_percent: 0.0,
                fork_count: None,
                short_job_count: None,
            })
            .collect();

        let candidates =
            build_candidate_windows(victim, None, None, BTreeMap::new(), None, 1000, &offenders);

        // +1 for the victim's own window.
        assert_eq!(candidates.len(), MAX_CANDIDATE_OFFENDERS + 1);
    }

    /// The invariant `episode.rs`'s module doc claims: an episode captured
    /// from a real `StallEvent` must replay in-process to the same
    /// attribution `calculate_blame_attributions` produced live. This is
    /// what would have caught offenders losing their `cpu_percent`/
    /// `fork_count`/`short_job_count` series on the way into `Episode`.
    #[test]
    fn a_captured_episode_replays_to_the_same_attribution_as_the_live_stall_event() {
        let victim = PodRef {
            namespace: "prod".to_string(),
            pod: "payment-api".to_string(),
        };
        let offender = PodRef {
            namespace: "prod".to_string(),
            pod: "fork-bomb".to_string(),
        };
        // Present in both the CPU-consumer list and fork_counts.
        let cpu_offender = PodRef {
            namespace: "prod".to_string(),
            pod: "cpu-hog".to_string(),
        };
        let mut fork_counts = HashMap::new();
        fork_counts.insert("prod/fork-bomb".to_string(), 200u64);
        let short_job_counts = HashMap::new();

        let candidates = build_candidate_windows(
            victim.clone(),
            Some("Deployment".to_string()),
            Some("payment-api".to_string()),
            BTreeMap::new(),
            Some(-5_000),
            1000,
            &[
                // Blamed live purely via fork_counts -- never appears as a
                // CPU consumer, so `cpu_percent` defaults to 0.0 here too.
                OffenderSignal {
                    pod: offender.clone(),
                    onset_ms: Some(-4_000),
                    cpu_percent: 0.0,
                    fork_count: Some(200),
                    short_job_count: None,
                },
                OffenderSignal {
                    pod: cpu_offender.clone(),
                    onset_ms: Some(-3_000),
                    cpu_percent: 60.0,
                    fork_count: None,
                    short_job_count: None,
                },
            ],
        );

        let stall_event = StallEvent {
            event_id: "live-event".to_string(),
            victim_pod: victim.pod.clone(),
            victim_namespace: victim.namespace.clone(),
            stall_delta_us: 1_500_000,
            timestamp: Instant::now(),
            concurrent_consumers: vec![CpuConsumer {
                pod: cpu_offender.pod.clone(),
                namespace: cpu_offender.namespace.clone(),
                cpu_percent: 60.0,
            }],
            fork_counts,
            short_job_counts,
            memory_stall_delta_us: 0,
            io_stall_delta_us: 0,
            memory_bytes: 0,
            io_bytes: 0,
            memory_anon_bytes: None,
            memory_file_bytes: None,
            memory_slab_bytes: None,
            memory_pgmajfault_delta: None,
            workingset_refault_delta: None,
            candidates,
        };

        let live_attributions = calculate_blame_attributions(&stall_event);
        assert_eq!(
            live_attributions.len(),
            2,
            "test setup should blame both the fork-only and CPU offenders"
        );

        let episode = crate::episode::Episode::from_capture(&stall_event, None, None);
        let replayed = episode.to_stall_event();
        let replayed_attributions = calculate_blame_attributions(&replayed);

        // Compare on everything but `timestamp` (wall-clock-at-call, not part
        // of the replay invariant), sorted by offender since both sides are
        // built by iterating a HashMap in unspecified order.
        let normalize = |attrs: &[BlameAttribution]| {
            let mut rows: Vec<_> = attrs
                .iter()
                .map(|a| {
                    (
                        a.offender_pod.clone(),
                        a.offender_namespace.clone(),
                        a.blame_score,
                        a.stall_us,
                        a.attributed_stall_us,
                        a.cpu_share,
                        a.fork_count,
                    )
                })
                .collect();
            rows.sort_by(|a, b| a.0.cmp(&b.0));
            rows
        };

        assert_eq!(
            normalize(&live_attributions),
            normalize(&replayed_attributions),
            "an episode captured from a live StallEvent must replay to the same attribution"
        );
    }

    #[test]
    fn test_parse_memory_stat_reads_curated_fields() {
        let content = "\
anon 61566976
file 4096
kernel_stack 36864
slab 1048576
pgfault 9001
pgmajfault 12
workingset_refault_anon 3
workingset_refault_file 7
";
        let stat = parse_memory_stat(content);
        assert_eq!(stat.anon_bytes, Some(61_566_976));
        assert_eq!(stat.file_bytes, Some(4_096));
        assert_eq!(stat.slab_bytes, Some(1_048_576));
        assert_eq!(stat.pgmajfault_total, Some(12));
        assert_eq!(stat.workingset_refault_anon_total, Some(3));
        assert_eq!(stat.workingset_refault_file_total, Some(7));
    }

    #[test]
    fn test_parse_memory_stat_leaves_missing_fields_none_not_zero() {
        // An older kernel's memory.stat lacking a curated field must not be
        // read as a real zero reading -- only the fields actually present
        // are populated.
        let stat = parse_memory_stat("anon 100\n");
        assert_eq!(stat.anon_bytes, Some(100));
        assert_eq!(stat.file_bytes, None);
        assert_eq!(stat.pgmajfault_total, None);
    }

    #[test]
    fn test_parse_memory_stat_skips_unparseable_lines() {
        let stat = parse_memory_stat("anon not_a_number\nfile 42\ngarbage line here\n");
        assert_eq!(stat.anon_bytes, None);
        assert_eq!(stat.file_bytes, Some(42));
    }

    #[test]
    fn test_accumulate_optional_sums_present_values_and_ignores_none() {
        let mut acc: Option<u64> = None;
        accumulate_optional(&mut acc, Some(10));
        accumulate_optional(&mut acc, None);
        accumulate_optional(&mut acc, Some(5));
        assert_eq!(acc, Some(15));
    }

    #[test]
    fn test_accumulate_optional_stays_none_when_nothing_ever_present() {
        let mut acc: Option<u64> = None;
        accumulate_optional(&mut acc, None);
        assert_eq!(acc, None);
    }
}
