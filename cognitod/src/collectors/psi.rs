use anyhow::Result;
use log::{debug, info};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use walkdir::WalkDir;

use crate::context::ContextStore;
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

/// GPU process contributing to resource pressure
#[derive(Debug, Clone)]
pub struct GpuConsumer {
    pub pod: String,
    pub namespace: String,
    pub gpu_memory_mb: u64,
    pub gpu_index: u32,
}

#[derive(Debug, Clone)]
pub struct StallEvent {
    pub victim_pod: String,
    pub victim_namespace: String,
    pub stall_delta_us: u64,
    pub timestamp: Instant,
    pub concurrent_consumers: Vec<CpuConsumer>,
    pub fork_counts: HashMap<String, u64>,
    pub short_job_counts: HashMap<String, u64>,
    /// GPU processes active during the stall
    pub gpu_consumers: Vec<GpuConsumer>,
}

#[derive(Debug, Clone)]
pub struct BlameAttribution {
    pub victim_pod: String,
    pub victim_namespace: String,
    pub offender_pod: String,
    pub offender_namespace: String,
    pub blame_score: f64,
    pub stall_us: u64,
    pub timestamp: u64,
    pub cpu_share: f64,
    pub fork_count: u64,
    pub short_job_count: u64,
    /// GPU memory used by offender during stall (MB)
    pub gpu_memory_mb: u64,
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

const HISTORY_SIZE: usize = 10;
const STALL_THRESHOLD_US: u64 = 100_000; // 100ms threshold for significant stall

pub struct PsiMonitor {
    k8s_ctx: Arc<K8sContext>,
    context: Arc<ContextStore>,
    incident_store: Option<Arc<crate::incidents::IncidentStore>>,
    history: HashMap<String, VecDeque<PsiSnapshot>>,
    pressure_start_time: HashMap<String, Instant>,
    sustained_pressure_duration: Duration,
}

impl PsiMonitor {
    pub fn new(
        k8s_ctx: Arc<K8sContext>,
        context: Arc<ContextStore>,
        incident_store: Option<Arc<crate::incidents::IncidentStore>>,
        sustained_pressure_seconds: u64,
    ) -> Self {
        Self {
            k8s_ctx,
            context,
            incident_store,
            history: HashMap::new(),
            pressure_start_time: HashMap::new(),
            sustained_pressure_duration: Duration::from_secs(sustained_pressure_seconds),
        }
    }

    pub async fn run(mut self) {
        info!("[psi] starting PSI monitor");
        let base_path = Path::new("/sys/fs/cgroup");

        loop {
            let psi_files = find_psi_files(base_path);
            debug!("[psi] scanning {} cgroups", psi_files.len());

            for path in psi_files {
                if let Some(container_id) = extract_container_id(&path)
                    && let Some(meta) = self.k8s_ctx.get_metadata(&container_id)
                    && let Ok(content) = std::fs::read_to_string(&path)
                    && let Ok(snapshot) = parse_psi_file(&content)
                {
                    let key = format!("{}/{}", meta.namespace, meta.pod_name);

                    // Get or create history for this pod
                    let hist = self.history.entry(key.clone()).or_default();

                    // Calculate delta if we have previous snapshot
                    let delta_stall_opt = hist
                        .back()
                        .map(|prev| snapshot.some_total.saturating_sub(prev.some_total));

                    // Add new snapshot to history
                    hist.push_back(snapshot);

                    // Keep only last N snapshots
                    if hist.len() > HISTORY_SIZE {
                        hist.pop_front();
                    }

                    // Process delta outside of history borrow
                    if let Some(delta_stall) = delta_stall_opt
                        && delta_stall > 0
                    {
                        info!(
                            "[psi] {}/{} delta_stall_us={}",
                            meta.namespace, meta.pod_name, delta_stall
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
                                    meta.namespace, meta.pod_name, self.sustained_pressure_duration
                                );

                                // Collect metrics
                                let consumers = self.get_concurrent_cpu_consumers();
                                let (fork_counts, short_job_counts) = self
                                    .context
                                    .get_pod_activity_window(self.sustained_pressure_duration);

                                let stall_event = StallEvent {
                                    victim_pod: meta.pod_name.clone(),
                                    victim_namespace: meta.namespace.clone(),
                                    stall_delta_us: delta_stall,
                                    timestamp: now,
                                    concurrent_consumers: consumers.clone(),
                                    fork_counts,
                                    short_job_counts,
                                    gpu_consumers: Vec::new(), // Phase 2: will be populated when GPU data available
                                };

                                info!(
                                    "[psi] StallEvent: {}/{} stalled {}us with {} concurrent consumers",
                                    stall_event.victim_namespace,
                                    stall_event.victim_pod,
                                    stall_event.stall_delta_us,
                                    consumers.len()
                                );

                                // Calculate blame attributions
                                let attributions = self.calculate_blame_attributions(&stall_event);

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

                                // Persist to database if available
                                if let Some(ref store) = self.incident_store {
                                    for attr in &attributions {
                                        if let Err(e) = store
                                            .insert_stall_attribution(
                                                &attr.victim_pod,
                                                &attr.victim_namespace,
                                                &attr.offender_pod,
                                                &attr.offender_namespace,
                                                attr.stall_us,
                                                attr.blame_score,
                                                attr.timestamp,
                                                attr.cpu_share,
                                                attr.fork_count,
                                                attr.short_job_count,
                                                attr.gpu_memory_mb,
                                            )
                                            .await
                                        {
                                            debug!("[psi] Failed to persist attribution: {}", e);
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
            }

            sleep(Duration::from_secs(1)).await;
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

    fn calculate_blame_attributions(&self, event: &StallEvent) -> Vec<BlameAttribution> {
        let total_cpu: f32 = event
            .concurrent_consumers
            .iter()
            .map(|c| c.cpu_percent)
            .sum();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Collect all potential offenders (CPU consumers + forkers + short-job creators)
        let mut offenders: HashMap<String, (String, String)> = HashMap::new(); // key -> (ns, pod)

        for c in &event.concurrent_consumers {
            let key = format!("{}/{}", c.namespace, c.pod);
            offenders.insert(key, (c.namespace.clone(), c.pod.clone()));
        }
        for key in event.fork_counts.keys() {
            if let Some((ns, pod)) = key.split_once('/') {
                offenders.insert(key.clone(), (ns.to_string(), pod.to_string()));
            }
        }
        for key in event.short_job_counts.keys() {
            if let Some((ns, pod)) = key.split_once('/') {
                offenders.insert(key.clone(), (ns.to_string(), pod.to_string()));
            }
        }

        let mut attributions = Vec::new();

        for (key, (ns, pod)) in offenders {
            // CPU Share
            let cpu_percent = event
                .concurrent_consumers
                .iter()
                .find(|c| c.namespace == ns && c.pod == pod)
                .map(|c| c.cpu_percent)
                .unwrap_or(0.0);

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
            // Weighted sum of normalized factors.
            // CPU is primary, but forks/short-jobs indicate "bad behavior"
            // Heuristic:
            // - CPU share is 0.0-1.0
            // - Forks: >100/15s is high. Normalize by 100?
            // - Short Jobs: >50/15s is high. Normalize by 50?

            let fork_score = (fork_count as f64 / 100.0).min(1.0);
            let short_job_score = (short_job_count as f64 / 50.0).min(1.0);

            // Composite score
            let raw_score = cpu_share + fork_score + short_job_score;

            // Weight by stall magnitude (in seconds)
            let blame_score = raw_score * (event.stall_delta_us as f64 / 1_000_000.0);

            if blame_score > 0.0 {
                // Lookup GPU memory for this offender
                let gpu_memory_mb = event
                    .gpu_consumers
                    .iter()
                    .filter(|g| g.pod == pod && g.namespace == ns)
                    .map(|g| g.gpu_memory_mb)
                    .sum();

                attributions.push(BlameAttribution {
                    victim_pod: event.victim_pod.clone(),
                    victim_namespace: event.victim_namespace.clone(),
                    offender_pod: pod,
                    offender_namespace: ns,
                    blame_score,
                    stall_us: event.stall_delta_us,
                    timestamp,
                    cpu_share,
                    fork_count,
                    short_job_count,
                    gpu_memory_mb,
                });
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
        // Set env vars to force K8sContext creation
        unsafe {
            std::env::set_var("K8S_API_URL", "http://localhost:8001");
            std::env::set_var("K8S_TOKEN", "dummy");
        }

        let k8s_ctx = K8sContext::new().expect("Failed to create K8sContext");
        let monitor = PsiMonitor::new(
            k8s_ctx.clone(),
            Arc::new(ContextStore::new(
                Duration::from_secs(60),
                1000,
                Some(k8s_ctx),
            )),
            None,
            15,
        );

        let mut fork_counts = HashMap::new();
        fork_counts.insert("default/fork-bomb".to_string(), 200);

        let mut short_job_counts = HashMap::new();
        short_job_counts.insert("default/short-job-pod".to_string(), 100);

        let event = StallEvent {
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
            fork_counts,
            short_job_counts,
            gpu_consumers: Vec::new(),
        };

        let attributions = monitor.calculate_blame_attributions(&event);

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
}
