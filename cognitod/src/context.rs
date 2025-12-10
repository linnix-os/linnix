use std::{collections::VecDeque, sync::Arc, sync::Mutex, time::Duration};

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::broadcast;

use crate::ProcessEvent;
use crate::k8s::{K8sContext, K8sMetadata};
use crate::types::SystemSnapshot;
use crate::utils::psi::PsiMetrics;

use sysinfo::{
    Disks,    // disk container (sysinfo ≥ 0.36)
    Networks, // network container
    Pid,      // typed PID wrapper
    System,   // system handle
};

pub type ProcessEntry = (ProcessEvent, Option<Arc<K8sMetadata>>);

pub type ProcessHistoryEntry = (u64, ProcessEvent, Option<Arc<K8sMetadata>>);

pub struct ContextStore {
    // Store timestamp, event, and optional cached metadata
    inner: Mutex<VecDeque<ProcessHistoryEntry>>,
    // Store live process state and cached metadata
    live: Mutex<HashMap<u32, ProcessEntry>>,
    max_age: Duration,
    max_len: usize,
    broadcaster: broadcast::Sender<ProcessEvent>,
    seq: AtomicU64,
    system_snapshot: Mutex<SystemSnapshot>,
    sys: Mutex<System>,
    k8s_ctx: Option<Arc<K8sContext>>,
}

#[derive(Clone, Debug)]
pub struct ProcessMemorySummary {
    pub pid: u32,
    pub comm: String,
    pub mem_percent: f32,
}

impl ContextStore {
    pub fn new(max_age: Duration, max_len: usize, k8s_ctx: Option<Arc<K8sContext>>) -> Self {
        let (broadcaster, _) = broadcast::channel(1024);
        Self {
            inner: Mutex::new(VecDeque::new()),
            live: Mutex::new(HashMap::new()),
            max_age,
            max_len,
            broadcaster,
            seq: AtomicU64::new(1),
            system_snapshot: Mutex::new(SystemSnapshot {
                timestamp: 0,
                cpu_percent: 0.0,
                mem_percent: 0.0,
                load_avg: [0.0, 0.0, 0.0],
                disk_read_bytes: 0,
                disk_write_bytes: 0,
                net_rx_bytes: 0,
                net_tx_bytes: 0,
                psi_cpu_some_avg10: 0.0,
                psi_memory_some_avg10: 0.0,
                psi_memory_full_avg10: 0.0,
                psi_io_some_avg10: 0.0,
                psi_io_full_avg10: 0.0,
            }),
            sys: Mutex::new(System::new_all()),
            k8s_ctx,
        }
    }

    pub fn get_live_map(&self) -> std::sync::MutexGuard<'_, HashMap<u32, ProcessEntry>> {
        self.live.lock().unwrap()
    }

    pub fn add(&self, mut event: ProcessEvent) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // Try to fetch or inherit metadata
        let mut metadata: Option<Arc<K8sMetadata>> = None;

        if let Some(ctx) = &self.k8s_ctx {
            match event.event_type {
                0 | 1 => {
                    // Exec or Fork: try to get fresh metadata
                    if let Some(meta) = ctx.get_metadata_for_pid(event.pid) {
                        metadata = Some(Arc::new(meta));
                    } else if event.event_type == 1 {
                        // Fork fallback: inherit parent's metadata if we can't find child's yet
                        // (race condition: process created but cgroup not yet populated)
                        let live = self.live.lock().unwrap();
                        if let Some((_, parent_meta)) = live.get(&event.ppid) {
                            metadata = parent_meta.clone();
                        }
                    }
                }
                2 => {
                    // Exit: check if we have it in live map
                    let live = self.live.lock().unwrap();
                    if let Some((_, meta)) = live.get(&event.pid) {
                        metadata = meta.clone();
                    }
                }
                _ => {
                    // Other events: try to lookup in live map first
                    let live = self.live.lock().unwrap();
                    if let Some((_, meta)) = live.get(&event.pid) {
                        metadata = meta.clone();
                    }
                }
            }
        }

        // Timestamp fix for Exit events: use start time from live map
        if event.event_type == 2 {
            let live = self.live.lock().unwrap();
            if let Some((proc, _)) = live.get(&event.pid) {
                // The Exit event currently has ts_ns = exit time.
                // We want ts_ns = start time (from live map) and exit_time_ns = exit time.
                event.exit_time_ns = event.ts_ns;
                event.ts_ns = proc.ts_ns;
            }
        }

        // If we still don't have metadata (e.g. late discovery), try one last check for non-exit
        if metadata.is_none()
            && event.event_type != 2
            && let Some(ctx) = &self.k8s_ctx
            && let Some(meta) = ctx.get_metadata_for_pid(event.pid)
        {
            metadata = Some(Arc::new(meta));
        }

        {
            let mut queue = self.inner.lock().unwrap();
            queue.push_back((now, event.clone(), metadata.clone()));
            Self::prune_locked(&mut queue, self.max_age, self.max_len);
        }

        {
            let mut live = self.get_live_map();
            match event.event_type {
                0 => {
                    // Exec
                    event.set_exit_time(None);
                    live.insert(event.pid, (event.clone(), metadata));
                }
                1 => {
                    // Fork
                    event.set_exit_time(None);
                    live.entry(event.pid)
                        .or_insert_with(|| (event.clone(), metadata));
                }
                2 => {
                    if let Some((proc, _)) = live.get_mut(&event.pid) {
                        proc.set_exit_time(Some(now));
                        proc.event_type = 2;
                    } else {
                        event.set_exit_time(Some(now));
                        live.insert(event.pid, (event.clone(), metadata));
                    }
                }
                _ => {}
            }

            live.retain(|_, (proc, _)| {
                proc.event_type != 2
                    || proc
                        .exit_time()
                        .is_none_or(|t| now.saturating_sub(t) < self.max_age.as_nanos() as u64)
            });
        }

        event.seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let _ = self.broadcaster.send(event);
    }

    pub fn get_recent(&self) -> Vec<ProcessEvent> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let queue = self.inner.lock().unwrap();
        queue
            .iter()
            .filter(|(t, _, _)| now - *t <= self.max_age.as_nanos() as u64)
            .map(|(_, e, _)| e.clone())
            .collect()
    }

    fn prune_locked(queue: &mut VecDeque<ProcessHistoryEntry>, max_age: Duration, max_len: usize) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        while queue.front().is_some_and(|(_, e, _)| {
            e.event_type == 2
                && e.exit_time()
                    .is_some_and(|et| now - et > max_age.as_nanos() as u64)
        }) {
            queue.pop_front();
        }
        while queue.len() > max_len {
            queue.pop_front();
        }
    }

    #[allow(dead_code)]
    pub fn snapshot(&self) -> Vec<ProcessEvent> {
        self.live_snapshot()
    }

    pub fn live_snapshot(&self) -> Vec<ProcessEvent> {
        let live = self.get_live_map();
        live.values().map(|(e, _)| e.clone()).collect()
    }

    pub fn get_process_by_pid(&self, pid: u32) -> Option<ProcessEvent> {
        let live = self.get_live_map();
        live.get(&pid).map(|(e, _)| e.clone())
    }

    pub fn broadcaster(&self) -> broadcast::Sender<ProcessEvent> {
        self.broadcaster.clone()
    }

    pub fn queue_depth(&self) -> usize {
        self.broadcaster.len()
    }

    pub fn top_rss_processes(&self, limit: usize) -> Vec<ProcessMemorySummary> {
        use std::cmp::Ordering;

        fn comm_to_string(comm: &[u8; 16]) -> String {
            let nul = comm.iter().position(|b| *b == 0).unwrap_or(comm.len());
            let slice = &comm[..nul];
            let text = String::from_utf8_lossy(slice).trim().to_string();
            if text.is_empty() {
                "unknown".to_string()
            } else {
                text
            }
        }

        let live = self.get_live_map();
        let mut entries: Vec<ProcessMemorySummary> = live
            .values()
            .filter_map(|(proc, _)| {
                let mem = proc.mem_percent()?;
                if mem <= 0.0 {
                    return None;
                }
                Some(ProcessMemorySummary {
                    pid: proc.pid,
                    comm: comm_to_string(&proc.comm),
                    mem_percent: mem,
                })
            })
            .collect();
        drop(live);

        entries.sort_by(|a, b| {
            b.mem_percent
                .partial_cmp(&a.mem_percent)
                .unwrap_or(Ordering::Equal)
        });
        if entries.len() > limit {
            entries.truncate(limit);
        }
        entries
    }

    pub fn top_cpu_processes(&self, limit: usize) -> Vec<ProcessMemorySummary> {
        use std::cmp::Ordering;

        fn comm_to_string(comm: &[u8; 16]) -> String {
            let nul = comm.iter().position(|b| *b == 0).unwrap_or(comm.len());
            let slice = &comm[..nul];
            let text = String::from_utf8_lossy(slice).trim().to_string();
            if text.is_empty() {
                "unknown".to_string()
            } else {
                text
            }
        }

        let live = self.get_live_map();
        let mut entries: Vec<ProcessMemorySummary> = live
            .values()
            .filter_map(|(proc, _)| {
                let cpu = proc.cpu_percent()?;
                if cpu <= 0.0 {
                    return None;
                }
                Some(ProcessMemorySummary {
                    pid: proc.pid,
                    comm: comm_to_string(&proc.comm),
                    mem_percent: cpu, // Reusing struct field for CPU
                })
            })
            .collect();
        drop(live);

        entries.sort_by(|a, b| {
            b.mem_percent
                .partial_cmp(&a.mem_percent)
                .unwrap_or(Ordering::Equal)
        });
        if entries.len() > limit {
            entries.truncate(limit);
        }
        entries
    }

    /// Refresh and store a point‑in‑time `SystemSnapshot`.
    pub fn update_system_snapshot(&self) {
        let mut sys = self.sys.lock().unwrap();
        // Only refresh global stats, not process list (expensive)
        sys.refresh_cpu_all();
        sys.refresh_memory();

        let cpu_percent = sys.global_cpu_usage();
        let mem_percent = if sys.total_memory() > 0 {
            (sys.used_memory() as f32 / sys.total_memory() as f32) * 100.0
        } else {
            0.0
        };

        let load = System::load_average();

        // Network counters
        let mut networks = Networks::new_with_refreshed_list();
        networks.refresh(true);
        let (mut rx, mut tx) = (0u64, 0u64);
        for data in networks.list().values() {
            rx += data.total_received();
            tx += data.total_transmitted();
        }

        // Disk counters
        let mut disks = Disks::new_with_refreshed_list();
        disks.refresh(true);
        let (mut read_bytes, mut write_bytes) = (0u64, 0u64);
        for disk in disks.list() {
            // Get the DiskUsage for the current disk
            let disk_usage = disk.usage(); // Access the usage method

            // Accumulate the bytes from DiskUsage
            read_bytes += disk_usage.read_bytes;
            write_bytes += disk_usage.written_bytes;
        }
        // PSI (Pressure Stall Information) - measures stall time, not just usage
        // Gracefully degrades to zeros if kernel doesn't support PSI (< 4.20)
        let psi = PsiMetrics::read().unwrap_or_default();

        let mut snapshot = self.system_snapshot.lock().unwrap();
        *snapshot = SystemSnapshot {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            cpu_percent,
            mem_percent,
            load_avg: [load.one as f32, load.five as f32, load.fifteen as f32],
            disk_read_bytes: read_bytes,
            disk_write_bytes: write_bytes,
            net_rx_bytes: rx,
            net_tx_bytes: tx,
            psi_cpu_some_avg10: psi.cpu_some_avg10,
            psi_memory_some_avg10: psi.memory_some_avg10,
            psi_memory_full_avg10: psi.memory_full_avg10,
            psi_io_some_avg10: psi.io_some_avg10,
            psi_io_full_avg10: psi.io_full_avg10,
        };
    }

    pub fn get_system_snapshot(&self) -> SystemSnapshot {
        self.system_snapshot.lock().unwrap().clone()
    }

    /// Update per‑process CPU/memory usage.
    pub fn update_process_stats(&self) {
        let mut sys = self.sys.lock().unwrap();
        sys.refresh_all();

        let mut live = self.get_live_map();
        for (event, _) in live.values_mut() {
            if let Some(proc) = sys.process(Pid::from_u32(event.pid)) {
                event.set_cpu_percent(Some(proc.cpu_usage()));
                let mem_pct = if sys.total_memory() > 0 {
                    Some((proc.memory() as f32 / sys.total_memory() as f32) * 100.0)
                } else {
                    Some(0.0)
                };
                event.set_mem_percent(mem_pct);
            }
        }
    }

    /// Get top CPU processes from the entire system (not just eBPF-tracked ones).
    /// This is a fallback for circuit breaker when no eBPF-tracked processes exist.
    pub fn top_cpu_processes_systemwide(&self, limit: usize) -> Vec<ProcessMemorySummary> {
        use std::cmp::Ordering;

        let sys = self.sys.lock().unwrap();
        let mut entries: Vec<ProcessMemorySummary> = sys
            .processes()
            .values()
            .filter_map(|proc| {
                let cpu = proc.cpu_usage();
                if cpu <= 0.0 {
                    return None;
                }
                Some(ProcessMemorySummary {
                    pid: proc.pid().as_u32(),
                    comm: proc.name().to_string_lossy().to_string(),
                    mem_percent: cpu,
                })
            })
            .collect();

        entries.sort_by(|a, b| {
            b.mem_percent
                .partial_cmp(&a.mem_percent)
                .unwrap_or(Ordering::Equal)
        });
        if entries.len() > limit {
            entries.truncate(limit);
        }
        entries
    }

    /// Get pod activity stats within a time window
    /// Get pod activity stats within a time window
    pub fn get_pod_activity_window(
        &self,
        window: Duration,
    ) -> (HashMap<String, u64>, HashMap<String, u64>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let cutoff = now.saturating_sub(window.as_nanos() as u64);

        let mut fork_counts: HashMap<String, u64> = HashMap::new();
        let mut short_job_counts: HashMap<String, u64> = HashMap::new();

        let queue = self.inner.lock().unwrap();

        // Scan history for relevant events
        for (ts, event, meta_opt) in queue.iter() {
            if *ts < cutoff {
                continue;
            }

            // Use the metadata cached at time of event
            if let Some(meta) = meta_opt {
                let key = format!("{}/{}", meta.namespace, meta.pod_name);

                // Count forks
                if event.event_type == 1 {
                    *fork_counts.entry(key.clone()).or_default() += 1;
                }

                // Count short jobs (exit event with lifetime < 1s)
                // Count short jobs (exit event with lifetime < 1s)
                if event.event_type == 2
                    && let Some(exit_time) = event.exit_time()
                {
                    let lifetime_ns = exit_time.saturating_sub(event.ts_ns);
                    if lifetime_ns < 1_000_000_000 {
                        *short_job_counts.entry(key).or_default() += 1;
                    }
                }
            }
        }

        (fork_counts, short_job_counts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PERCENT_MILLI_UNKNOWN, ProcessEvent, ProcessEventWire};
    use linnix_ai_ebpf_common::EventType;

    fn sample_event(pid: u32, ppid: u32, kind: EventType) -> ProcessEvent {
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"test");
        let base = ProcessEventWire {
            pid,
            ppid,
            uid: 0,
            gid: 0,
            event_type: kind as u32,
            ts_ns: 0,
            seq: 0,
            comm,
            exit_time_ns: 0,
            cpu_pct_milli: PERCENT_MILLI_UNKNOWN,
            mem_pct_milli: PERCENT_MILLI_UNKNOWN,
            data: 0,
            data2: 0,
            aux: 0,
            aux2: 0,
        };
        ProcessEvent::new(base)
    }

    #[test]
    fn exec_followed_by_exit_sets_exit_timestamp() {
        let store = ContextStore::new(Duration::from_secs(10), 128, None);
        let exec = sample_event(42, 1, EventType::Exec);
        store.add(exec);

        let live = store.live_snapshot();
        assert_eq!(live.len(), 1, "exec should register a live process");
        let proc = &live[0];
        assert_eq!(proc.event_type, EventType::Exec as u32);
        assert!(proc.exit_time().is_none());

        let exit = sample_event(42, 1, EventType::Exit);
        store.add(exit);

        let live = store.live_snapshot();
        assert_eq!(
            live.len(),
            1,
            "exit should retain the process for grace period"
        );
        let proc = &live[0];
        assert_eq!(proc.event_type, EventType::Exit as u32);
        assert!(proc.exit_time().is_some());
    }

    #[test]
    fn lone_exit_backfills_record() {
        let store = ContextStore::new(Duration::from_secs(10), 128, None);
        let exit_only = sample_event(99, 2, EventType::Exit);
        store.add(exit_only);

        let live = store.live_snapshot();
        assert_eq!(
            live.len(),
            1,
            "exit-only should still capture process record"
        );
        let proc = &live[0];
        assert_eq!(proc.pid, 99);
        assert_eq!(proc.event_type, EventType::Exit as u32);
        assert!(proc.exit_time().is_some());
    }
    #[test]
    fn exit_uses_start_time_from_exec() {
        let store = ContextStore::new(Duration::from_secs(10), 128, None);
        let mut exec = sample_event(100, 1, EventType::Exec);
        exec.ts_ns = 1_000_000_000; // Start at 1s
        store.add(exec);

        let mut exit = sample_event(100, 1, EventType::Exit);
        exit.ts_ns = 2_500_000_000; // Exit at 2.5s
        store.add(exit);

        // Check the history queue
        let recent = store.get_recent();
        // search for the exit event in history (should be the last one added)
        let exit_event = recent
            .iter()
            .find(|e| e.event_type == EventType::Exit as u32)
            .expect("Exit event not found");

        // The EXIT event should now have:
        // ts_ns = 1_000_000_000 (from Exec)
        // exit_time_ns = 2_500_000_000 (from Exit)
        assert_eq!(
            exit_event.ts_ns, 1_000_000_000,
            "Exit event should use start time"
        );
        assert_eq!(
            exit_event.exit_time_ns, 2_500_000_000,
            "Exit event should record exit time"
        );

        // Duration should be 1.5s
        let duration = exit_event.exit_time_ns - exit_event.ts_ns;
        assert_eq!(duration, 1_500_000_000);
    }
}
