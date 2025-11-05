use std::{collections::VecDeque, sync::Mutex, time::Duration};

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::broadcast;

use crate::ProcessEvent;
use crate::types::SystemSnapshot;

use sysinfo::{
    Disks,    // disk container (sysinfo ≥ 0.36)
    Networks, // network container
    Pid,      // typed PID wrapper
    System,   // system handle
};

pub struct ContextStore {
    inner: Mutex<VecDeque<(u64, ProcessEvent)>>,
    live: Mutex<HashMap<u32, ProcessEvent>>,
    max_age: Duration,
    max_len: usize,
    broadcaster: broadcast::Sender<ProcessEvent>,
    seq: AtomicU64,
    system_snapshot: Mutex<SystemSnapshot>,
}

#[derive(Clone, Debug)]
pub struct ProcessMemorySummary {
    pub pid: u32,
    pub comm: String,
    pub mem_percent: f32,
}

impl ContextStore {
    pub fn new(max_age: Duration, max_len: usize) -> Self {
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
            }),
        }
    }

    pub fn get_live_map(&self) -> std::sync::MutexGuard<'_, HashMap<u32, ProcessEvent>> {
        self.live.lock().unwrap()
    }

    pub fn add(&self, mut event: ProcessEvent) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        {
            let mut queue = self.inner.lock().unwrap();
            queue.push_back((now, event.clone()));
            Self::prune_locked(&mut queue, self.max_age, self.max_len);
        }

        {
            let mut live = self.get_live_map();
            match event.event_type {
                0 => {
                    // Exec: enrich tags before inserting
                    if event.tags.is_empty()
                        && let Some(mut tags) = derive_cgroup_tags(event.pid) {
                            event.tags.append(&mut tags);
                        }
                    event.set_exit_time(None);
                    live.insert(event.pid, event.clone());
                }
                1 => {
                    event.set_exit_time(None);
                    // Fork: only compute tags if we're inserting this PID for the first time
                    if !live.contains_key(&event.pid) && event.tags.is_empty()
                        && let Some(mut tags) = derive_cgroup_tags(event.pid) {
                            event.tags.append(&mut tags);
                        }
                    live.entry(event.pid).or_insert_with(|| event.clone());
                }
                2 => {
                    if let Some(proc) = live.get_mut(&event.pid) {
                        proc.set_exit_time(Some(now));
                        proc.event_type = 2;
                    } else {
                        event.set_exit_time(Some(now));
                        live.insert(event.pid, event.clone());
                    }
                }
                _ => {}
            }

            live.retain(|_, proc| {
                proc.event_type != 2
                    || proc
                        .exit_time()
                        .is_none_or(|t| now - t < self.max_age.as_nanos() as u64)
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
            .filter(|(t, _)| now - *t <= self.max_age.as_nanos() as u64)
            .map(|(_, e)| e.clone())
            .collect()
    }

    fn prune_locked(queue: &mut VecDeque<(u64, ProcessEvent)>, max_age: Duration, max_len: usize) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        while queue.front().is_some_and(|(_, e)| {
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
        live.values().cloned().collect()
    }

    pub fn get_process_by_pid(&self, pid: u32) -> Option<ProcessEvent> {
        let live = self.get_live_map();
        live.get(&pid).cloned()
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
            .filter_map(|proc| {
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
            .filter_map(|proc| {
                let cpu = proc.cpu_percent()?;
                if cpu <= 0.0 {
                    return None;
                }
                Some(ProcessMemorySummary {
                    pid: proc.pid,
                    comm: comm_to_string(&proc.comm),
                    mem_percent: cpu,  // Reusing struct field for CPU
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
        let mut sys = System::new_all();
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
        };
    }

    pub fn get_system_snapshot(&self) -> SystemSnapshot {
        self.system_snapshot.lock().unwrap().clone()
    }

    /// Update per‑process CPU/memory usage.
    pub fn update_process_stats(&self) {
        let mut sys = System::new_all();
        sys.refresh_all();

        let mut live = self.get_live_map();
        for event in live.values_mut() {
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

}

/// Extract lightweight container/cgroup tags for a PID from /proc/<pid>/cgroup.
/// Best-effort and zero-cost on failure; returns Some(nonempty) on success.
fn derive_cgroup_tags(pid: u32) -> Option<Vec<String>> {
    use std::fs;
    let path = format!("/proc/{pid}/cgroup");
    let Ok(contents) = fs::read_to_string(&path) else { return None; };
    let mut tags: Vec<String> = Vec::new();

    // Collect all cgroup path components; format: "hier:id:path"
    for line in contents.lines() {
        let path_part = line.split(':').nth(2).unwrap_or("");
        if path_part.is_empty() { continue; }
        for comp in path_part.split('/') {
            if comp.is_empty() { continue; }
            let lc = comp.to_lowercase();
            // Systemd slices
            if lc.ends_with(".slice") {
                tags.push(format!("slice:{}", comp));
            }
            // Docker/systemd scope container IDs: docker-<id>.scope or cri-containerd-<id>.scope
            for pref in ["docker-", "crio-", "cri-containerd-"] {
                if lc.starts_with(pref) && lc.ends_with(".scope") {
                    let id = comp.trim_start_matches(pref).trim_end_matches(".scope");
                    let short = id.chars().take(12).collect::<String>();
                    if short.chars().all(|c| c.is_ascii_hexdigit()) && short.len() >= 8 {
                        tags.push(format!("container:{}", short));
                    }
                }
            }
            // containerd v2 layout: .../k8s.io/<container-id>
            if lc.len() >= 12 && lc.chars().take(12).all(|c| c.is_ascii_hexdigit()) {
                let short = lc.chars().take(12).collect::<String>();
                tags.push(format!("container:{}", short));
            }
            // Kubernetes pod UID markers: "pod<uid>" variants
            if let Some(idx) = lc.find("pod") {
                let uid = &lc[idx+3..];
                let uid_short = uid.chars().filter(|c| c.is_ascii_hexdigit() || *c == '-').take(20).collect::<String>();
                if !uid_short.is_empty() {
                    tags.push(format!("k8s_pod:{}", uid_short));
                }
            }
        }
        // Remember last component as generic cgroup tag
        if let Some(last) = path_part.rsplit('/').find(|c| !c.is_empty()) {
            tags.push(format!("cgroup:{}", last));
        }
    }

    // De-duplicate while preserving order
    if tags.is_empty() { return None; }
    let mut seen = std::collections::HashSet::new();
    tags.retain(|t| seen.insert(t.clone()));
    Some(tags)
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
        let store = ContextStore::new(Duration::from_secs(10), 128);
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
        let store = ContextStore::new(Duration::from_secs(10), 128);
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
}
