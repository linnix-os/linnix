use anyhow::Result;
use log::{debug, info};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use walkdir::WalkDir;

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
    pub timestamp: std::time::Instant,
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

pub struct PsiMonitor {
    k8s_ctx: Arc<K8sContext>,
    history: HashMap<String, VecDeque<PsiSnapshot>>,
}

impl PsiMonitor {
    pub fn new(k8s_ctx: Arc<K8sContext>) -> Self {
        Self {
            k8s_ctx,
            history: HashMap::new(),
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
                    if let Some(prev) = hist.back() {
                        let delta_stall = snapshot.some_total.saturating_sub(prev.some_total);
                        if delta_stall > 0 {
                            info!(
                                "[psi] {}/{} delta_stall_us={}",
                                meta.namespace, meta.pod_name, delta_stall
                            );
                        }
                    }

                    // Add new snapshot to history
                    hist.push_back(snapshot);

                    // Keep only last N snapshots
                    if hist.len() > HISTORY_SIZE {
                        hist.pop_front();
                    }
                }
            }

            sleep(Duration::from_secs(1)).await;
        }
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
}
