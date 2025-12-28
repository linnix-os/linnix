//! GPU monitoring via NVIDIA Management Library (NVML)
//!
//! This module provides GPU visibility for Linnix, enabling monitoring of:
//! - GPU utilization (compute and memory)
//! - Memory usage (used/total)
//! - Temperature
//! - Power consumption
//! - Per-process GPU memory usage with K8s attribution

use anyhow::{Context, Result};
use log::{debug, info, warn};
use nvml_wrapper::Nvml;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;

use crate::k8s::K8sContext;

/// Information about a GPU device
#[derive(Debug, Clone, Serialize)]
pub struct GpuDeviceInfo {
    pub index: u32,
    pub name: String,
    pub uuid: String,
}

/// GPU utilization percentages
#[derive(Debug, Clone, Serialize)]
pub struct GpuUtilization {
    pub gpu_percent: u32,
    pub memory_percent: u32,
}

/// Information about a process using the GPU
#[derive(Debug, Clone, Serialize)]
pub struct GpuProcessInfo {
    pub pid: u32,
    pub used_gpu_memory_mb: u64,
    /// Pod name if running in Kubernetes
    pub pod_name: Option<String>,
    /// Namespace if running in Kubernetes
    pub namespace: Option<String>,
}

/// Snapshot of GPU state at a point in time
#[derive(Debug, Clone, Serialize)]
pub struct GpuSnapshot {
    pub device: GpuDeviceInfo,
    pub utilization: GpuUtilization,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub temperature_c: u32,
    pub power_usage_mw: u32,
    pub processes: Vec<GpuProcessInfo>,
    pub timestamp_ns: u64,
}

/// Shared GPU data accessible from API
pub type GpuData = Arc<RwLock<Vec<GpuSnapshot>>>;

/// GPU monitor that polls NVML for metrics
pub struct GpuMonitor {
    nvml: Nvml,
    k8s_ctx: Option<Arc<K8sContext>>,
    poll_interval: Duration,
    data: GpuData,
}

impl GpuMonitor {
    /// Create a new GPU monitor
    ///
    /// Returns an error if NVML initialization fails (no NVIDIA GPU or drivers)
    pub fn new(k8s_ctx: Option<Arc<K8sContext>>, poll_interval_ms: u64) -> Result<Self> {
        let nvml =
            Nvml::init().context("Failed to initialize NVML - NVIDIA GPU may not be present")?;

        let device_count = nvml
            .device_count()
            .context("Failed to get GPU device count")?;
        info!(
            "[gpu] NVML initialized, found {} GPU device(s)",
            device_count
        );

        Ok(Self {
            nvml,
            k8s_ctx,
            poll_interval: Duration::from_millis(poll_interval_ms),
            data: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Get a reference to the shared GPU data for API access
    pub fn data(&self) -> GpuData {
        Arc::clone(&self.data)
    }

    /// Run the GPU monitoring loop
    pub async fn run(self) {
        info!(
            "[gpu] Starting GPU monitor (poll interval: {:?})",
            self.poll_interval
        );

        loop {
            match self.collect_snapshots().await {
                Ok(snapshots) => {
                    let count = snapshots.len();
                    let mut data = self.data.write().await;
                    *data = snapshots;
                    debug!("[gpu] Collected {} GPU snapshot(s)", count);
                }
                Err(e) => {
                    warn!("[gpu] Failed to collect GPU metrics: {}", e);
                }
            }

            sleep(self.poll_interval).await;
        }
    }

    /// Collect current GPU snapshots for all devices
    async fn collect_snapshots(&self) -> Result<Vec<GpuSnapshot>> {
        let device_count = self.nvml.device_count()?;
        let mut snapshots = Vec::with_capacity(device_count as usize);
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // Build PID -> (pod_name, namespace) map for K8s attribution
        let k8s_pid_map = self.build_k8s_pid_map();

        for idx in 0..device_count {
            match self.collect_device_snapshot(idx, timestamp_ns, &k8s_pid_map) {
                Ok(snapshot) => snapshots.push(snapshot),
                Err(e) => {
                    warn!("[gpu] Failed to collect metrics for device {}: {}", idx, e);
                }
            }
        }

        Ok(snapshots)
    }

    /// Collect snapshot for a single GPU device
    fn collect_device_snapshot(
        &self,
        index: u32,
        timestamp_ns: u64,
        k8s_pid_map: &HashMap<u32, (String, String)>,
    ) -> Result<GpuSnapshot> {
        let device = self.nvml.device_by_index(index)?;

        // Device info
        let name = device.name().unwrap_or_else(|_| "Unknown".to_string());
        let uuid = device.uuid().unwrap_or_else(|_| "Unknown".to_string());

        // Utilization
        let utilization = device.utilization_rates().unwrap_or_else(|_| {
            nvml_wrapper::struct_wrappers::device::Utilization { gpu: 0, memory: 0 }
        });

        // Memory info
        let memory_info = device.memory_info()?;
        let memory_used_mb = memory_info.used / (1024 * 1024);
        let memory_total_mb = memory_info.total / (1024 * 1024);

        // Temperature (GPU core)
        let temperature_c = device
            .temperature(nvml_wrapper::enum_wrappers::device::TemperatureSensor::Gpu)
            .unwrap_or(0);

        // Power usage
        let power_usage_mw = device.power_usage().unwrap_or(0);

        // Running processes
        let processes = self.collect_process_info(&device, k8s_pid_map);

        Ok(GpuSnapshot {
            device: GpuDeviceInfo { index, name, uuid },
            utilization: GpuUtilization {
                gpu_percent: utilization.gpu,
                memory_percent: utilization.memory,
            },
            memory_used_mb,
            memory_total_mb,
            temperature_c,
            power_usage_mw,
            processes,
            timestamp_ns,
        })
    }

    /// Collect process information for a device
    fn collect_process_info(
        &self,
        device: &nvml_wrapper::Device,
        k8s_pid_map: &HashMap<u32, (String, String)>,
    ) -> Vec<GpuProcessInfo> {
        use nvml_wrapper::enums::device::UsedGpuMemory;

        // Try compute processes first, then graphics processes
        let compute_procs = device.running_compute_processes().unwrap_or_default();
        let graphics_procs = device.running_graphics_processes().unwrap_or_default();

        let mut processes = Vec::new();

        for proc in compute_procs.iter().chain(graphics_procs.iter()) {
            let (pod_name, namespace) = k8s_pid_map
                .get(&proc.pid)
                .map(|(p, n)| (Some(p.clone()), Some(n.clone())))
                .unwrap_or((None, None));

            // Extract memory from UsedGpuMemory enum
            let used_memory_bytes = match proc.used_gpu_memory {
                UsedGpuMemory::Used(bytes) => bytes,
                UsedGpuMemory::Unavailable => 0,
            };

            processes.push(GpuProcessInfo {
                pid: proc.pid,
                used_gpu_memory_mb: used_memory_bytes / (1024 * 1024),
                pod_name,
                namespace,
            });
        }

        processes
    }

    /// Build a map from PID to (pod_name, namespace) for K8s attribution
    fn build_k8s_pid_map(&self) -> HashMap<u32, (String, String)> {
        let mut pid_map = HashMap::new();

        if let Some(ref k8s_ctx) = self.k8s_ctx {
            // Get all container metadata and build PID -> pod mapping
            // This requires iterating through /proc to find container PIDs
            // For now, we'll use a simpler approach via the K8s context's existing mechanisms

            // The K8sContext stores container_id -> metadata mappings
            // We need to reverse-lookup: find what container a PID belongs to
            // This is done by reading /proc/<pid>/cgroup and extracting container ID

            if let Ok(entries) = std::fs::read_dir("/proc") {
                for entry in entries.filter_map(|e| e.ok()) {
                    if let Some(pid_str) = entry.file_name().to_str() {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            // Read cgroup to find container ID
                            let cgroup_path = format!("/proc/{}/cgroup", pid);
                            if let Ok(content) = std::fs::read_to_string(&cgroup_path) {
                                if let Some(container_id) = extract_container_id(&content) {
                                    // Look up K8s metadata for this container
                                    if let Some(meta) = k8s_ctx.get_metadata(&container_id) {
                                        pid_map.insert(
                                            pid,
                                            (meta.pod_name.clone(), meta.namespace.clone()),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        pid_map
    }
}

/// Extract container ID from cgroup file content
fn extract_container_id(content: &str) -> Option<String> {
    // cgroup format varies, but typically contains the container ID
    // Examples:
    // 0::/kubepods/burstable/pod123.../cri-containerd-abc123...
    // 1:name=systemd:/docker/abc123...

    for line in content.lines() {
        // Look for containerd/docker container IDs (64 hex chars)
        if let Some(idx) = line.find("cri-containerd-") {
            let start = idx + "cri-containerd-".len();
            let rest = &line[start..];
            // Extract up to .scope or end
            let end = rest.find('.').unwrap_or(rest.len()).min(64);
            if end >= 64 {
                return Some(rest[..64].to_string());
            }
        }

        if let Some(idx) = line.find("/docker/") {
            let start = idx + "/docker/".len();
            let rest = &line[start..];
            let end = rest.len().min(64);
            if end >= 64 {
                return Some(rest[..64].to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_snapshot_serialization() {
        let snapshot = GpuSnapshot {
            device: GpuDeviceInfo {
                index: 0,
                name: "NVIDIA Tesla T4".to_string(),
                uuid: "GPU-12345678-1234-1234-1234-123456789012".to_string(),
            },
            utilization: GpuUtilization {
                gpu_percent: 45,
                memory_percent: 30,
            },
            memory_used_mb: 4096,
            memory_total_mb: 16384,
            temperature_c: 55,
            power_usage_mw: 70000,
            processes: vec![GpuProcessInfo {
                pid: 12345,
                used_gpu_memory_mb: 2048,
                pod_name: Some("ml-training-pod".to_string()),
                namespace: Some("ml-workloads".to_string()),
            }],
            timestamp_ns: 1703529600000000000,
        };

        let json = serde_json::to_string(&snapshot).expect("Serialization failed");
        assert!(json.contains("NVIDIA Tesla T4"));
        assert!(json.contains("ml-training-pod"));
        assert!(json.contains("45")); // gpu_percent
    }

    #[test]
    fn test_extract_container_id_containerd() {
        let content = "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123.slice/cri-containerd-e4063920952d766348421832d2df465324397166164478852332152342342342.scope";
        let id = extract_container_id(content);
        assert_eq!(
            id,
            Some("e4063920952d766348421832d2df465324397166164478852332152342342342".to_string())
        );
    }

    #[test]
    fn test_extract_container_id_docker() {
        let content = "1:name=systemd:/docker/e4063920952d766348421832d2df465324397166164478852332152342342342";
        let id = extract_container_id(content);
        assert_eq!(
            id,
            Some("e4063920952d766348421832d2df465324397166164478852332152342342342".to_string())
        );
    }

    #[test]
    fn test_extract_container_id_no_match() {
        let content = "0::/user.slice/user-1000.slice/session-1.scope";
        let id = extract_container_id(content);
        assert!(id.is_none());
    }
}
