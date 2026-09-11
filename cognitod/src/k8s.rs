use log::{debug, info, trace, warn};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Critical,
    High,
    #[default]
    Medium,
    Low,
}

impl From<&str> for Priority {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            _ => Self::Medium,
        }
    }
}

#[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq)]
pub struct K8sMetadata {
    pub pod_name: String,
    pub namespace: String,
    pub container_name: String,
    pub owner_kind: Option<String>,
    pub owner_name: Option<String>,
    pub priority: Priority,
    pub slo_tier: Option<String>,
}

pub struct K8sContext {
    // Map from Container ID (stripped) to Metadata
    container_map: RwLock<HashMap<String, K8sMetadata>>,
    client: Client,
    api_url: String,
    token: String,
    pub node_name: String,
    /// Root under which `<pid>/cgroup` is read. Always `/proc` in
    /// production; tests point it at a fixture tree so metadata-resolution
    /// races can be exercised without a live `/proc`.
    proc_root: PathBuf,
}

/// Extracts a 64-char container id from `/proc/<pid>/cgroup` content, or
/// `None` when no line carries one.
///
/// Pure so the heuristic is unit-testable without a live `/proc`: cgroup v2
/// writes a single `0::/...` line, cgroup v1 writes one line per controller,
/// and both bury the id in the last path segment as
/// `cri-containerd-<id>.scope`, `docker-<id>.scope`, or a bare `<id>`.
fn container_id_from_cgroup_content(content: &str) -> Option<String> {
    for line in content.lines() {
        // Simple heuristic: look for last part that looks like a container ID
        if let Some(last_part) = line.split('/').next_back() {
            // Remove .scope suffix if present
            let clean = last_part.trim_end_matches(".scope");
            // Remove prefix like "cri-containerd-" or "docker-"
            let id = if let Some(idx) = clean.rfind('-') {
                &clean[idx + 1..]
            } else {
                clean
            };

            if id.len() == 64 {
                return Some(id.to_string());
            }
        }
    }
    None
}

enum K8sTlsConfig {
    SystemRoots,
    CustomCa(Vec<u8>),
    InsecureSkipVerify,
}

fn env_flag_is_true(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| flag_value_is_true(&value))
}

fn flag_value_is_true(value: &str) -> bool {
    value.eq_ignore_ascii_case("true")
}

fn manual_tls_config_from_env() -> Option<K8sTlsConfig> {
    if let Ok(ca_path) = std::env::var("K8S_CA_CERT_PATH") {
        std::fs::read(ca_path).ok().map(K8sTlsConfig::CustomCa)
    } else if env_flag_is_true("K8S_INSECURE_SKIP_VERIFY") {
        Some(K8sTlsConfig::InsecureSkipVerify)
    } else {
        Some(K8sTlsConfig::SystemRoots)
    }
}

impl K8sContext {
    pub fn new() -> Option<Arc<Self>> {
        let (api_url, token, tls_config) = if let (Ok(url), Ok(t)) =
            (std::env::var("K8S_API_URL"), std::env::var("K8S_TOKEN"))
        {
            // Local/Manual mode
            (url, t, manual_tls_config_from_env()?)
        } else {
            // In-cluster mode
            let host = std::env::var("KUBERNETES_SERVICE_HOST").ok()?;
            let port = std::env::var("KUBERNETES_SERVICE_PORT").ok()?;
            let url = format!("https://{}:{}", host, port);
            let t = std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
                .ok()?;
            let ca = std::fs::read("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt").ok()?;
            (url, t, K8sTlsConfig::CustomCa(ca))
        };

        // Try to get node name from env (downward API) or hostname
        let node_name = std::env::var("NODE_NAME")
            .ok()
            .or_else(|| std::env::var("HOSTNAME").ok())
            .unwrap_or_else(|| "localhost".to_string());

        let mut builder = Client::builder();
        match tls_config {
            K8sTlsConfig::SystemRoots => {}
            K8sTlsConfig::CustomCa(ca) => {
                builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&ca).ok()?);
            }
            K8sTlsConfig::InsecureSkipVerify => {
                warn!(
                    "[k8s] K8S_INSECURE_SKIP_VERIFY=true set; accepting invalid Kubernetes API certificates"
                );
                builder = builder.danger_accept_invalid_certs(true);
            }
        }

        let client = builder.build().ok()?;

        Some(Arc::new(Self {
            container_map: RwLock::new(HashMap::new()),
            client,
            api_url,
            token,
            node_name,
            proc_root: PathBuf::from("/proc"),
        }))
    }

    #[cfg(test)]
    /// Test seam: builds a context reading `<pid>/cgroup` from a fixture
    /// tree instead of the real `/proc`, so metadata-resolution races can
    /// be driven deterministically. Same-crate only; production always
    /// goes through `new()` and reads the real `/proc`.
    pub(crate) fn new_for_test(proc_root: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            container_map: RwLock::new(HashMap::new()),
            client: Client::new(),
            api_url: "http://127.0.0.1:1".to_string(),
            token: "test".to_string(),
            node_name: "test-node".to_string(),
            proc_root,
        })
    }

    pub fn start_watcher(self: Arc<Self>) {
        tokio::spawn(async move {
            info!("[k8s] starting pod watcher for node {}", self.node_name);
            let mut consecutive_failures: u32 = 0;
            loop {
                // Stringify the error immediately: `refresh_pods` fails with
                // `Box<dyn Error>` (not `Send`), which must not live across
                // the awaits below in this spawned future.
                match self.refresh_pods().await.map_err(|e| e.to_string()) {
                    Ok(()) => {
                        if consecutive_failures > 0 {
                            info!(
                                "[k8s] pod watcher recovered after {consecutive_failures} failed refresh(es)"
                            );
                        }
                        consecutive_failures = 0;
                        sleep(Duration::from_secs(30)).await;
                    }
                    Err(detail) => {
                        consecutive_failures += 1;
                        // Retry fast at first: a startup race (API not up yet
                        // when the daemon starts) used to leave container_map
                        // empty for a full 30s per failed attempt, which is
                        // exactly the window where early Fork/Exec events lose
                        // the metadata race. Back off to the normal 30s
                        // cadence only after repeated failures.
                        let backoff_secs = match consecutive_failures {
                            1 => 5,
                            2 => 10,
                            _ => 30,
                        };
                        warn!(
                            "[k8s] failed to refresh pods (failure #{consecutive_failures}): {detail}; retrying in {backoff_secs}s"
                        );
                        sleep(Duration::from_secs(backoff_secs)).await;
                    }
                }
            }
        });
    }

    async fn refresh_pods(&self) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!(
            "{}/api/v1/pods?fieldSelector=spec.nodeName={}",
            self.api_url, self.node_name
        );
        let resp = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(format!("API error: {}", resp.status()).into());
        }

        let pod_list: PodList = resp.json().await?;
        let mut new_map = HashMap::new();

        for pod in pod_list.items {
            let ns = pod.metadata.namespace.unwrap_or_default();
            let pod_name = pod.metadata.name.unwrap_or_default();

            let (owner_kind, owner_name) = if let Some(owners) = pod.metadata.owner_references {
                if let Some(owner) = owners.first() {
                    (Some(owner.kind.clone()), Some(owner.name.clone()))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            let (priority, slo_tier) = if let Some(labels) = &pod.metadata.labels {
                let p = labels
                    .get("linnix.dev/priority")
                    .map(|s| Priority::from(s.as_str()))
                    .unwrap_or_default();
                let s = labels.get("linnix.dev/slo-tier").cloned();
                (p, s)
            } else {
                (Priority::default(), None)
            };

            if let Some(statuses) = pod.status.container_statuses {
                for status in statuses {
                    if let Some(container_id) = status.container_id {
                        // container_id is usually "containerd://<id>" or "docker://<id>"
                        if let Some(stripped) = container_id.strip_prefix("containerd://") {
                            new_map.insert(
                                stripped.to_string(),
                                K8sMetadata {
                                    pod_name: pod_name.clone(),
                                    namespace: ns.clone(),
                                    container_name: status.name.clone(),
                                    owner_kind: owner_kind.clone(),
                                    owner_name: owner_name.clone(),
                                    priority: priority.clone(),
                                    slo_tier: slo_tier.clone(),
                                },
                            );
                        } else if let Some(stripped) = container_id.strip_prefix("docker://") {
                            new_map.insert(
                                stripped.to_string(),
                                K8sMetadata {
                                    pod_name: pod_name.clone(),
                                    namespace: ns.clone(),
                                    container_name: status.name.clone(),
                                    owner_kind: owner_kind.clone(),
                                    owner_name: owner_name.clone(),
                                    priority: priority.clone(),
                                    slo_tier: slo_tier.clone(),
                                },
                            );
                        }
                    }
                }
            }
        }

        {
            let mut map = self.container_map.write().unwrap();
            *map = new_map;
        }
        debug!(
            "[k8s] refreshed pod map, {} containers tracked",
            self.container_map.read().unwrap().len()
        );
        Ok(())
    }

    pub fn get_metadata_for_pid(&self, pid: u32) -> Option<K8sMetadata> {
        // Read <proc_root>/<pid>/cgroup (`proc_root` is /proc in production,
        // a fixture tree in tests).
        let path = self.proc_root.join(pid.to_string()).join("cgroup");
        let Ok(content) = std::fs::read_to_string(&path) else {
            // Expected for pids that have already exited (e.g. a fork-bomb
            // child that lived microseconds) -- not itself evidence of a
            // container-map race.
            trace!("[k8s] pid {pid} has no {path:?} (already exited?)");
            return None;
        };

        let id = container_id_from_cgroup_content(&content)?;

        let meta = self.get_metadata(&id);
        if meta.is_none() {
            // The pid resolved to a real container ID, but that ID isn't
            // (yet) in the watcher's container map -- the container-map race:
            // the pod's process started before the last poll picked up its
            // containerID.
            debug!(
                "[k8s] pid {pid} -> container {id} has no entry in container_map ({} entries tracked)",
                self.container_map.read().unwrap().len()
            );
        }
        meta
    }

    pub fn get_metadata(&self, container_id: &str) -> Option<K8sMetadata> {
        let map = self.container_map.read().unwrap();
        map.get(container_id).cloned()
    }

    /// Inserts container metadata directly, bypassing the API watcher.
    ///
    /// Lets callers that already know a container's identity — notably tests
    /// driving the collectors against a fixture cgroup tree — populate the
    /// cache without a reachable Kubernetes API.
    pub fn insert_metadata(&self, container_id: impl Into<String>, metadata: K8sMetadata) {
        let mut map = self.container_map.write().unwrap();
        map.insert(container_id.into(), metadata);
    }
}

#[derive(Deserialize)]
struct PodList {
    items: Vec<Pod>,
}

#[derive(Deserialize)]
struct Pod {
    metadata: PodMetadata,
    status: PodStatus,
}

#[derive(Deserialize)]
struct PodMetadata {
    name: Option<String>,
    namespace: Option<String>,
    #[serde(rename = "ownerReferences")]
    owner_references: Option<Vec<OwnerReference>>,
    labels: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
struct OwnerReference {
    kind: String,
    name: String,
}

#[derive(Deserialize)]
struct PodStatus {
    #[serde(rename = "containerStatuses")]
    container_statuses: Option<Vec<ContainerStatus>>,
}

#[derive(Deserialize)]
struct ContainerStatus {
    name: String,
    #[serde(rename = "containerID")]
    container_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_parsing() {
        assert_eq!(Priority::from("critical"), Priority::Critical);
        assert_eq!(Priority::from("High"), Priority::High);
        assert_eq!(Priority::from("MEDIUM"), Priority::Medium);
        assert_eq!(Priority::from("low"), Priority::Low);
        assert_eq!(Priority::from("unknown"), Priority::Medium);
    }

    #[test]
    fn test_priority_serialization() {
        assert_eq!(
            serde_json::to_string(&Priority::Critical).unwrap(),
            "\"critical\""
        );
        assert_eq!(serde_json::to_string(&Priority::High).unwrap(), "\"high\"");
        assert_eq!(
            serde_json::to_string(&Priority::Medium).unwrap(),
            "\"medium\""
        );
        assert_eq!(serde_json::to_string(&Priority::Low).unwrap(), "\"low\"");
    }

    #[test]
    fn insecure_skip_verify_requires_literal_true() {
        assert!(flag_value_is_true("true"));
        assert!(flag_value_is_true("TRUE"));
        assert!(!flag_value_is_true("1"));
        assert!(!flag_value_is_true("yes"));
        assert!(!flag_value_is_true(""));
    }

    #[test]
    fn container_id_parses_cgroup_v2_unified_line() {
        let id = "e".repeat(64);
        let content = format!(
            "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123abc.slice/cri-containerd-{id}.scope\n"
        );
        assert_eq!(container_id_from_cgroup_content(&content), Some(id));
    }

    #[test]
    fn container_id_parses_cgroup_v1_per_controller_lines() {
        let id = "f".repeat(64);
        let content = format!(
            "2:cpu,cpuacct:/kubepods.slice/kubepods-burstable.slice/docker-{id}.scope\n\
             1:name=systemd:/kubepods.slice/kubepods-burstable.slice/docker-{id}.scope\n"
        );
        assert_eq!(container_id_from_cgroup_content(&content), Some(id));
    }

    #[test]
    fn container_id_parses_bare_id_without_runtime_prefix() {
        let id = "a".repeat(64);
        let content = format!("0::/kubepods/{id}\n");
        assert_eq!(container_id_from_cgroup_content(&content), Some(id));
    }

    #[test]
    fn container_id_is_none_without_a_64_char_segment() {
        assert_eq!(container_id_from_cgroup_content("0::/\n"), None);
        assert_eq!(
            container_id_from_cgroup_content("0::/kubepods.slice/short-id.scope\n"),
            None
        );
        assert_eq!(container_id_from_cgroup_content(""), None);
    }

    #[test]
    fn new_for_test_reads_cgroup_from_the_fixture_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let id = "b".repeat(64);
        let pid_dir = tmp.path().join("4242");
        std::fs::create_dir(&pid_dir).unwrap();
        std::fs::write(
            pid_dir.join("cgroup"),
            format!("0::/kubepods.slice/cri-containerd-{id}.scope\n"),
        )
        .unwrap();

        let ctx = K8sContext::new_for_test(tmp.path().to_path_buf());
        // Map empty: the pid resolves to a container id, but nothing is known
        // about it yet -- the container-map race, deterministically.
        assert!(ctx.get_metadata_for_pid(4242).is_none());

        ctx.insert_metadata(
            id.clone(),
            K8sMetadata {
                pod_name: "victim-workload".to_string(),
                namespace: "default".to_string(),
                container_name: "app".to_string(),
                owner_kind: None,
                owner_name: None,
                priority: Priority::default(),
                slo_tier: None,
            },
        );
        let meta = ctx
            .get_metadata_for_pid(4242)
            .expect("map warmed after the race; resolution should heal");
        assert_eq!(meta.pod_name, "victim-workload");
        assert_eq!(meta.namespace, "default");
    }
}
