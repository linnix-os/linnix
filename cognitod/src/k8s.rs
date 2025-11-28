use log::{debug, info, warn};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct K8sMetadata {
    pub pod_name: String,
    pub namespace: String,
    pub container_name: String,
    pub owner_kind: Option<String>,
    pub owner_name: Option<String>,
}

pub struct K8sContext {
    // Map from Container ID (stripped) to Metadata
    container_map: RwLock<HashMap<String, K8sMetadata>>,
    client: Client,
    api_url: String,
    token: String,
    pub node_name: String,
}

impl K8sContext {
    pub fn new() -> Option<Arc<Self>> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST").ok()?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").ok()?;
        let api_url = format!("https://{}:{}", host, port);

        let token =
            std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token").ok()?;
        let ca_cert = std::fs::read("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt").ok()?;

        // Try to get node name from env (downward API) or hostname
        let node_name = std::env::var("NODE_NAME")
            .ok()
            .or_else(|| std::env::var("HOSTNAME").ok())
            .unwrap_or_else(|| "localhost".to_string());

        let client = Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(&ca_cert).ok()?)
            .build()
            .ok()?;

        Some(Arc::new(Self {
            container_map: RwLock::new(HashMap::new()),
            client,
            api_url,
            token,
            node_name,
        }))
    }

    pub fn start_watcher(self: Arc<Self>) {
        tokio::spawn(async move {
            info!("[k8s] starting pod watcher for node {}", self.node_name);
            loop {
                if let Err(e) = self.refresh_pods().await {
                    warn!("[k8s] failed to refresh pods: {}", e);
                }
                sleep(Duration::from_secs(30)).await;
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
        // Read /proc/<pid>/cgroup
        let content = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)).ok()?;

        // Parse cgroup to find container ID
        // Format: 0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/cri-containerd-<id>.scope
        // Or similar. We look for a 64-char hex string.

        for line in content.lines() {
            // Simple heuristic: look for last part that looks like a container ID
            if let Some(last_part) = line.split('/').last() {
                // Remove .scope suffix if present
                let clean = last_part.trim_end_matches(".scope");
                // Remove prefix like "cri-containerd-" or "docker-"
                let id = if let Some(idx) = clean.rfind('-') {
                    &clean[idx + 1..]
                } else {
                    clean
                };

                if id.len() == 64 {
                    let map = self.container_map.read().unwrap();
                    if let Some(meta) = map.get(id) {
                        return Some(meta.clone());
                    }
                }
            }
        }
        None
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
