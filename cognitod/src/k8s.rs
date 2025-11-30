use log::{debug, info, warn};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
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

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
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
}

impl K8sContext {
    pub fn new() -> Option<Arc<Self>> {
        let (api_url, token, ca_cert) = if let (Ok(url), Ok(t)) =
            (std::env::var("K8S_API_URL"), std::env::var("K8S_TOKEN"))
        {
            // Local/Manual mode
            (url, t, None)
        } else {
            // In-cluster mode
            let host = std::env::var("KUBERNETES_SERVICE_HOST").ok()?;
            let port = std::env::var("KUBERNETES_SERVICE_PORT").ok()?;
            let url = format!("https://{}:{}", host, port);
            let t = std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
                .ok()?;
            let ca = std::fs::read("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt").ok()?;
            (url, t, Some(ca))
        };

        // Try to get node name from env (downward API) or hostname
        let node_name = std::env::var("NODE_NAME")
            .ok()
            .or_else(|| std::env::var("HOSTNAME").ok())
            .unwrap_or_else(|| "localhost".to_string());

        let mut builder = Client::builder();
        if let Some(ca) = ca_cert {
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&ca).ok()?);
        } else {
            // In local mode, we might be using self-signed certs (like kind)
            builder = builder.danger_accept_invalid_certs(true);
        }

        let client = builder.build().ok()?;

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
        // Read /proc/<pid>/cgroup
        let content = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)).ok()?;

        // Parse cgroup to find container ID
        // Format: 0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/cri-containerd-<id>.scope
        // Or similar. We look for a 64-char hex string.

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
}
