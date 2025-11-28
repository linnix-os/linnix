use serde::{Deserialize, Serialize};
use crate::k8s::K8sMetadata;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum InsightReason {
    ForkStorm,
    ShortJobFlood,
    RunawayTree,
    CpuSpin,
    IoSaturation,
    OomRisk,
    Normal,
}

impl InsightReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ForkStorm => "fork_storm",
            Self::ShortJobFlood => "short_job_flood",
            Self::RunawayTree => "runaway_tree",
            Self::CpuSpin => "cpu_spin",
            Self::IoSaturation => "io_saturation",
            Self::OomRisk => "oom_risk",
            Self::Normal => "normal",
        }
    }

    pub fn triggers_alert(&self) -> bool {
        !matches!(self, Self::Normal)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodContribution {
    pub namespace: String,
    pub pod: String,
    pub cpu_usage: f32,
    pub psi_contribution: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Insight {
    pub reason_code: InsightReason,
    pub summary: String,
    pub confidence: f32,
    pub id: String,
    pub top_pods: Vec<PodContribution>,
    pub suggested_next_step: String,
    // Compat fields
    pub primary_process: Option<String>,
    pub k8s: Option<K8sMetadata>,
}

impl Insight {
    pub fn redact(&mut self) {
        use sha2::{Sha256, Digest};
        
        let hash = |s: &str| -> String {
            let mut hasher = Sha256::new();
            hasher.update(s);
            format!("{:x}", hasher.finalize())[..8].to_string()
        };

        for pod in &mut self.top_pods {
            pod.namespace = hash(&pod.namespace);
            pod.pod = hash(&pod.pod);
        }

        if let Some(k8s) = &mut self.k8s {
            k8s.namespace = hash(&k8s.namespace);
            k8s.pod_name = hash(&k8s.pod_name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_hashes_pod_names() {
        let mut insight = Insight {
            reason_code: InsightReason::ForkStorm,
            summary: "Test".to_string(),
            confidence: 0.9,
            id: "test-123".to_string(),
            top_pods: vec![PodContribution {
                namespace: "production".to_string(),
                pod: "my-app-xyz".to_string(),
                cpu_usage: 80.0,
                psi_contribution: 10.0,
            }],
            suggested_next_step: "Check".to_string(),
            primary_process: None,
            k8s: None,
        };

        insight.redact();

        assert_ne!(insight.top_pods[0].namespace, "production");
        assert_ne!(insight.top_pods[0].pod, "my-app-xyz");
        assert_eq!(insight.top_pods[0].namespace.len(), 8);
    }

    #[test]
    fn redact_is_deterministic() {
        let mut i1 = Insight {
            reason_code: InsightReason::Normal,
            summary: "T".to_string(),
            confidence: 0.5,
            id: "1".to_string(),
            top_pods: vec![PodContribution {
                namespace: "default".to_string(),
                pod: "test-pod".to_string(),
                cpu_usage: 50.0,
                psi_contribution: 5.0,
            }],
            suggested_next_step: "Wait".to_string(),
            primary_process: None,
            k8s: None,
        };

        let mut i2 = i1.clone();
        i1.redact();
        i2.redact();

        assert_eq!(i1.top_pods[0].namespace, i2.top_pods[0].namespace);
    }
}
