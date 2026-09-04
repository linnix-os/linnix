use crate::k8s::K8sMetadata;
use serde::{Deserialize, Serialize};

/// The single reason-code vocabulary shared by insights (LLM-facing
/// diagnoses) and stall attributions (the heuristic blame score's dominant
/// term). Before this merge the two lived as separate enums --
/// `InsightReason` (7 variants) and `attribution::BlameReason` (3 variants,
/// now folded in as `ForkStorm`, `ShortJobChurn`, `NoisyNeighbor`) -- which
/// meant reason-code accuracy could never be scored against a single ground
/// truth. See datasets/schema/insight.schema.json (v0.2) for the wire
/// contract this enum backs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InsightReason {
    ForkStorm,
    ShortJobChurn,
    RunawayTree,
    CpuSpin,
    /// A pod's stall is dominated by another pod's CPU share rather than by
    /// forks or short-job churn. Formerly `BlameReason::HighCpuContention`
    /// ("high_cpu_contention"); renamed on the v0.2 schema bump since this is
    /// the failure library's "CPU noisy neighbour" scenario by another name.
    NoisyNeighbor,
    IoSaturation,
    OomRisk,
    /// cgroup `cpu.max` quota throttling the workload rather than a
    /// neighbour stealing its CPU -- distinct from `NoisyNeighbor` because
    /// the fix is raising the pod's own limit, not evicting anyone else.
    CpuThrottled,
    /// Ephemeral-storage / disk-pressure eviction path (unbounded log
    /// writes, etc.), distinct from `IoSaturation`'s throughput contention.
    DiskPressure,
    /// Retransmits / connection exhaustion / socket saturation.
    NetworkSaturation,
    /// A rollout raised resource usage or introduced a regression; the
    /// culprit is a deployment revision, not a neighbouring pod.
    DeploymentRegression,
    Normal,
}

impl InsightReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ForkStorm => "fork_storm",
            Self::ShortJobChurn => "short_job_churn",
            Self::RunawayTree => "runaway_tree",
            Self::CpuSpin => "cpu_spin",
            Self::NoisyNeighbor => "noisy_neighbor",
            Self::IoSaturation => "io_saturation",
            Self::OomRisk => "oom_risk",
            Self::CpuThrottled => "cpu_throttled",
            Self::DiskPressure => "disk_pressure",
            Self::NetworkSaturation => "network_saturation",
            Self::DeploymentRegression => "deployment_regression",
            Self::Normal => "normal",
        }
    }

    pub fn triggers_alert(&self) -> bool {
        !matches!(self, Self::Normal)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PodContribution {
    pub namespace: String,
    pub pod: String,
    pub cpu_usage: f32,
    pub psi_contribution: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Insight {
    pub reason_code: InsightReason,
    pub summary: String,
    pub confidence: f32,
    pub id: String,
    pub top_pods: Vec<PodContribution>,
    pub suggested_next_step: String,
    /// Ids of the facts (`incidents::investigation::Fact::id`) that ground
    /// this insight's summary, in the same numbering the analyzer cited
    /// against the incident. Empty rather than omitted when nothing grounded
    /// it -- an insight that cites nothing is a fact worth keeping, not a
    /// missing field. Added on the v0.2 schema bump so the Incident Lab can
    /// score evidence correctness (every ref must resolve to a supplied fact
    /// whose value matches the episode).
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    // Compat fields
    pub primary_process: Option<String>,
    pub k8s: Option<K8sMetadata>,
}

impl Insight {
    pub fn redact(&mut self) {
        use sha2::{Digest, Sha256};

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
            evidence_refs: vec![],
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
            evidence_refs: vec![],
            primary_process: None,
            k8s: None,
        };

        let mut i2 = i1.clone();
        i1.redact();
        i2.redact();

        assert_eq!(i1.top_pods[0].namespace, i2.top_pods[0].namespace);
    }
}
