//! Scenario manifests -- the human-authored input to `xtask lab run`.
//!
//! A manifest describes a cluster situation ("a fork bomb stalls the payment
//! API") in the same shape `cognitod/tests/attribution_eval.rs`'s Rust
//! scenario table already does, so anyone porting a case between the two only
//! has to translate field names, not invent a new mental model. Deliberately
//! *not* the same table, though: that eval suite asserts exact per-offender
//! `stall_ms` ranges and inspects Prometheus/alert output, which a JSON
//! manifest has no business doing -- a manifest only needs to state who
//! should be blamed and why, then let `xtask lab score` grade a replay
//! against it the same way any other episode's `ground_truth` is graded.
//!
//! Every candidate pod is assumed to live in the victim's namespace, matching
//! the convention `attribution_eval.rs` already uses throughout (every
//! fork/short-job key there is `format!("{}/{}", VICTIM_NS, pod)`).

use std::collections::{BTreeMap, HashMap};

use cognitod::episode::{
    CandidateWindow, Episode, EpisodeSource, GroundTruth, PodRef, TriggerInfo,
};
use cognitod::schema::InsightReason;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConsumerSpec {
    pub pod: String,
    pub cpu_percent: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CountSpec {
    pub pod: String,
    pub count: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExpectedOffender {
    pub pod: String,
    pub reason: InsightReason,
}

/// A cluster situation: what's happening, and who a correct diagnosis should
/// name. `expect_reported`'s first entry becomes the episode's
/// `ground_truth` -- entries after it document a scenario with more than one
/// real offender (see `attribution_eval.rs`'s fork-bomb case) but are not
/// separately scored, matching how `xtask lab score` grades only the
/// top-ranked prediction.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScenarioManifest {
    pub name: String,
    pub victim: PodRef,
    pub victim_stall_us: u64,
    #[serde(default)]
    pub consumers: Vec<ConsumerSpec>,
    #[serde(default)]
    pub forks: Vec<CountSpec>,
    #[serde(default)]
    pub short_jobs: Vec<CountSpec>,
    #[serde(default)]
    pub expect_reported: Vec<ExpectedOffender>,
}

impl ScenarioManifest {
    /// Materializes this scenario into a synthetic `Episode`, ready for
    /// `xtask lab score` (or `Episode::to_stall_event` directly) exactly like
    /// any other episode on disk.
    ///
    /// The victim itself is dropped from `candidates` even when a scenario
    /// lists it as a consumer or forker (see `attribution_eval.rs`'s
    /// "CPU-bound victim" case) -- `calculate_blame_attributions` ignores a
    /// victim's own entries unconditionally, so keeping them here would only
    /// misdescribe what a real capture looks like.
    pub fn to_episode(&self) -> Episode {
        let mut cpu_by_pod: BTreeMap<String, f64> = BTreeMap::new();
        for consumer in &self.consumers {
            *cpu_by_pod.entry(consumer.pod.clone()).or_insert(0.0) += consumer.cpu_percent;
        }
        let fork_by_pod: HashMap<&str, u64> = self
            .forks
            .iter()
            .map(|f| (f.pod.as_str(), f.count))
            .collect();
        let short_job_by_pod: HashMap<&str, u64> = self
            .short_jobs
            .iter()
            .map(|s| (s.pod.as_str(), s.count))
            .collect();

        let mut pods: Vec<&str> = cpu_by_pod
            .keys()
            .map(String::as_str)
            .chain(fork_by_pod.keys().copied())
            .chain(short_job_by_pod.keys().copied())
            .collect();
        pods.sort_unstable();
        pods.dedup();

        let candidates = pods
            .into_iter()
            .filter(|&pod| pod != self.victim.pod)
            .map(|pod| {
                let mut pre_window: BTreeMap<String, Vec<f64>> = BTreeMap::new();
                if let Some(cpu) = cpu_by_pod.get(pod) {
                    pre_window.insert("cpu_percent".to_string(), vec![*cpu]);
                }
                if let Some(count) = fork_by_pod.get(pod) {
                    pre_window.insert("fork_count".to_string(), vec![*count as f64]);
                }
                if let Some(count) = short_job_by_pod.get(pod) {
                    pre_window.insert("short_job_count".to_string(), vec![*count as f64]);
                }

                CandidateWindow {
                    pod: PodRef {
                        namespace: self.victim.namespace.clone(),
                        pod: pod.to_string(),
                    },
                    owner_kind: None,
                    owner_name: None,
                    pre_window,
                    post_window: BTreeMap::new(),
                    sample_interval_ms: 1000,
                    first_deviation_offset_ms: None,
                }
            })
            .collect();

        let ground_truth = self.expect_reported.first().map(|offender| GroundTruth {
            culprit: PodRef {
                namespace: self.victim.namespace.clone(),
                pod: offender.pod.clone(),
            },
            reason_code: offender.reason,
            corrected: false,
        });

        Episode {
            version: cognitod::episode::EPISODE_FORMAT_VERSION.to_string(),
            episode_id: format!("ep-{}", slugify(&self.name)),
            captured_at: chrono::Utc::now().to_rfc3339(),
            source: EpisodeSource::Synthetic,
            scenario: Some(self.name.clone()),
            trigger: TriggerInfo {
                rule_name: "psi_stall_attribution".to_string(),
                rule_version: "1".to_string(),
            },
            victim: self.victim.clone(),
            victim_stall_us: self.victim_stall_us,
            candidates,
            pod_graph: Vec::new(),
            diagnosis: None,
            ground_truth,
            evidence_cited: Vec::new(),
            outcome: None,
        }
    }
}

fn slugify(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> ScenarioManifest {
        ScenarioManifest {
            name: "a fork bomb is blamed even though its CPU share looks modest".to_string(),
            victim: PodRef {
                namespace: "prod".to_string(),
                pod: "payment-api".to_string(),
            },
            victim_stall_us: 1_000_000,
            consumers: vec![
                ConsumerSpec {
                    pod: "fork-bomb".to_string(),
                    cpu_percent: 10.0,
                },
                ConsumerSpec {
                    pod: "steady-worker".to_string(),
                    cpu_percent: 20.0,
                },
            ],
            forks: vec![CountSpec {
                pod: "fork-bomb".to_string(),
                count: 400,
            }],
            short_jobs: vec![],
            expect_reported: vec![
                ExpectedOffender {
                    pod: "fork-bomb".to_string(),
                    reason: InsightReason::ForkStorm,
                },
                ExpectedOffender {
                    pod: "steady-worker".to_string(),
                    reason: InsightReason::NoisyNeighbor,
                },
            ],
        }
    }

    #[test]
    fn replay_of_the_generated_episode_matches_the_first_expected_offender() {
        let episode = manifest().to_episode();
        let prediction =
            crate::replay(&episode).expect("fork storm scenario should produce a prediction");
        assert_eq!(prediction.pod, "fork-bomb");
        assert_eq!(prediction.reason, InsightReason::ForkStorm);
    }

    #[test]
    fn the_victim_is_never_materialized_as_its_own_candidate() {
        let mut m = manifest();
        m.consumers.push(ConsumerSpec {
            pod: "payment-api".to_string(),
            cpu_percent: 70.0,
        });
        m.forks.push(CountSpec {
            pod: "payment-api".to_string(),
            count: 300,
        });

        let episode = m.to_episode();
        assert!(
            episode
                .candidates
                .iter()
                .all(|c| c.pod.pod != "payment-api"),
            "the victim should never appear in its own candidate list"
        );
    }

    #[test]
    fn a_scenario_with_no_expected_offender_produces_no_ground_truth() {
        let mut m = manifest();
        m.expect_reported.clear();

        let episode = m.to_episode();
        assert!(episode.ground_truth.is_none());
    }

    #[test]
    fn round_tripping_through_json_matches_the_episode_schema_version() {
        let episode = manifest().to_episode();
        assert_eq!(episode.version, cognitod::episode::EPISODE_FORMAT_VERSION);
        let raw = serde_json::to_string(&episode).unwrap();
        let roundtripped: Episode = serde_json::from_str(&raw).unwrap();
        assert_eq!(roundtripped.episode_id, episode.episode_id);
    }
}
