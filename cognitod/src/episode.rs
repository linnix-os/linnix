//! The Incident Lab's episode format.
//!
//! An episode is one self-contained record of a stall: the signal series that
//! led up to it, the candidate offenders, Linnix's diagnosis, and (if known)
//! the ground truth. It is the one artifact both halves of the lab agree on:
//! `xtask lab run` writes episodes by capturing a real k3s VM, `xtask lab
//! replay` reads them back with no kernel involvement, and `xtask lab score`
//! compares a replayed diagnosis against the ground truth carried alongside
//! it. The `xtask lab` CLI itself is a later Incident Lab phase; this module
//! only owns the record shape.
//!
//! The invariant this format exists to hold: an episode captured on a real
//! VM must replay in-process on a laptop, byte-identically, with no kernel
//! involvement. That is why every field here is plain, owned, serializable
//! data -- nothing borrowed from a live `PsiMonitor` or cgroup filesystem.
//!
//! Versioned from the first commit (`EPISODE_FORMAT_VERSION`), independent of
//! the Insight schema version (currently v0.2, see
//! datasets/schema/insight.schema.json) -- the two evolve on separate
//! schedules: an episode embeds one `Insight` as its diagnosis, but adding a
//! signal to `CandidateWindow` does not change what an `Insight` looks like,
//! and vice versa.

use serde::{Deserialize, Serialize};

use crate::schema::{Insight, InsightReason};

pub const EPISODE_FORMAT_VERSION: &str = "0.1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PodRef {
    pub namespace: String,
    pub pod: String,
}

/// Where an episode came from. Distinguishes synthetic lab scenarios from
/// real captures so a score report can break accuracy down by source --
/// the gap between the two is the number Phase 5 cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeSource {
    /// Injected by a scenario manifest under a lab run (Phase 2).
    Synthetic,
    /// Captured from a real k3s VM in the kernel/topology matrix (Phase 3).
    VmCapture,
    /// A design partner's correction on a live insight (Phase 5).
    DesignPartner,
}

/// The rule and trigger version that opened the incident this episode
/// captures. Carried explicitly because a scorer comparing episodes captured
/// months apart needs to know whether a scenario's fingerprint changed
/// because the workload changed or because the detector did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriggerInfo {
    pub rule_name: String,
    pub rule_version: String,
}

/// One candidate's signal series across the detection window, split into
/// what preceded the trigger and what followed it. Onset ordering
/// ("busiest pod is not the culprit") is computed from
/// `first_deviation_offset_ms`, not from inspecting the series by eye.
///
/// Each series is a plain sample vector rather than a richer per-signal
/// struct on purpose: Phase 1 (widening `StallEvent` to carry memory/io/net,
/// not just CPU) adds signals to what gets sampled without changing this
/// shape, since a new signal is just another vector here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateWindow {
    pub pod: PodRef,
    pub owner_kind: Option<String>,
    pub owner_name: Option<String>,
    /// Samples per signal, keyed by signal name (e.g. "cpu_percent",
    /// "memory_rss_bytes", "io_bytes", "network_bytes"). A map rather than
    /// fixed fields so Phase 1 signals slot in without a format bump.
    pub pre_window: std::collections::BTreeMap<String, Vec<f64>>,
    pub post_window: std::collections::BTreeMap<String, Vec<f64>>,
    pub sample_interval_ms: u64,
    /// Milliseconds from the trigger firing to this candidate's first
    /// deviation from baseline. Negative if the deviation preceded the
    /// trigger. `None` when onset could not be computed (pre-Phase-1
    /// captures, or a candidate that never deviated).
    pub first_deviation_offset_ms: Option<i64>,
}

/// The ground truth a scenario manifest asserts, or a design partner's
/// correction. `corrected` distinguishes the two: a scenario's truth is
/// known before the run, a correction is a human overriding what Linnix
/// diagnosed after the fact -- both score the same way, but only one
/// implies the diagnosis was wrong.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroundTruth {
    pub culprit: PodRef,
    pub reason_code: InsightReason,
    pub corrected: bool,
}

/// Whether the diagnosis's suggested step actually helped, per
/// `incidents::outcome::RecoveryWatch`'s post-action PSI poll.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub suggested_step_helped: Option<bool>,
    pub recovery_time_ms: Option<u64>,
    pub psi_before: Option<u64>,
    pub psi_after: Option<u64>,
}

/// One captured or replayed incident, in the shape `xtask lab score` reads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Episode {
    /// Format version (`EPISODE_FORMAT_VERSION`), independent of the Insight
    /// schema version embedded in `diagnosis`.
    pub version: String,
    pub episode_id: String,
    /// RFC 3339. A `String` rather than `chrono::DateTime` at the boundary
    /// keeps this format decodable by tooling that never links against
    /// cognitod's dependency tree, e.g. a pure-Python scorer.
    pub captured_at: String,
    pub source: EpisodeSource,
    /// The scenario manifest name, when `source` is `Synthetic`.
    pub scenario: Option<String>,
    pub trigger: TriggerInfo,
    pub victim: PodRef,
    pub candidates: Vec<CandidateWindow>,
    /// The pod/ownership graph as a flat edge list (owner -> pod), rather
    /// than a nested tree, so it round-trips through JSON without a custom
    /// (de)serializer.
    pub pod_graph: Vec<PodGraphEdge>,
    /// Linnix's own diagnosis, when one was produced. Reuses `schema::Insight`
    /// directly -- an episode's diagnosis is exactly what `/insights` served,
    /// not a lab-specific projection of it.
    pub diagnosis: Option<Insight>,
    pub ground_truth: Option<GroundTruth>,
    /// Fact or evidence ids the diagnosis cited, resolved against this
    /// episode. Mirrors `diagnosis.evidence_refs` but kept as its own field:
    /// a `None` diagnosis (replay produced nothing) can still carry evidence
    /// a human correction cited.
    pub evidence_cited: Vec<String>,
    pub outcome: Option<Outcome>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PodGraphEdge {
    pub owner_kind: String,
    pub owner_name: String,
    pub pod: PodRef,
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN_FIXTURE: &str =
        include_str!("../../datasets/episodes/golden/fork_storm_v0.1.json");

    #[test]
    fn golden_fixture_round_trips_through_serde() {
        let episode: Episode =
            serde_json::from_str(GOLDEN_FIXTURE).expect("golden fixture must deserialize");
        assert_eq!(episode.version, EPISODE_FORMAT_VERSION);

        let reserialized = serde_json::to_string_pretty(&episode).unwrap();
        let roundtripped: Episode =
            serde_json::from_str(&reserialized).expect("reserialized episode must deserialize");
        assert_eq!(episode, roundtripped);
    }

    #[test]
    fn golden_fixture_carries_a_reason_code_from_the_merged_vocabulary() {
        let episode: Episode = serde_json::from_str(GOLDEN_FIXTURE).unwrap();
        let truth = episode
            .ground_truth
            .expect("fixture should assert a ground truth");
        assert_eq!(truth.reason_code, InsightReason::ForkStorm);
    }
}
