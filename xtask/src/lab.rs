//! `cargo xtask lab` -- the Incident Lab CLI.
//!
//! `replay` and `score` are in-process only: they read episode JSON, run it
//! back through `calculate_blame_attributions`, and compare the result
//! against the ground truth carried in the episode. No kernel, no reasoner
//! call -- `episode::Episode`'s own invariant is byte-identical in-process
//! replay, and the ground truth this scores (`culprit`, `reason_code`) comes
//! entirely out of the heuristic, never out of the LLM-backed reasoner that
//! only fills in `diagnosis.summary`/`suggested_next_step`.
//!
//! `run` (materializing episodes from scenario manifests) and the CI
//! regression gate are later Incident Lab slices; this module only owns
//! `replay` and `score` against episodes that already exist on disk.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use cognitod::attribution::{AttributionSink, BlameMetrics};
use cognitod::collectors::psi::calculate_blame_attributions;
use cognitod::episode::Episode;
use cognitod::schema::InsightReason;
use serde::Serialize;

/// What replay predicted for one episode: the top-ranked offender and reason,
/// or nothing if no offender cleared the reporting bar.
#[derive(Debug, Clone, Serialize)]
pub struct Prediction {
    pub namespace: String,
    pub pod: String,
    pub reason: InsightReason,
}

/// Replays one episode's `StallEvent` through the same heuristic and sink the
/// live daemon uses, and returns its top-ranked offender, if any.
///
/// A fresh `AttributionSink` is built per call so cooldown state never
/// carries over between episodes -- each episode is scored as if it were the
/// first time its incident was ever seen.
pub fn replay(episode: &Episode) -> Option<Prediction> {
    let event = episode.to_stall_event();
    let attributions = calculate_blame_attributions(&event);

    let metrics = std::sync::Arc::new(BlameMetrics::new("xtask-lab"));
    let sink = AttributionSink::new(metrics, None, "xtask-lab");
    let emitted = sink.emit(&attributions);

    emitted.first().map(|event| Prediction {
        namespace: event.offender.namespace.clone(),
        pod: event.offender.pod.clone(),
        reason: event.offender.reason,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// No ground truth to score against -- excluded from accuracy.
    NoGroundTruth,
    Correct,
    WrongCulprit,
    WrongReason,
    NoPrediction,
}

#[derive(Debug, Serialize)]
pub struct EpisodeScore {
    pub episode_id: String,
    pub scenario: Option<String>,
    pub verdict: Verdict,
    pub predicted: Option<Prediction>,
}

#[derive(Debug, Serialize)]
pub struct ScoreReport {
    pub scored: usize,
    pub correct: usize,
    pub accuracy: f64,
    pub episodes: Vec<EpisodeScore>,
}

fn score_one(episode: &Episode) -> EpisodeScore {
    let predicted = replay(episode);

    let verdict = match (&episode.ground_truth, &predicted) {
        (None, _) => Verdict::NoGroundTruth,
        (Some(_), None) => Verdict::NoPrediction,
        (Some(truth), Some(pred)) => {
            if truth.culprit.namespace != pred.namespace || truth.culprit.pod != pred.pod {
                Verdict::WrongCulprit
            } else if truth.reason_code != pred.reason {
                Verdict::WrongReason
            } else {
                Verdict::Correct
            }
        }
    };

    EpisodeScore {
        episode_id: episode.episode_id.clone(),
        scenario: episode.scenario.clone(),
        verdict,
        predicted,
    }
}

pub fn score(episodes: &[Episode]) -> ScoreReport {
    let scores: Vec<EpisodeScore> = episodes.iter().map(score_one).collect();

    let scored = scores
        .iter()
        .filter(|s| s.verdict != Verdict::NoGroundTruth)
        .count();
    let correct = scores
        .iter()
        .filter(|s| s.verdict == Verdict::Correct)
        .count();
    let accuracy = if scored > 0 {
        correct as f64 / scored as f64
    } else {
        1.0
    };

    ScoreReport {
        scored,
        correct,
        accuracy,
        episodes: scores,
    }
}

fn load_episode(path: &Path) -> Result<Episode> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading episode file {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing episode file {}", path.display()))
}

fn load_episodes_from_dir(dir: &Path) -> Result<Vec<Episode>> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading episode directory {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();

    paths.iter().map(|p| load_episode(p)).collect()
}

pub fn run_replay(path: &Path) -> Result<()> {
    let episode = load_episode(path)?;
    let prediction = replay(&episode);
    println!("{}", serde_json::to_string_pretty(&prediction)?);
    Ok(())
}

pub fn run_score(path: &Path) -> Result<()> {
    let episodes = if path.is_dir() {
        load_episodes_from_dir(path)?
    } else {
        vec![load_episode(path)?]
    };
    if episodes.is_empty() {
        bail!("no episodes found under {}", path.display());
    }

    let report = score(&episodes);
    println!("{}", serde_json::to_string_pretty(&report)?);

    if report.accuracy < 1.0 {
        bail!(
            "accuracy {:.1}% ({}/{} correct) is below 100%",
            report.accuracy * 100.0,
            report.correct,
            report.scored
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN_FIXTURE: &str =
        include_str!("../../datasets/episodes/golden/fork_storm_v0.1.json");

    fn golden() -> Episode {
        serde_json::from_str(GOLDEN_FIXTURE).expect("golden fixture must deserialize")
    }

    #[test]
    fn replay_names_the_fork_bomb_as_the_offender() {
        let prediction = replay(&golden()).expect("fork storm should produce a prediction");
        assert_eq!(prediction.namespace, "prod");
        assert_eq!(prediction.pod, "fork-bomb");
        assert_eq!(prediction.reason, InsightReason::ForkStorm);
    }

    #[test]
    fn score_matches_the_golden_fixture_ground_truth() {
        let report = score(&[golden()]);
        assert_eq!(report.scored, 1);
        assert_eq!(report.correct, 1);
        assert_eq!(report.accuracy, 1.0);
        assert_eq!(report.episodes[0].verdict, Verdict::Correct);
    }

    #[test]
    fn an_episode_without_ground_truth_is_excluded_from_accuracy() {
        let mut episode = golden();
        episode.ground_truth = None;

        let report = score(&[episode]);
        assert_eq!(report.scored, 0);
        assert_eq!(report.correct, 0);
        assert_eq!(
            report.accuracy, 1.0,
            "an empty denominator should not read as a failure"
        );
        assert_eq!(report.episodes[0].verdict, Verdict::NoGroundTruth);
    }

    #[test]
    fn a_stall_too_small_to_report_scores_as_no_prediction() {
        let mut episode = golden();
        episode.victim_stall_us = 0;

        let report = score(&[episode]);
        assert_eq!(report.episodes[0].verdict, Verdict::NoPrediction);
        assert!(report.accuracy < 1.0);
    }

    #[test]
    fn a_wrong_culprit_in_ground_truth_is_caught() {
        use cognitod::episode::PodRef;

        let mut episode = golden();
        episode.ground_truth.as_mut().unwrap().culprit = PodRef {
            namespace: "prod".to_string(),
            pod: "steady-worker".to_string(),
        };

        let report = score(&[episode]);
        assert_eq!(report.episodes[0].verdict, Verdict::WrongCulprit);
    }

    #[test]
    fn a_wrong_reason_in_ground_truth_is_caught() {
        let mut episode = golden();
        episode.ground_truth.as_mut().unwrap().reason_code = InsightReason::NoisyNeighbor;

        let report = score(&[episode]);
        assert_eq!(report.episodes[0].verdict, Verdict::WrongReason);
    }
}
