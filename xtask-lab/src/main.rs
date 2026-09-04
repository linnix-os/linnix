//! `cargo lab` -- the Incident Lab CLI.
//!
//! A separate binary from `xtask` on purpose: `xtask build-ebpf` runs under
//! the pinned eBPF nightly toolchain in CI, and `cargo xtask <cmd>` compiles
//! the whole `xtask` binary before dispatching -- so if this command lived
//! there, that nightly (older than `cognitod`'s MSRV-adjacent language
//! features -- let-chains, `is_multiple_of`) would have to compile all of
//! `cognitod` and fail before `build-ebpf` ever got a chance to override the
//! toolchain for its own subprocess. Splitting the crate keeps `xtask`
//! dependency-light and lets this one link against `cognitod` freely.
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
//! regression gate are later Incident Lab slices; this binary only owns
//! `replay` and `score` against episodes that already exist on disk.

mod scenario;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use cognitod::attribution::{AttributionSink, BlameMetrics};
use cognitod::collectors::psi::calculate_blame_attributions;
use cognitod::episode::{Episode, EpisodeSource};
use cognitod::schema::InsightReason;
use serde::Serialize;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("replay") => {
            let path = args
                .get(2)
                .context("usage: cargo lab replay <episode.json>")?;
            run_replay(&PathBuf::from(path))
        }
        Some("score") => {
            let path = args
                .get(2)
                .context("usage: cargo lab score <episode.json|dir>")?;
            run_score(&PathBuf::from(path))
        }
        Some("run") => {
            let scenarios_dir = args
                .get(2)
                .context("usage: cargo lab run <scenarios-dir> <output-dir>")?;
            let output_dir = args
                .get(3)
                .context("usage: cargo lab run <scenarios-dir> <output-dir>")?;
            run_scenarios(&PathBuf::from(scenarios_dir), &PathBuf::from(output_dir))
        }
        Some(other) => bail!("unknown lab subcommand: {other}"),
        None => bail!("usage: cargo lab <run|replay|score> <path>"),
    }
}

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
    pub source: EpisodeSource,
    pub verdict: Verdict,
    pub predicted: Option<Prediction>,
}

/// Accuracy over one `EpisodeSource`'s slice of a score run. Kept separate
/// per source because they mean different things: `Synthetic` accuracy is a
/// regression gate (the six hand-authored scenarios must keep scoring
/// 100%), while `VmCapture`/`DesignPartner` accuracy is a number to watch,
/// not a bar to clear -- a real capture can be a genuinely hard case no
/// scenario author anticipated.
#[derive(Debug, Serialize)]
pub struct SourceBreakdown {
    pub source: EpisodeSource,
    pub scored: usize,
    pub correct: usize,
    pub accuracy: f64,
}

#[derive(Debug, Serialize)]
pub struct ScoreReport {
    pub scored: usize,
    pub correct: usize,
    pub accuracy: f64,
    pub by_source: Vec<SourceBreakdown>,
    pub episodes: Vec<EpisodeScore>,
}

impl ScoreReport {
    /// The `Synthetic` breakdown, if any episode of that source was scored.
    /// This is the one `run_score` gates the build on -- see its doc comment.
    pub fn synthetic(&self) -> Option<&SourceBreakdown> {
        self.by_source
            .iter()
            .find(|b| b.source == EpisodeSource::Synthetic)
    }
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
        source: episode.source,
        verdict,
        predicted,
    }
}

fn breakdown_for(scores: &[EpisodeScore], source: EpisodeSource) -> Option<SourceBreakdown> {
    let mut scored = 0;
    let mut correct = 0;
    for s in scores.iter().filter(|s| s.source == source) {
        if s.verdict == Verdict::NoGroundTruth {
            continue;
        }
        scored += 1;
        if s.verdict == Verdict::Correct {
            correct += 1;
        }
    }
    if scored == 0 && !scores.iter().any(|s| s.source == source) {
        return None;
    }
    let accuracy = if scored > 0 {
        correct as f64 / scored as f64
    } else {
        1.0
    };
    Some(SourceBreakdown {
        source,
        scored,
        correct,
        accuracy,
    })
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

    let by_source = [
        EpisodeSource::Synthetic,
        EpisodeSource::VmCapture,
        EpisodeSource::DesignPartner,
    ]
    .into_iter()
    .filter_map(|source| breakdown_for(&scores, source))
    .collect();

    ScoreReport {
        scored,
        correct,
        accuracy,
        by_source,
        episodes: scores,
    }
}

fn load_episode(path: &Path) -> Result<Episode> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading episode file {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing episode file {}", path.display()))
}

/// A JSON data file, excluding the `*.schema.json` sibling every `datasets/`
/// directory carries alongside its records.
fn is_data_json(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext == "json")
        && !path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().ends_with(".schema.json"))
}

fn load_episodes_from_dir(dir: &Path) -> Result<Vec<Episode>> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading episode directory {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| is_data_json(p))
        .collect();
    paths.sort();

    paths.iter().map(|p| load_episode(p)).collect()
}

fn load_scenarios_from_dir(dir: &Path) -> Result<Vec<scenario::ScenarioManifest>> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading scenario directory {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| is_data_json(p))
        .collect();
    paths.sort();

    paths
        .iter()
        .map(|p| -> Result<scenario::ScenarioManifest> {
            let raw = std::fs::read_to_string(p)
                .with_context(|| format!("reading scenario file {}", p.display()))?;
            serde_json::from_str(&raw)
                .with_context(|| format!("parsing scenario file {}", p.display()))
        })
        .collect()
}

/// Materializes every scenario manifest under `scenarios_dir` into an episode
/// JSON file under `output_dir`, named after the episode id so a rerun
/// overwrites the same file rather than accumulating stale copies.
fn run_scenarios(scenarios_dir: &Path, output_dir: &Path) -> Result<()> {
    let scenarios = load_scenarios_from_dir(scenarios_dir)?;
    if scenarios.is_empty() {
        bail!(
            "no scenario manifests found under {}",
            scenarios_dir.display()
        );
    }
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("creating output directory {}", output_dir.display()))?;

    for manifest in &scenarios {
        let episode = manifest.to_episode();
        let out_path = output_dir.join(format!("{}.json", episode.episode_id));
        std::fs::write(&out_path, serde_json::to_string_pretty(&episode)?)
            .with_context(|| format!("writing episode file {}", out_path.display()))?;
        println!("wrote {}", out_path.display());
    }
    Ok(())
}

fn run_replay(path: &Path) -> Result<()> {
    let episode = load_episode(path)?;
    let prediction = replay(&episode);
    println!("{}", serde_json::to_string_pretty(&prediction)?);
    Ok(())
}

fn run_score(path: &Path) -> Result<()> {
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

    // Only `Synthetic` accuracy gates the build. `VmCapture`/`DesignPartner`
    // episodes are real-world data, not a hand-authored regression suite --
    // a genuinely hard real capture must not fail CI the way a regression in
    // the six scenario manifests should. See `SourceBreakdown`'s doc comment.
    if let Some(synthetic) = report.synthetic()
        && synthetic.accuracy < 1.0
    {
        bail!(
            "synthetic accuracy {:.1}% ({}/{} correct) is below 100%",
            synthetic.accuracy * 100.0,
            synthetic.correct,
            synthetic.scored
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

    #[test]
    fn a_wrong_vm_capture_does_not_drag_down_the_synthetic_breakdown() {
        let synthetic = golden();
        let mut vm_capture = golden();
        vm_capture.source = EpisodeSource::VmCapture;
        vm_capture.episode_id = "ep-vm-wrong".to_string();
        vm_capture.ground_truth.as_mut().unwrap().reason_code = InsightReason::NoisyNeighbor;

        let report = score(&[synthetic, vm_capture]);

        let synthetic_breakdown = report.synthetic().expect("a synthetic episode was scored");
        assert_eq!(synthetic_breakdown.accuracy, 1.0);

        let vm_breakdown = report
            .by_source
            .iter()
            .find(|b| b.source == EpisodeSource::VmCapture)
            .expect("a vm_capture episode was scored");
        assert!(vm_breakdown.accuracy < 1.0);

        // Overall accuracy still reflects the mix -- only the per-source
        // breakdown, which `run_score` gates on, separates them.
        assert!(report.accuracy < 1.0);
    }

    #[test]
    fn synthetic_accuracy_below_100_percent_fails_the_gate_even_with_a_perfect_vm_capture() {
        let mut synthetic = golden();
        synthetic.ground_truth.as_mut().unwrap().reason_code = InsightReason::NoisyNeighbor;
        let mut vm_capture = golden();
        vm_capture.source = EpisodeSource::VmCapture;
        vm_capture.episode_id = "ep-vm-right".to_string();

        let report = score(&[synthetic, vm_capture]);

        assert!(report.synthetic().unwrap().accuracy < 1.0);
        assert_eq!(
            report
                .by_source
                .iter()
                .find(|b| b.source == EpisodeSource::VmCapture)
                .unwrap()
                .accuracy,
            1.0
        );
    }
}
