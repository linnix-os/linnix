//! Ground truth for the kernel/topology matrix's injection harness.
//!
//! `terraform/kernel-matrix/scenarios/*.yaml` deploys real pods onto a
//! matrix cell to produce a genuine `VmCapture` episode -- but cognitod
//! itself can't know what it was shown (`Episode::from_capture` always
//! stamps `ground_truth: None`, see its doc comment), only the harness that
//! injected the fault knows that. This table is the harness's side of that
//! contract: the identities here must match the pod names in the
//! corresponding scenario manifest exactly, the same way
//! `datasets/scenarios/*.json` and `scenario.rs::ScenarioManifest` agree on
//! names for synthetic episodes.
//!
//! Deliberately only the three scenarios with an injectable, single-culprit
//! shape: `below_reporting_bar` has no "correctly stayed silent" verdict for
//! `xtask lab score` to grade, `multi_process_pod` and
//! `victim_self_exclusion` test attribution internals a real VM run doesn't
//! need to re-cover.

use anyhow::{Result, bail};
use cognitod::episode::{GroundTruth, PodRef};
use cognitod::schema::InsightReason;

/// The ground truth `cargo lab stamp` attaches for one named scenario,
/// matching the offender pod its `terraform/kernel-matrix/scenarios/<name
/// with underscores as hyphens>.yaml` manifest deploys into namespace
/// "prod" alongside the shared `payment-api` victim in `namespace.yaml`.
pub fn ground_truth_for(scenario: &str) -> Result<GroundTruth> {
    let (pod, reason) = match scenario {
        "fork_storm" => ("fork-bomb", InsightReason::ForkStorm),
        "cpu_noisy_neighbor" => ("image-resize-worker", InsightReason::NoisyNeighbor),
        "short_job_churn" => ("ci-runner", InsightReason::ShortJobChurn),
        other => bail!(
            "unknown injection scenario: {other} (expected one of: fork_storm, cpu_noisy_neighbor, short_job_churn)"
        ),
    };

    Ok(GroundTruth {
        culprit: PodRef {
            namespace: "prod".to_string(),
            pod: pod.to_string(),
        },
        reason_code: reason,
        corrected: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_wired_scenario_resolves() {
        for scenario in ["fork_storm", "cpu_noisy_neighbor", "short_job_churn"] {
            assert!(
                ground_truth_for(scenario).is_ok(),
                "{scenario} should resolve to a ground truth"
            );
        }
    }

    #[test]
    fn an_unwired_scenario_is_rejected() {
        assert!(ground_truth_for("below_reporting_bar").is_err());
    }
}
