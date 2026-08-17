//! Did the action work?
//!
//! An incident records that pressure was high and something was done about it.
//! On its own that is a claim, not a result: the columns for the result —
//! `psi_after` and `recovery_time_ms` — have existed since the first schema,
//! are read back by `/incidents/{id}`, and are averaged into
//! `avg_recovery_time_ms` on `/incidents/stats`, but nothing ever wrote them.
//! That endpoint has been reporting an average over a column that is always
//! NULL.
//!
//! Watching a victim's pressure after an action is what turns a blame
//! heuristic into a verified attribution: the difference between "this pod was
//! contending" and "removing it demonstrably reduced the stall".

use std::time::Duration;

use tokio::time::Instant;

/// How long to watch, and what counts as recovered.
#[derive(Debug, Clone, Copy)]
pub struct RecoveryWatch {
    /// How often to sample pressure.
    pub poll_interval: Duration,
    /// How long to keep watching before giving up on recovery.
    pub max_wait: Duration,
    /// Pressure at or below this is recovered.
    ///
    /// This is the same threshold that decided the incident was happening, not
    /// a second number invented for the outcome. Recovery has to mean "the
    /// condition we acted on is no longer true", or the two halves of the
    /// record describe different things.
    pub recovered_below: f32,
}

impl RecoveryWatch {
    pub const DEFAULT_POLL: Duration = Duration::from_secs(1);
    pub const DEFAULT_MAX_WAIT: Duration = Duration::from_secs(120);

    pub fn with_threshold(recovered_below: f32) -> Self {
        Self {
            poll_interval: Self::DEFAULT_POLL,
            max_wait: Self::DEFAULT_MAX_WAIT,
            recovered_below,
        }
    }
}

/// What was actually observed after the action.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RecoveryOutcome {
    /// Pressure at the end of the observation, whatever happened. Always
    /// recorded: "we watched and it stayed bad" is a result, and the most
    /// important one to be able to see.
    pub psi_after: f32,
    /// Time until pressure fell below the threshold.
    ///
    /// `None` means it never did within `max_wait` — deliberately not the
    /// window length, which would record a recovery that did not happen. A row
    /// with `psi_after` set and this `None` says "observed, did not recover",
    /// which is a different statement from a row where both are `None` and
    /// nothing was ever measured.
    pub recovery_time_ms: Option<i64>,
}

/// Watches pressure until it recovers or the window expires.
///
/// `sample` is called rather than reading `/proc` directly so the caller
/// chooses what pressure means for this incident — and so this is testable
/// without a stalling machine.
pub async fn observe_recovery<S>(mut sample: S, watch: RecoveryWatch) -> RecoveryOutcome
where
    S: FnMut() -> f32,
{
    let started = Instant::now();
    let mut last = sample();

    // Checked before the first sleep: an action that worked immediately should
    // report a fast recovery, not one rounded up to the poll interval.
    if last <= watch.recovered_below {
        return RecoveryOutcome {
            psi_after: last,
            recovery_time_ms: Some(0),
        };
    }

    loop {
        tokio::time::sleep(watch.poll_interval).await;
        last = sample();
        let elapsed = started.elapsed();

        if last <= watch.recovered_below {
            return RecoveryOutcome {
                psi_after: last,
                recovery_time_ms: Some(elapsed.as_millis() as i64),
            };
        }

        if elapsed >= watch.max_wait {
            return RecoveryOutcome {
                psi_after: last,
                recovery_time_ms: None,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A queue of readings, so a test can describe pressure over time.
    fn readings(values: &[f32]) -> impl FnMut() -> f32 + '_ {
        let mut idx = 0;
        move || {
            let value = values[idx.min(values.len() - 1)];
            idx += 1;
            value
        }
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_is_timed_from_the_action() {
        // Still bad for two polls, recovered on the third.
        let outcome = observe_recovery(
            readings(&[80.0, 70.0, 60.0, 5.0]),
            RecoveryWatch {
                poll_interval: Duration::from_secs(1),
                max_wait: Duration::from_secs(60),
                recovered_below: 10.0,
            },
        )
        .await;

        assert_eq!(outcome.psi_after, 5.0);
        assert_eq!(outcome.recovery_time_ms, Some(3_000));
    }

    #[tokio::test(start_paused = true)]
    async fn pressure_that_never_falls_records_the_reading_and_no_recovery() {
        let outcome = observe_recovery(
            readings(&[80.0]),
            RecoveryWatch {
                poll_interval: Duration::from_secs(1),
                max_wait: Duration::from_secs(5),
                recovered_below: 10.0,
            },
        )
        .await;

        // The distinction this whole type exists to preserve: we watched, and
        // it did not recover. Recording the window length here would claim a
        // recovery at 5s that never happened.
        assert_eq!(outcome.psi_after, 80.0);
        assert_eq!(outcome.recovery_time_ms, None);
    }

    #[tokio::test(start_paused = true)]
    async fn an_immediate_recovery_is_not_rounded_up_to_a_poll() {
        let outcome = observe_recovery(
            readings(&[2.0]),
            RecoveryWatch {
                poll_interval: Duration::from_secs(30),
                max_wait: Duration::from_secs(120),
                recovered_below: 10.0,
            },
        )
        .await;

        assert_eq!(outcome.recovery_time_ms, Some(0));
    }

    #[tokio::test(start_paused = true)]
    async fn pressure_exactly_at_the_threshold_counts_as_recovered() {
        // The threshold is the line the incident was declared on, so sitting
        // on it is no longer breaching.
        let outcome = observe_recovery(
            readings(&[80.0, 10.0]),
            RecoveryWatch {
                poll_interval: Duration::from_secs(1),
                max_wait: Duration::from_secs(60),
                recovered_below: 10.0,
            },
        )
        .await;

        assert_eq!(outcome.recovery_time_ms, Some(1_000));
    }
}
