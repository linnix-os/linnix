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

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use crate::enforcement::{ActionStatus, EnforcementQueue};

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
    /// Pressure at the end of the observation. Recorded whatever the reading
    /// was — "we watched and it stayed bad" is a result, and the most
    /// important one to be able to see.
    ///
    /// `None` when pressure could not be read at all. A failed read is not a
    /// low reading: `PsiMetrics::read` yields zeros when `/proc/pressure` is
    /// unavailable, and zero is below every threshold, so treating it as a
    /// value would record a missing measurement as an instant recovery.
    pub psi_after: Option<f32>,
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
pub async fn observe_recovery<S, I>(
    mut sample: S,
    mut invalidated: I,
    watch: RecoveryWatch,
) -> RecoveryOutcome
where
    S: FnMut() -> Option<f32>,
    I: FnMut() -> bool,
{
    let started = Instant::now();
    let mut last = sample();

    // Checked before the first sleep: an action that worked immediately should
    // report a fast recovery, not one rounded up to the poll interval.
    if last.is_some_and(|psi| psi <= watch.recovered_below) {
        return RecoveryOutcome {
            psi_after: last,
            recovery_time_ms: Some(0),
        };
    }

    loop {
        tokio::time::sleep(watch.poll_interval).await;

        // Another intervention landed while this one was being measured. Both
        // watches read the same system-wide pressure, so whatever happens next
        // cannot be attributed to this action — and crediting it anyway is how
        // a second kill's success gets recorded against the first.
        if invalidated() {
            return RecoveryOutcome {
                psi_after: None,
                recovery_time_ms: None,
            };
        }

        // A failed read leaves the previous reading standing rather than
        // overwriting it with an absence: the last thing actually observed is
        // better evidence than nothing, and a transient unreadable /proc must
        // not end the watch.
        if let Some(reading) = sample() {
            last = Some(reading);

            if reading <= watch.recovered_below {
                return RecoveryOutcome {
                    psi_after: last,
                    recovery_time_ms: Some(started.elapsed().as_millis() as i64),
                };
            }
        }

        if started.elapsed() >= watch.max_wait {
            return RecoveryOutcome {
                psi_after: last,
                recovery_time_ms: None,
            };
        }
    }
}

impl RecoveryOutcome {
    /// Whether anything was actually observed.
    ///
    /// An unmeasured outcome must not be written: leaving both columns NULL
    /// says "nobody looked", which is true, where writing them would claim an
    /// observation that never happened.
    pub fn is_measured(&self) -> bool {
        self.psi_after.is_some()
    }
}

/// Waits until a proposed action has actually executed.
///
/// Returns false if it was rejected, expired, or is still waiting when the
/// deadline passes. This gates the recovery watch, because timing a recovery
/// against an action that has not run measures the weather: in `monitor` mode
/// and whenever human approval is required — both defaults — `propose_auto`
/// returns successfully with a *pending* action, and a natural fall in
/// pressure would otherwise be recorded as a successful auto-kill.
pub async fn await_execution(
    queue: &Arc<EnforcementQueue>,
    action_id: &str,
    poll_interval: Duration,
) -> Option<u64> {
    // Deadlines live on the same clock as the sleeps below. Comparing a wall
    // clock against virtual sleeps is not merely untestable — under paused
    // time the sleeps advance and the wall clock does not, so the loop spins
    // for the TTL in *real* seconds.
    let mut pending_deadline: Option<Instant> = None;
    let mut approved_deadline: Option<Instant> = None;

    loop {
        let action = queue.get_by_id(action_id).await?;

        match action.status {
            ActionStatus::Executed => {
                return Some(action.executed_at_ms.unwrap_or_else(epoch_millis));
            }
            ActionStatus::Rejected | ActionStatus::Expired | ActionStatus::Failed => return None,
            ActionStatus::Pending => {
                // While pending, the action's own approval lifetime is the
                // deadline: the queue holds proposals for 300s while the
                // recovery watch runs for 120s, and borrowing the shorter
                // number would abandon an incident an operator could still
                // validly approve.
                let deadline = *pending_deadline.get_or_insert_with(|| {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    // One poll of slack, and strictly after: `approve` accepts
                    // an approval at exactly `expires_at`, so giving up *at*
                    // the boundary would abandon an action an operator is
                    // still allowed to approve — and which would then really
                    // execute, with its incident permanently unverifiable.
                    Instant::now()
                        + Duration::from_secs(action.expires_at.saturating_sub(now))
                        + poll_interval
                });

                if Instant::now() > deadline {
                    return None;
                }
            }
            ActionStatus::Approved => {
                // Approval stops the expiry clock. `approve` allows approval
                // at the boundary and the executor only scans once a second,
                // so exiting on the proposal's expiry here would abandon an
                // action that is about to really run — and the kill would then
                // happen with the incident permanently unverifiable.
                let deadline =
                    *approved_deadline.get_or_insert_with(|| Instant::now() + EXECUTION_GRACE);

                if Instant::now() >= deadline {
                    return None;
                }
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

/// How long an approved action may sit before the executor is presumed dead.
///
/// The executor scans every second, so this is generous by two orders of
/// magnitude; it exists only so a stalled executor cannot leave the watch
/// waiting forever.
const EXECUTION_GRACE: Duration = Duration::from_secs(60);

fn epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The whole verification, in the order it has to happen: wait for the action
/// to run, then measure.
///
/// Exists as one function so the ordering is testable. Split across the call
/// site it is just a convention, and a convention that "measure only after the
/// action executed" is exactly the kind that silently stops holding.
///
/// `None` means there is nothing to record: either the action never ran, or
/// pressure could never be read. Both are honestly represented by leaving the
/// incident's outcome columns NULL.
pub async fn verify_action_outcome<S>(
    queue: &Arc<EnforcementQueue>,
    action_id: &str,
    sample: S,
    watch: RecoveryWatch,
) -> Option<RecoveryOutcome>
where
    S: FnMut() -> Option<f32>,
{
    let executed_at_ms = await_execution(queue, action_id, watch.poll_interval).await?;

    // Measured *before* observing, not after. Computing it afterwards folds
    // the watch's own duration into the delay and then adds the watch again —
    // a three-second recovery reported as six.
    let pre_watch_delay = Duration::from_millis(epoch_millis().saturating_sub(executed_at_ms));

    // The window is 120 seconds after the *kill*, so whatever the insert and
    // the polling already consumed comes out of it. Otherwise a fall three
    // minutes after the action could still be recorded as its recovery.
    let remaining = watch.max_wait.checked_sub(pre_watch_delay)?;
    if remaining.is_zero() {
        return None;
    }

    // Any execution after this one invalidates the measurement: two watches
    // reading system-wide pressure cannot both own the same fall.
    let executions_at_start = queue.execution_count();
    let queue_for_check = Arc::clone(queue);

    let outcome = observe_recovery(
        sample,
        move || queue_for_check.execution_count() != executions_at_start,
        RecoveryWatch {
            max_wait: remaining,
            ..watch
        },
    )
    .await;

    if !outcome.is_measured() {
        return None;
    }

    Some(RecoveryOutcome {
        recovery_time_ms: outcome
            .recovery_time_ms
            .map(|ms| ms + pre_watch_delay.as_millis() as i64),
        ..outcome
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Above Linux's maximum `pid_max` (2^22), so no process can hold it.
    ///
    /// `SafetyGuard::is_safe_to_kill` inspects the live process table, so a
    /// plausible-looking pid makes these tests depend on whatever happens to
    /// be running on the machine — which is how they passed locally and failed
    /// in CI, where pid 1234 belonged to a process on the critical list.
    const UNUSED_PID: u32 = 4_000_001;

    /// A queue of readings, so a test can describe pressure over time.
    fn readings(values: &[Option<f32>]) -> impl FnMut() -> Option<f32> + '_ {
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
            readings(&[Some(80.0), Some(70.0), Some(60.0), Some(5.0)]),
            || false,
            RecoveryWatch {
                poll_interval: Duration::from_secs(1),
                max_wait: Duration::from_secs(60),
                recovered_below: 10.0,
            },
        )
        .await;

        assert_eq!(outcome.psi_after, Some(5.0));
        assert_eq!(outcome.recovery_time_ms, Some(3_000));
    }

    #[tokio::test(start_paused = true)]
    async fn pressure_that_never_falls_records_the_reading_and_no_recovery() {
        let outcome = observe_recovery(
            readings(&[Some(80.0)]),
            || false,
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
        assert_eq!(outcome.psi_after, Some(80.0));
        assert_eq!(outcome.recovery_time_ms, None);
    }

    #[tokio::test(start_paused = true)]
    async fn an_immediate_recovery_is_not_rounded_up_to_a_poll() {
        let outcome = observe_recovery(
            readings(&[Some(2.0)]),
            || false,
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
    async fn an_unreadable_proc_is_not_a_recovery() {
        // `PsiMetrics::read` yields zeros when /proc/pressure is unavailable,
        // and zero is below every threshold. Treating a failed read as a
        // reading would record "recovered instantly" for a measurement that
        // never happened — the most flattering possible lie.
        let outcome = observe_recovery(
            readings(&[None]),
            || false,
            RecoveryWatch {
                poll_interval: Duration::from_secs(1),
                max_wait: Duration::from_secs(5),
                recovered_below: 10.0,
            },
        )
        .await;

        assert_eq!(outcome.psi_after, None);
        assert_eq!(outcome.recovery_time_ms, None);
        assert!(
            !outcome.is_measured(),
            "an outcome with no reading must not be written at all"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_transient_read_failure_does_not_end_the_watch() {
        // One unreadable sample in the middle must not abandon the watch or
        // discard what was already observed.
        let outcome = observe_recovery(
            readings(&[Some(80.0), None, Some(70.0), Some(4.0)]),
            || false,
            RecoveryWatch {
                poll_interval: Duration::from_secs(1),
                max_wait: Duration::from_secs(60),
                recovered_below: 10.0,
            },
        )
        .await;

        assert_eq!(outcome.psi_after, Some(4.0));
        assert_eq!(outcome.recovery_time_ms, Some(3_000));
    }

    #[tokio::test(start_paused = true)]
    async fn an_action_that_never_executes_is_never_credited() {
        use crate::enforcement::{ActionType, EnforcementQueue};

        let queue = Arc::new(EnforcementQueue::new(5));
        // The default posture: proposed, awaiting a human.
        let id = queue
            .propose_auto(
                ActionType::KillProcess {
                    pid: UNUSED_PID,
                    signal: 9,
                },
                "test".to_string(),
                "circuit_breaker".to_string(),
                None,
                false,
            )
            .await
            .unwrap();

        let executed = await_execution(&queue, &id, Duration::from_secs(1))
            .await
            .is_some();

        assert!(
            !executed,
            "a pending action must not start the recovery clock"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_rejected_action_stops_the_wait_immediately() {
        use crate::enforcement::{ActionType, EnforcementQueue};

        let queue = Arc::new(EnforcementQueue::new(3_600));
        let id = queue
            .propose_auto(
                ActionType::KillProcess {
                    pid: UNUSED_PID,
                    signal: 9,
                },
                "test".to_string(),
                "circuit_breaker".to_string(),
                None,
                false,
            )
            .await
            .unwrap();
        queue.reject(&id, "operator".to_string()).await.unwrap();

        assert!(
            await_execution(&queue, &id, Duration::from_secs(1))
                .await
                .is_none(),
            "a rejected action is a decision, not something to keep waiting on"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_pending_action_is_never_measured_however_calm_the_machine_gets() {
        use crate::enforcement::{ActionType, EnforcementQueue};

        let queue = Arc::new(EnforcementQueue::new(5));
        let id = queue
            .propose_auto(
                ActionType::KillProcess {
                    pid: UNUSED_PID,
                    signal: 9,
                },
                "test".to_string(),
                "circuit_breaker".to_string(),
                None,
                false, // the default: awaiting a human
            )
            .await
            .unwrap();

        // Pressure is perfect throughout. Measuring here would credit the
        // pending kill with a recovery that happened on its own — the failure
        // the ordering exists to prevent.
        let outcome = verify_action_outcome(
            &queue,
            &id,
            || Some(0.0),
            RecoveryWatch {
                poll_interval: Duration::from_secs(1),
                max_wait: Duration::from_secs(5),
                recovered_below: 10.0,
            },
        )
        .await;

        assert!(
            outcome.is_none(),
            "an action that never ran must produce no verification at all"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn approval_at_the_expiry_boundary_still_gets_measured() {
        use crate::enforcement::{ActionType, EnforcementQueue};

        // `approve` permits approval at `now == expires_at`, and the executor
        // only scans once a second. Exiting on the proposal's expiry would
        // abandon an action that is about to really run, leaving a real kill
        // permanently unverifiable.
        let queue = Arc::new(EnforcementQueue::new(2));
        let id = queue
            .propose_auto(
                ActionType::KillProcess {
                    pid: UNUSED_PID,
                    signal: 9,
                },
                "test".to_string(),
                "circuit_breaker".to_string(),
                None,
                false,
            )
            .await
            .unwrap();

        let late = Arc::clone(&queue);
        let late_id = id.clone();
        tokio::spawn(async move {
            // Approved right at the boundary, executed a scan later.
            tokio::time::sleep(Duration::from_secs(2)).await;
            let _ = late.approve(&late_id, "operator".to_string()).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = late.complete(&late_id).await;
        });

        assert!(
            await_execution(&queue, &id, Duration::from_millis(200))
                .await
                .is_some(),
            "an action approved at the boundary and then executed must be seen"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_kill_that_failed_is_never_treated_as_executed() {
        use crate::enforcement::{ActionType, EnforcementQueue};

        let queue = Arc::new(EnforcementQueue::new(60));
        let id = queue
            .propose_auto(
                ActionType::KillProcess {
                    pid: UNUSED_PID,
                    signal: 9,
                },
                "test".to_string(),
                "circuit_breaker".to_string(),
                None,
                true,
            )
            .await
            .unwrap();

        // What the executor now does when libc::kill returns an error.
        queue
            .fail(&id, "kill failed: No such process".to_string())
            .await
            .expect("failing an approved action is a valid transition");

        assert!(
            await_execution(&queue, &id, Duration::from_millis(200))
                .await
                .is_none(),
            "a failed kill must not start a recovery watch"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_approved_action_the_executor_never_runs_does_not_wait_forever() {
        use crate::enforcement::{ActionType, EnforcementQueue};

        let queue = Arc::new(EnforcementQueue::new(3_600));
        let id = queue
            .propose_auto(
                ActionType::KillProcess {
                    pid: UNUSED_PID,
                    signal: 9,
                },
                "test".to_string(),
                "circuit_breaker".to_string(),
                None,
                true, // approved, but nothing ever executes it
            )
            .await
            .unwrap();

        assert!(
            await_execution(&queue, &id, Duration::from_secs(1))
                .await
                .is_none(),
            "a stalled executor must not hold the watch open indefinitely"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_approval_after_the_recovery_window_is_still_measured() {
        use crate::enforcement::{ActionType, EnforcementQueue};

        // The production shape: proposals live for 300s, the recovery watch
        // runs for 120s. An operator approving at minute three is acting well
        // within the action's life, and that incident must still get an
        // outcome — borrowing the watch duration as the execution deadline
        // would abandon it at two minutes, permanently.
        let queue = Arc::new(EnforcementQueue::new(300));
        let id = queue
            .propose_auto(
                ActionType::KillProcess {
                    pid: UNUSED_PID,
                    signal: 9,
                },
                "test".to_string(),
                "circuit_breaker".to_string(),
                None,
                false,
            )
            .await
            .unwrap();

        let approver = Arc::clone(&queue);
        let late_id = id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(180)).await;
            approver
                .approve(&late_id, "operator".to_string())
                .await
                .unwrap();
            approver.complete(&late_id).await.unwrap();
        });

        let outcome = verify_action_outcome(
            &queue,
            &id,
            || Some(1.0),
            RecoveryWatch {
                poll_interval: Duration::from_secs(1),
                max_wait: Duration::from_secs(120),
                recovered_below: 10.0,
            },
        )
        .await;

        assert!(
            outcome.is_some(),
            "an action approved at 180s is inside its 300s life and must be measured"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_overlapping_execution_invalidates_the_measurement() {
        use crate::enforcement::{ActionType, EnforcementQueue};

        let queue = Arc::new(EnforcementQueue::new(60));
        let propose = |queue: Arc<EnforcementQueue>| async move {
            queue
                .propose_auto(
                    ActionType::KillProcess {
                        pid: UNUSED_PID,
                        signal: 9,
                    },
                    "test".to_string(),
                    "circuit_breaker".to_string(),
                    None,
                    true,
                )
                .await
                .unwrap()
        };

        let first = propose(Arc::clone(&queue)).await;
        queue.complete(&first).await.unwrap();

        // A second kill lands while the first is still being watched. Both
        // read the same system-wide pressure, so the fall that follows cannot
        // be attributed to the first action.
        let interferer = Arc::clone(&queue);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let second = interferer
                .propose_auto(
                    ActionType::KillProcess {
                        pid: UNUSED_PID,
                        signal: 9,
                    },
                    "test".to_string(),
                    "circuit_breaker".to_string(),
                    None,
                    true,
                )
                .await
                .unwrap();
            interferer.complete(&second).await.unwrap();
        });

        let outcome = verify_action_outcome(
            &queue,
            &first,
            || Some(50.0), // never recovers on its own
            RecoveryWatch {
                poll_interval: Duration::from_secs(1),
                max_wait: Duration::from_secs(30),
                recovered_below: 10.0,
            },
        )
        .await;

        assert!(
            outcome.is_none(),
            "a measurement overlapped by another kill must record nothing"
        );
    }

    /// Real time on purpose: `executed_at_ms` is a wall-clock stamp, so a
    /// paused clock would advance the sleeps and not the stamp, and the test
    /// would pass without testing anything. Kept to ~1.6s for that reason.
    ///
    /// The watch itself must take measurable time here: with an instant
    /// recovery, counting the observation twice adds nothing and the bug hides.
    #[tokio::test]
    async fn recovery_is_timed_from_the_kill_and_counted_once() {
        use crate::enforcement::{ActionType, EnforcementQueue};

        let queue = Arc::new(EnforcementQueue::new(60));
        let id = queue
            .propose_auto(
                ActionType::KillProcess {
                    pid: UNUSED_PID,
                    signal: 9,
                },
                "test".to_string(),
                "circuit_breaker".to_string(),
                None,
                true,
            )
            .await
            .unwrap();
        queue.complete(&id).await.unwrap();

        // The incident insert and the executor poll: real delay before anyone
        // starts watching.
        tokio::time::sleep(Duration::from_millis(1_000)).await;

        // Still stalling for two polls, then recovered: the watch spans ~600ms.
        let mut polls = 0;
        let outcome = verify_action_outcome(
            &queue,
            &id,
            move || {
                polls += 1;
                Some(if polls > 2 { 1.0 } else { 90.0 })
            },
            RecoveryWatch {
                poll_interval: Duration::from_millis(300),
                max_wait: Duration::from_secs(30),
                recovered_below: 10.0,
            },
        )
        .await
        .expect("an executed action with readable pressure is measured");

        let reported = outcome.recovery_time_ms.unwrap();

        // ~1000ms of pre-watch delay plus ~600ms of watching.
        assert!(
            reported >= 1_500,
            "recovery must be timed from the kill, got {reported}ms"
        );

        // The half that catches double counting: measuring the delay *after*
        // observing folds the watch in twice, which lands near 2200ms.
        assert!(
            reported < 2_000,
            "the observation interval must not be counted twice, got {reported}ms"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_executed_action_is_measured() {
        use crate::enforcement::{ActionType, EnforcementQueue};

        let queue = Arc::new(EnforcementQueue::new(3_600));
        let id = queue
            .propose_auto(
                ActionType::KillProcess {
                    pid: UNUSED_PID,
                    signal: 9,
                },
                "test".to_string(),
                "circuit_breaker".to_string(),
                None,
                true,
            )
            .await
            .unwrap();
        queue.complete(&id).await.unwrap();

        let outcome = verify_action_outcome(
            &queue,
            &id,
            || Some(2.0),
            RecoveryWatch {
                poll_interval: Duration::from_secs(1),
                max_wait: Duration::from_secs(5),
                recovered_below: 10.0,
            },
        )
        .await
        .expect("an executed action is measured");

        assert_eq!(outcome.recovery_time_ms, Some(0));
        assert_eq!(outcome.psi_after, Some(2.0));
    }

    #[tokio::test(start_paused = true)]
    async fn an_executed_action_with_unreadable_pressure_records_nothing() {
        use crate::enforcement::{ActionType, EnforcementQueue};

        let queue = Arc::new(EnforcementQueue::new(3_600));
        let id = queue
            .propose_auto(
                ActionType::KillProcess {
                    pid: UNUSED_PID,
                    signal: 9,
                },
                "test".to_string(),
                "circuit_breaker".to_string(),
                None,
                true,
            )
            .await
            .unwrap();
        queue.complete(&id).await.unwrap();

        assert!(
            verify_action_outcome(
                &queue,
                &id,
                || None,
                RecoveryWatch {
                    poll_interval: Duration::from_secs(1),
                    max_wait: Duration::from_secs(3),
                    recovered_below: 10.0,
                },
            )
            .await
            .is_none(),
            "nothing observed means nothing to write"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_executed_action_starts_the_watch() {
        use crate::enforcement::{ActionType, EnforcementQueue};

        let queue = Arc::new(EnforcementQueue::new(3_600));
        let id = queue
            .propose_auto(
                ActionType::KillProcess {
                    pid: UNUSED_PID,
                    signal: 9,
                },
                "test".to_string(),
                "circuit_breaker".to_string(),
                None,
                true,
            )
            .await
            .unwrap();
        queue.complete(&id).await.unwrap();

        assert!(
            await_execution(&queue, &id, Duration::from_secs(1))
                .await
                .is_some()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn pressure_exactly_at_the_threshold_counts_as_recovered() {
        // The threshold is the line the incident was declared on, so sitting
        // on it is no longer breaching.
        let outcome = observe_recovery(
            readings(&[Some(80.0), Some(10.0)]),
            || false,
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
