//! Eval suite for incident outcomes — the "did it work" half of an incident.
//!
//! `psi_after` and `recovery_time_ms` were in the schema from the start, were
//! read back by the API, and were averaged into `avg_recovery_time_ms` on
//! `/incidents/stats` — while nothing ever wrote them. These cases cover the
//! write path end to end, and the distinction the columns now have to carry:
//! "recovered", "watched and did not recover", and "never measured" are three
//! different statements.

use cognitod::incidents::outcome::RecoveryOutcome;
use cognitod::incidents::{Incident, IncidentStore};

fn incident() -> Incident {
    Incident {
        id: None,
        timestamp: 1_732_242_135,
        event_type: "circuit_breaker_cpu".to_string(),
        psi_cpu: 75.21,
        psi_memory: 12.34,
        cpu_percent: 96.3,
        load_avg: "26.00,24.20,21.30".to_string(),
        action: "auto_kill".to_string(),
        target_pid: Some(472_693),
        target_name: Some("aggressive-stress.sh".to_string()),
        system_snapshot: None,
        llm_analysis: None,
        llm_analyzed_at: None,
        investigation: None,
        recovery_time_ms: None,
        psi_after: None,
    }
}

async fn store() -> (tempfile::TempDir, IncidentStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = IncidentStore::new(dir.path().join("incidents.db"))
        .await
        .expect("fresh database should initialise");
    (dir, store)
}

#[tokio::test]
async fn an_outcome_reaches_the_row_the_api_reads_back() {
    let (_dir, store) = store().await;
    let id = store.insert(&incident()).await.unwrap();

    // Before: the state every incident has been stuck in.
    let before = store.get(id).await.unwrap().expect("incident exists");
    assert_eq!(before.psi_after, None);
    assert_eq!(before.recovery_time_ms, None);

    store
        .record_outcome(
            id,
            &RecoveryOutcome {
                psi_after: 4.5,
                recovery_time_ms: Some(3_000),
            },
        )
        .await
        .unwrap();

    let after = store.get(id).await.unwrap().expect("incident exists");
    assert_eq!(after.recovery_time_ms, Some(3_000));
    assert_eq!(after.psi_after, Some(4.5));

    // The rest of the row must be untouched — the outcome is an addition to
    // the record, not a rewrite of what was observed at the time.
    assert_eq!(after.psi_cpu, before.psi_cpu);
    assert_eq!(after.target_pid, before.target_pid);
    assert_eq!(after.action, before.action);
}

#[tokio::test]
async fn watched_but_not_recovered_is_distinguishable_from_never_measured() {
    let (_dir, store) = store().await;

    let measured = store.insert(&incident()).await.unwrap();
    let unmeasured = store.insert(&incident()).await.unwrap();

    store
        .record_outcome(
            measured,
            &RecoveryOutcome {
                psi_after: 71.0,
                recovery_time_ms: None,
            },
        )
        .await
        .unwrap();

    let watched = store.get(measured).await.unwrap().unwrap();
    let untouched = store.get(unmeasured).await.unwrap().unwrap();

    // Both have no recovery time, and they mean different things. The
    // pressure reading is what separates "we looked and it stayed bad" from
    // "nobody looked" — which is the difference between evidence a fix failed
    // and no evidence at all.
    assert_eq!(watched.recovery_time_ms, None);
    assert_eq!(watched.psi_after, Some(71.0));
    assert_eq!(untouched.recovery_time_ms, None);
    assert_eq!(untouched.psi_after, None);
}

#[tokio::test]
async fn the_stats_average_counts_only_incidents_that_recovered() {
    let (_dir, store) = store().await;

    let fast = store.insert(&incident()).await.unwrap();
    let slow = store.insert(&incident()).await.unwrap();
    let never = store.insert(&incident()).await.unwrap();
    let _unmeasured = store.insert(&incident()).await.unwrap();

    store
        .record_outcome(
            fast,
            &RecoveryOutcome {
                psi_after: 3.0,
                recovery_time_ms: Some(1_000),
            },
        )
        .await
        .unwrap();
    store
        .record_outcome(
            slow,
            &RecoveryOutcome {
                psi_after: 6.0,
                recovery_time_ms: Some(3_000),
            },
        )
        .await
        .unwrap();
    store
        .record_outcome(
            never,
            &RecoveryOutcome {
                psi_after: 80.0,
                recovery_time_ms: None,
            },
        )
        .await
        .unwrap();

    let stats = store.stats().await.unwrap();

    // 1000 and 3000 average to 2000. The incident that never recovered must
    // not be folded in as a slow recovery — that would make a failed action
    // look like a sluggish one, which is the more flattering reading.
    assert_eq!(stats.avg_recovery_time_ms, Some(2_000));
    assert_eq!(stats.total, 4);
}

#[tokio::test]
async fn the_average_stays_absent_until_something_recovers() {
    let (_dir, store) = store().await;
    let id = store.insert(&incident()).await.unwrap();

    // The state that shipped: an endpoint reporting an average over a column
    // nothing writes. It has to read as "no data", not as zero.
    assert_eq!(store.stats().await.unwrap().avg_recovery_time_ms, None);

    store
        .record_outcome(
            id,
            &RecoveryOutcome {
                psi_after: 90.0,
                recovery_time_ms: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(
        store.stats().await.unwrap().avg_recovery_time_ms,
        None,
        "an incident that never recovered contributes no recovery time"
    );
}
