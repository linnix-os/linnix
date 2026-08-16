//! Eval suite for stored investigations.
//!
//! The point of storing a grounded investigation separately from the raw reply
//! is that the two answer different questions: "what did the model say" and
//! "what of it could be checked". These cases cover the round trip and, more
//! importantly, the case where those two answers diverge.

use cognitod::incidents::investigation::{Fact, parse_and_ground};
use cognitod::incidents::{AnalysisOutcome, Incident, IncidentStore};
use sqlx::sqlite::SqlitePoolOptions;

fn facts() -> Vec<Fact> {
    vec![
        Fact::new("f1", "CPU usage was 96.3%"),
        Fact::new("f2", "CPU pressure stall was 75.2%"),
    ]
}

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
async fn a_grounded_investigation_survives_the_round_trip() {
    let (_dir, store) = store().await;
    let id = store.insert(&incident()).await.unwrap();

    let raw = r#"{"hypotheses":[{"reason_code":"cpu_spin",
        "statement":"A tight loop held the CPU","supporting_fact_ids":["f1","f2"],
        "confidence":0.7,"proposed_action":"Inspect the process"}]}"#;
    let outcome = AnalysisOutcome {
        raw_response: raw.to_string(),
        investigation: Some(parse_and_ground(raw, facts()).unwrap()),
        parse_error: None,
    };

    store.add_llm_analysis(id, &outcome).await.unwrap();

    let stored = store
        .get_investigation(id)
        .await
        .unwrap()
        .expect("a grounded investigation is readable");
    assert_eq!(stored.hypotheses.len(), 1);
    assert_eq!(stored.hypotheses[0].statement, "A tight loop held the CPU");
    assert_eq!(stored.hypotheses[0].model_stated_confidence, Some(0.7));

    // Rendering resolves citations through the daemon's own wording.
    assert!(stored.render().contains("CPU usage was 96.3%"));

    let incident = store.get(id).await.unwrap().unwrap();
    assert!(incident.llm_analysis.is_some());
    assert!(incident.investigation.is_some());
}

#[tokio::test]
async fn a_reply_that_invented_its_evidence_stores_no_investigation() {
    // The reply parsed, so this is not a transport failure. It simply claimed
    // things the daemon never observed, and none of it survived grounding.
    let (_dir, store) = store().await;
    let id = store.insert(&incident()).await.unwrap();

    let raw = r#"{"hypotheses":[{"reason_code":"fork_storm",
        "statement":"The checkout pod spawned 400 workers",
        "supporting_fact_ids":["f11"]}]}"#;
    let grounded = parse_and_ground(raw, facts()).unwrap();
    assert!(grounded.is_empty());

    let outcome = AnalysisOutcome {
        raw_response: raw.to_string(),
        investigation: Some(grounded),
        parse_error: None,
    };
    store.add_llm_analysis(id, &outcome).await.unwrap();

    // The empty investigation is still stored: "nothing held up" is a finding
    // about the model, and losing it would look like no analysis ever ran.
    let stored = store.get_investigation(id).await.unwrap().unwrap();
    assert!(stored.hypotheses.is_empty());
    assert_eq!(stored.discarded.len(), 1);

    // And the claim itself never reaches a reader as a conclusion.
    assert!(!stored.render().contains("checkout"));
}

#[tokio::test]
async fn an_ungroundable_reply_keeps_the_text_and_stores_no_investigation() {
    let (_dir, store) = store().await;
    let id = store.insert(&incident()).await.unwrap();

    let outcome = AnalysisOutcome {
        raw_response: "The model is warming up, try again later".to_string(),
        investigation: None,
        parse_error: Some("no JSON object in response".to_string()),
    };
    store.add_llm_analysis(id, &outcome).await.unwrap();

    assert!(store.get_investigation(id).await.unwrap().is_none());

    // The raw text is what makes this diagnosable rather than just absent.
    let incident = store.get(id).await.unwrap().unwrap();
    assert!(incident.llm_analysis.unwrap().contains("warming up"));
    assert!(incident.investigation.is_none());
}

#[tokio::test]
async fn an_old_database_gains_the_column_and_keeps_its_rows_readable() {
    // Every incident read selects the new column positionally, so if the
    // migration does not fire on an existing database, reads do not degrade —
    // they fail outright, for incidents recorded long before any of this.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("incidents.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

    {
        let pool = SqlitePoolOptions::new().connect(&db_url).await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                psi_cpu REAL NOT NULL,
                psi_memory REAL NOT NULL,
                cpu_percent REAL NOT NULL,
                load_avg TEXT NOT NULL,
                action TEXT NOT NULL,
                target_pid INTEGER,
                target_name TEXT,
                system_snapshot TEXT,
                llm_analysis TEXT,
                llm_analyzed_at INTEGER,
                recovery_time_ms INTEGER,
                psi_after REAL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO incidents (timestamp, event_type, psi_cpu, psi_memory, cpu_percent,
             load_avg, action, llm_analysis)
             VALUES (1, 'circuit_breaker_cpu', 70.0, 5.0, 90.0, '1,2,3', 'auto_kill',
                     'a paragraph of prose from the old analyzer')",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
    }

    let store = IncidentStore::new(&db_path)
        .await
        .expect("an existing database should migrate");

    let incident = store
        .get(1)
        .await
        .expect("reads must survive the upgrade")
        .expect("the pre-existing row is still there");

    // The old prose is untouched, and simply has no grounded form.
    assert!(incident.llm_analysis.unwrap().contains("old analyzer"));
    assert!(incident.investigation.is_none());
    assert!(store.get_investigation(1).await.unwrap().is_none());
}

#[tokio::test]
async fn an_unanalysed_incident_has_no_investigation() {
    let (_dir, store) = store().await;
    let id = store.insert(&incident()).await.unwrap();

    assert!(store.get_investigation(id).await.unwrap().is_none());
    let incident = store.get(id).await.unwrap().unwrap();
    assert!(incident.llm_analysis.is_none());
    assert!(incident.investigation.is_none());
}
