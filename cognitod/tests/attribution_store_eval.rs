//! Eval suite for persisted stall attributions.
//!
//! The `/attribution` endpoint and the Prometheus villain counter must agree on
//! what "stall attributed to this offender" means. These cases cover the
//! storage path that feeds the endpoint — fresh installs, upgrades from a
//! database written before the split existed, and the round trip an SRE sees
//! when they query a victim.

use cognitod::collectors::psi::BlameAttribution;
use cognitod::incidents::IncidentStore;
use sqlx::sqlite::SqlitePoolOptions;

fn attribution(offender: &str, blame: f64, attributed_us: u64) -> BlameAttribution {
    BlameAttribution {
        victim_pod: "payment-api".to_string(),
        victim_namespace: "prod".to_string(),
        offender_pod: offender.to_string(),
        offender_namespace: "prod".to_string(),
        blame_score: blame,
        stall_us: 900_000,
        attributed_stall_us: attributed_us,
        timestamp: now_secs(),
        cpu_share: 0.8,
        fork_count: 12,
        short_job_count: 3,
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn a_stored_attribution_reports_the_offender_share_not_the_victim_total() {
    let dir = tempfile::tempdir().unwrap();
    let store = IncidentStore::new(dir.path().join("incidents.db"))
        .await
        .expect("fresh database should initialise");

    // One 900ms stall split 2:1 between two offenders.
    store
        .insert_stall_attribution(&attribution("image-resize-worker", 2.0, 600_000))
        .await
        .expect("insert should succeed on a fresh schema");
    store
        .insert_stall_attribution(&attribution("batch-etl", 1.0, 300_000))
        .await
        .expect("insert should succeed on a fresh schema");

    let rows = store
        .query_attributions("payment-api", "prod", 300)
        .await
        .unwrap();

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].offender_pod, "image-resize-worker");
    assert_eq!(rows[0].attributed_stall_us, Some(600_000));
    assert_eq!(rows[1].attributed_stall_us, Some(300_000));

    // The victim total is still reported, and still the same on both rows —
    // which is exactly why the endpoint needs the attributed figure too.
    assert_eq!(rows[0].stall_us, 900_000);
    assert_eq!(rows[1].stall_us, 900_000);

    // The shares must not sum past the stall that actually happened.
    let attributed: u64 = rows.iter().filter_map(|r| r.attributed_stall_us).sum();
    assert!(attributed <= rows[0].stall_us);
}

#[tokio::test]
async fn upgrading_an_old_database_backfills_the_offender_share() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("incidents.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

    // A database as written before the attributed share existed: no such
    // column, and every offender row carrying the victim's whole stall.
    {
        let pool = SqlitePoolOptions::new().connect(&db_url).await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE stall_attributions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_pod TEXT NOT NULL,
                victim_namespace TEXT NOT NULL,
                offender_pod TEXT NOT NULL,
                offender_namespace TEXT NOT NULL,
                stall_us INTEGER NOT NULL,
                blame_score REAL NOT NULL,
                timestamp INTEGER NOT NULL,
                cpu_share REAL DEFAULT 0.0,
                fork_count INTEGER DEFAULT 0,
                short_job_count INTEGER DEFAULT 0
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        // Two offenders of one 900ms event, blamed 3:1.
        for (offender, blame) in [("noisy-neighbour", 3.0), ("quiet-neighbour", 1.0)] {
            sqlx::query(
                "INSERT INTO stall_attributions (victim_pod, victim_namespace, offender_pod,
                 offender_namespace, stall_us, blame_score, timestamp)
                 VALUES ('payment-api', 'prod', ?, 'prod', 900000, ?, 1700000000)",
            )
            .bind(offender)
            .bind(blame)
            .execute(&pool)
            .await
            .unwrap();
        }
        pool.close().await;
    }

    // Opening the store must migrate the schema and reconcile the old rows
    // rather than leaving them claiming the full stall each.
    let store = IncidentStore::new(&db_path)
        .await
        .expect("opening an older database should migrate it");

    let window = (now_secs() - 1_700_000_000 + 60) as i64;
    let rows = store
        .query_attributions("payment-api", "prod", window)
        .await
        .unwrap();

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].offender_pod, "noisy-neighbour");
    assert_eq!(
        rows[0].attributed_stall_us,
        Some(675_000),
        "3/4 of the 900ms stall"
    );
    assert_eq!(
        rows[1].attributed_stall_us,
        Some(225_000),
        "1/4 of the 900ms stall"
    );

    // Inserting after the migration must still work, which is the check that
    // the ALTER path and the CREATE path produce the same schema.
    store
        .insert_stall_attribution(&attribution("late-arrival", 1.0, 100_000))
        .await
        .expect("insert should succeed after migration");
}

#[tokio::test]
async fn two_events_in_one_second_are_backfilled_separately() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("incidents.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

    {
        let pool = SqlitePoolOptions::new().connect(&db_url).await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE stall_attributions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_pod TEXT NOT NULL,
                victim_namespace TEXT NOT NULL,
                offender_pod TEXT NOT NULL,
                offender_namespace TEXT NOT NULL,
                stall_us INTEGER NOT NULL,
                blame_score REAL NOT NULL,
                timestamp INTEGER NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        // Timestamps have one-second resolution, and one victim can stall twice
        // within a second — its containers are scanned separately and collapse
        // to the same pod key. These two events must not pool their blame.
        //
        // Event A: 400ms stall, blamed 3:1. Event B: 800ms stall, blamed 1:1.
        for (offender, stall, blame) in [
            ("hog-a", 400_000, 3.0),
            ("hog-b", 400_000, 1.0),
            ("hog-c", 800_000, 1.0),
            ("hog-d", 800_000, 1.0),
        ] {
            sqlx::query(
                "INSERT INTO stall_attributions (victim_pod, victim_namespace, offender_pod,
                 offender_namespace, stall_us, blame_score, timestamp)
                 VALUES ('payment-api', 'prod', ?, 'prod', ?, ?, 1700000000)",
            )
            .bind(offender)
            .bind(stall as i64)
            .bind(blame)
            .execute(&pool)
            .await
            .unwrap();
        }
        pool.close().await;
    }

    let store = IncidentStore::new(&db_path).await.unwrap();
    let window = (now_secs() - 1_700_000_000 + 60) as i64;
    let rows = store
        .query_attributions("payment-api", "prod", window)
        .await
        .unwrap();

    let share = |pod: &str| {
        rows.iter()
            .find(|r| r.offender_pod == pod)
            .unwrap()
            .attributed_stall_us
    };

    // Each event renormalises within itself: 3:1 of 400ms, and 1:1 of 800ms.
    assert_eq!(share("hog-a"), Some(300_000));
    assert_eq!(share("hog-b"), Some(100_000));
    assert_eq!(share("hog-c"), Some(400_000));
    assert_eq!(share("hog-d"), Some(400_000));

    // Pooling the denominators would leave each event's shares reconciling to
    // neither stall; here both add up exactly.
    let event_a: u64 = [share("hog-a"), share("hog-b")].iter().flatten().sum();
    let event_b: u64 = [share("hog-c"), share("hog-d")].iter().flatten().sum();
    assert_eq!(event_a, 400_000);
    assert_eq!(event_b, 800_000);
}

#[tokio::test]
async fn a_row_with_no_recoverable_blame_stays_unknown_rather_than_zero() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("incidents.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

    {
        let pool = SqlitePoolOptions::new().connect(&db_url).await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE stall_attributions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_pod TEXT NOT NULL,
                victim_namespace TEXT NOT NULL,
                offender_pod TEXT NOT NULL,
                offender_namespace TEXT NOT NULL,
                stall_us INTEGER NOT NULL,
                blame_score REAL NOT NULL,
                timestamp INTEGER NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        // Zero blame: there is nothing to renormalise against, so the share is
        // genuinely unknown. Reporting 0 would assert the offender caused no
        // stall, which is a different and false claim.
        sqlx::query(
            "INSERT INTO stall_attributions (victim_pod, victim_namespace, offender_pod,
             offender_namespace, stall_us, blame_score, timestamp)
             VALUES ('payment-api', 'prod', 'mystery-pod', 'prod', 900000, 0.0, 1700000000)",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
    }

    let store = IncidentStore::new(&db_path).await.unwrap();
    let window = (now_secs() - 1_700_000_000 + 60) as i64;
    let rows = store
        .query_attributions("payment-api", "prod", window)
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].attributed_stall_us, None,
        "an unrecoverable share must read as unknown, not as zero stall caused"
    );
}

/// The property a permalink rests on: fixed bounds give the same answer later.
///
/// A relative window cannot promise this — it slides — so anything shareable
/// has to resolve to absolute timestamps first. This is the test that would
/// fail if `query_attributions_between` ever reintroduced `now`.
#[tokio::test]
async fn absolute_bounds_return_the_same_rows_however_much_later_they_are_asked() {
    let dir = tempfile::tempdir().unwrap();
    let store = IncidentStore::new(dir.path().join("incidents.db"))
        .await
        .expect("fresh database should initialise");

    let at = now_secs();
    let mut old = attribution("image-resize-worker", 2.0, 600_000);
    old.timestamp = at - 3_600; // an hour ago, outside any short window
    store.insert_stall_attribution(&old).await.unwrap();

    let bounds = (at as i64 - 3_660, at as i64 - 3_540);

    let first = store
        .query_attributions_between("payment-api", "prod", bounds.0, bounds.1)
        .await
        .unwrap();
    assert_eq!(first.len(), 1, "the row should be inside the fixed bounds");

    // A newer stall lands. The fixed window must not notice it, or a link
    // shared during an incident would keep growing new evidence afterwards.
    store
        .insert_stall_attribution(&attribution("batch-etl", 1.0, 300_000))
        .await
        .unwrap();

    let second = store
        .query_attributions_between("payment-api", "prod", bounds.0, bounds.1)
        .await
        .unwrap();
    assert_eq!(
        second.len(),
        1,
        "a fixed window must not pick up rows written after it was cited"
    );
    assert_eq!(second[0].offender_pod, first[0].offender_pod);
    assert_eq!(second[0].attributed_stall_us, first[0].attributed_stall_us);
}

/// One-second timestamp resolution means an exclusive upper bound silently
/// drops whatever was recorded in the current second — the rows most likely to
/// matter while an incident is live.
#[tokio::test]
async fn a_row_written_on_the_upper_bound_is_included() {
    let dir = tempfile::tempdir().unwrap();
    let store = IncidentStore::new(dir.path().join("incidents.db"))
        .await
        .expect("fresh database should initialise");

    let at = now_secs();
    let mut row = attribution("image-resize-worker", 2.0, 600_000);
    row.timestamp = at;
    store.insert_stall_attribution(&row).await.unwrap();

    let rows = store
        .query_attributions_between("payment-api", "prod", at as i64 - 60, at as i64)
        .await
        .unwrap();

    assert_eq!(
        rows.len(),
        1,
        "the instant named as the end of the window is part of it"
    );
}
