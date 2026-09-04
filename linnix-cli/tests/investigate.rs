use assert_cmd::Command;
use httpmock::prelude::*;

/// Two offenders in one detection window. The victim's stall is reported once,
/// not once per offender row.
#[tokio::test]
async fn investigate_ranks_offenders_by_attributed_stall() {
    let server = MockServer::start_async().await;
    let _m = server
        .mock_async(|when, then| {
            when.method(GET)
                .path("/attribution")
                .query_param("pod", "payment-api")
                .query_param("namespace", "payments")
                .query_param("window", "20");
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    r#"{
                        "victim": {"pod": "payment-api", "namespace": "payments"},
                        "window_minutes": 20,
                        "attributions": [
                            {"offender_pod":"image-resizer","offender_namespace":"media",
                             "stall_us":1000000,"attributed_stall_us":700000,"blame_score":2.0,
                             "timestamp":100,"cpu_share":0.62,"fork_count":186,
                             "short_job_count":42,"reason":"noisy_neighbor"},
                            {"offender_pod":"etl-runner","offender_namespace":"batch",
                             "stall_us":1000000,"attributed_stall_us":300000,"blame_score":1.0,
                             "timestamp":100,"cpu_share":0.20,"fork_count":4,
                             "short_job_count":2,"reason":"fork_storm"}
                        ]
                    }"#,
                );
        })
        .await;

    Command::new(assert_cmd::cargo::cargo_bin!("linnix-cli"))
        .args([
            "--url",
            &server.base_url(),
            "--no-color",
            "investigate",
            "payments/payment-api",
            "--since",
            "20m",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("media/image-resizer"))
        .stdout(predicates::str::contains("70% of attributed stall"))
        .stdout(predicates::str::contains("1.0s"))
        .stdout(predicates::str::contains("batch/etl-runner"));
}

/// A quiet window must not produce an accusation.
#[tokio::test]
async fn investigate_reports_no_offender_found() {
    let server = MockServer::start_async().await;
    let _m = server
        .mock_async(|when, then| {
            when.method(GET).path("/attribution");
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    r#"{"victim":{"pod":"api","namespace":"payments"},
                        "window_minutes":15,"attributions":[]}"#,
                );
        })
        .await;

    Command::new(assert_cmd::cargo::cargo_bin!("linnix-cli"))
        .args([
            "--url",
            &server.base_url(),
            "--no-color",
            "investigate",
            "payments/api",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("No contention attributed"));
}

#[tokio::test]
async fn investigate_explains_missing_incident_store() {
    let server = MockServer::start_async().await;
    let _m = server
        .mock_async(|when, then| {
            when.method(GET).path("/attribution");
            then.status(503);
        })
        .await;

    Command::new(assert_cmd::cargo::cargo_bin!("linnix-cli"))
        .args([
            "--url",
            &server.base_url(),
            "--no-color",
            "investigate",
            "payments/api",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("no incident store"));
}

#[tokio::test]
async fn investigate_rejects_malformed_target() {
    Command::new(assert_cmd::cargo::cargo_bin!("linnix-cli"))
        .args(["--no-color", "investigate", "payment-api"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("NAMESPACE/POD"));
}
