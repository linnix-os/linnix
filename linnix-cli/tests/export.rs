use assert_cmd::Command;
use httpmock::prelude::*;

#[tokio::test]
async fn export_generates_report() {
    let server = MockServer::start_async().await;
    let events_body = r#"[{"pid":2,"ppid":1,"comm":"bash","argv":["ENV=secret","/bin/ls","arg"]}]"#;
    let _m_events = server
        .mock_async(|when, then| {
            when.method(GET)
                .path("/events")
                .query_param("since", "15m")
                .query_param("rule", "fork_storm");
            then.status(200)
                .header("content-type", "application/json")
                .body(events_body);
        })
        .await;
    let _m_status = server
        .mock_async(|when, then| {
            when.method(GET).path("/status");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"cpu_pct":1.0,"rss_mb":2}"#);
        })
        .await;

    Command::new(assert_cmd::cargo::cargo_bin!("linnix-cli"))
        .args([
            "--url",
            &server.base_url(),
            "export",
            "--since",
            "15m",
            "--rule",
            "fork_storm",
            "--format",
            "txt",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("Top suspect: 1 -> 2"))
        .stdout(predicates::str::contains("argv_hash"));
}
