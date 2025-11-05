use assert_cmd::Command;
use httpmock::prelude::*;

#[tokio::test]
async fn stats_mode_fetches_status() {
    let server = MockServer::start_async().await;
    let _m = server
        .mock_async(|when, then| {
            when.method(GET).path("/status");
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    r#"{"cpu_pct":1.2,"rss_mb":3,"events_per_sec":4,"rb_overflows":5,"rate_limited":6,"offline":false}"#,
                );
        })
        .await;

    Command::new(assert_cmd::cargo::cargo_bin!("linnix-cli"))
        .args(["--url", &server.base_url(), "--stats"])
        .assert()
        .success()
        .stdout(predicates::str::contains("cpu_pct"));
}
