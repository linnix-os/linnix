use assert_cmd::Command;
use httpmock::prelude::*;

#[tokio::test]
async fn doctor_command_checks_health() {
    let server = MockServer::start_async().await;

    // Mock healthz endpoint
    let _health = server
        .mock_async(|when, then| {
            when.method(GET).path("/healthz");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"status":"ok","version":"0.1.0"}"#);
        })
        .await;

    // Mock status endpoint with full expected structure
    let _status = server
        .mock_async(|when, then| {
            when.method(GET).path("/status");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{
                    "version": "0.2.0",
                    "uptime_s": 3600,
                    "offline": false,
                    "events_per_sec": 100,
                    "rb_overflows": 0,
                    "rate_limited": 0,
                    "kernel_version": "5.15.0",
                    "aya_version": "0.11.0",
                    "transport": "perf",
                    "active_rules": 5,
                    "probes": {"rss_probe": "enabled", "btf": true},
                    "reasoner": {"configured": true, "endpoint": "http://localhost:8090", "ilm_enabled": false},
                    "incidents_last_1h": 2,
                    "feedback_entries": 10,
                    "slack_stats": {"sent": 5, "failed": 0, "approved": 3, "denied": 1},
                    "perf_poll_errors": 0,
                    "dropped_events_total": 0
                }"#);
        })
        .await;

    Command::new(assert_cmd::cargo::cargo_bin!("linnix-cli"))
        .args(["--url", &server.base_url(), "doctor"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Linnix Doctor"));
}

#[tokio::test]
async fn doctor_command_handles_unreachable_server() {
    // Use a port that's not listening
    // Doctor command still returns success but shows FAIL in output
    Command::new(assert_cmd::cargo::cargo_bin!("linnix-cli"))
        .args(["--url", "http://127.0.0.1:59999", "doctor"])
        .assert()
        .success() // Doctor returns Ok even on connection failure
        .stdout(predicates::str::contains("FAIL"));
}
