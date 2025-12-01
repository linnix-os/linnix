use assert_cmd::Command;
use httpmock::prelude::*;

#[tokio::test]
async fn stream_receives_events() {
    let server = MockServer::start_async().await;

    // Mock stream endpoint with SSE events
    let body = r#"data: {"event_type":"Exec","pid":1234,"ppid":1,"comm":"test","ts":1234567890}

"#;
    let _m = server
        .mock_async(|when, then| {
            when.method(GET).path("/stream");
            then.status(200)
                .header("content-type", "text/event-stream")
                .body(body);
        })
        .await;

    // Default mode is streaming, which will exit after receiving the single event
    Command::new(assert_cmd::cargo::cargo_bin!("linnix-cli"))
        .args(["--url", &server.base_url(), "--no-color"])
        .timeout(std::time::Duration::from_secs(2))
        .assert()
        .success();
}

#[tokio::test]
async fn stream_handles_heartbeats() {
    let server = MockServer::start_async().await;

    // Mock stream endpoint with heartbeat followed by event
    let body = ": heartbeat\n\ndata: {\"event_type\":\"Exec\",\"pid\":1234,\"ppid\":1,\"comm\":\"test\",\"ts\":1234567890}\n\n";
    let _m = server
        .mock_async(|when, then| {
            when.method(GET).path("/stream");
            then.status(200)
                .header("content-type", "text/event-stream")
                .body(body);
        })
        .await;

    Command::new(assert_cmd::cargo::cargo_bin!("linnix-cli"))
        .args(["--url", &server.base_url(), "--no-color"])
        .timeout(std::time::Duration::from_secs(2))
        .assert()
        .success();
}
