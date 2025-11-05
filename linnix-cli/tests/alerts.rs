use assert_cmd::Command;
use httpmock::prelude::*;

#[tokio::test]
async fn alerts_mode_streams() {
    let server = MockServer::start_async().await;
    let body =
        "data: {\"rule\":\"r1\",\"severity\":\"High\",\"message\":\"m1\",\"host\":\"h\"}\n\n";
    let _m = server
        .mock_async(|when, then| {
            when.method(GET).path("/alerts");
            then.status(200)
                .header("content-type", "text/event-stream")
                .body(body);
        })
        .await;

    Command::new(assert_cmd::cargo::cargo_bin!("linnix-cli"))
        .args(["--url", &server.base_url(), "--alerts", "--no-color"])
        .assert()
        .success()
        .stdout(predicates::str::contains("[HIGH]"));
}
