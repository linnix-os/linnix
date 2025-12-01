use assert_cmd::Command;
use httpmock::prelude::*;

#[tokio::test]
async fn processes_command_lists_processes() {
    let server = MockServer::start_async().await;
    let _m = server
        .mock_async(|when, then| {
            when.method(GET).path("/processes");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"[{"pid":1234,"comm":"test_proc","ppid":1,"cpu_pct":5.0,"rss_mb":100}]"#);
        })
        .await;

    Command::new(assert_cmd::cargo::cargo_bin!("linnix-cli"))
        .args(["--url", &server.base_url(), "processes"])
        .assert()
        .success();
}

#[tokio::test]
async fn processes_command_handles_empty_list() {
    let server = MockServer::start_async().await;
    let _m = server
        .mock_async(|when, then| {
            when.method(GET).path("/processes");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"[]"#);
        })
        .await;

    Command::new(assert_cmd::cargo::cargo_bin!("linnix-cli"))
        .args(["--url", &server.base_url(), "processes"])
        .assert()
        .success();
}
