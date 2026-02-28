// SPDX-License-Identifier: AGPL-3.0-or-later
//
// cognitod/tests/uds_listener.rs — Unix domain socket integration tests
//
// Tests UDS config parsing, path creation, and socket permission semantics.

use cognitod::config::{ApiConfig, Config};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};

// =============================================================================
// CONFIG TESTS
// =============================================================================

#[test]
fn uds_config_defaults_to_none() {
    let api = ApiConfig::default();
    assert!(
        api.unix_socket.is_none(),
        "UDS should be disabled by default"
    );
}

#[test]
fn uds_config_parses_from_toml() {
    let toml_str = r#"
[api]
listen_addr = "0.0.0.0:3000"
unix_socket = "/var/run/linnix/cognitod.sock"
"#;
    let config: Config = toml::from_str(toml_str).expect("valid TOML");
    assert_eq!(
        config.api.unix_socket.as_deref(),
        Some("/var/run/linnix/cognitod.sock")
    );
}

#[test]
fn uds_config_absent_field_is_none() {
    let toml_str = r#"
[api]
listen_addr = "127.0.0.1:3000"
"#;
    let config: Config = toml::from_str(toml_str).expect("valid TOML");
    assert!(config.api.unix_socket.is_none());
}

#[test]
fn uds_config_round_trip() {
    let api = ApiConfig {
        listen_addr: "0.0.0.0:3000".to_string(),
        auth_token: Some("secret".to_string()),
        unix_socket: Some("/tmp/test.sock".to_string()),
    };
    let serialized = toml::to_string(&api).expect("serialize");
    let back: ApiConfig = toml::from_str(&serialized).expect("deserialize");
    assert_eq!(back.unix_socket.as_deref(), Some("/tmp/test.sock"));
    assert_eq!(back.auth_token.as_deref(), Some("secret"));
}

// =============================================================================
// UDS BIND + CONNECT (live socket test)
// =============================================================================

#[tokio::test]
async fn uds_bind_and_connect_smoke() {
    use tokio::net::UnixListener;

    let dir = tempfile::tempdir().expect("tempdir");
    let sock_path = dir.path().join("test.sock");

    let listener = UnixListener::bind(&sock_path).expect("bind");

    // Verify socket file exists with expected permissions
    let meta = std::fs::metadata(&sock_path).expect("stat");
    assert!(meta.file_type().is_socket());

    // Set permissions like production code does
    std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o660)).unwrap();
    let perms = std::fs::metadata(&sock_path).unwrap().permissions();
    assert_eq!(perms.mode() & 0o777, 0o660);

    // Connect and verify the listener accepts
    let connect_handle = tokio::spawn({
        let path = sock_path.clone();
        async move { tokio::net::UnixStream::connect(path).await }
    });

    let (accepted, _addr) = listener.accept().await.expect("accept");
    let connected = connect_handle.await.expect("join").expect("connect");

    // Both sides should have valid streams
    drop(accepted);
    drop(connected);
}

#[tokio::test]
async fn uds_stale_socket_cleanup() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock_path = dir.path().join("stale.sock");

    // Create a stale socket file
    let _first = tokio::net::UnixListener::bind(&sock_path).expect("first bind");
    drop(_first);

    // The file still exists after dropping the listener
    assert!(sock_path.exists());

    // Remove and re-bind — the pattern used in main.rs
    let _ = std::fs::remove_file(&sock_path);
    let _second = tokio::net::UnixListener::bind(&sock_path).expect("second bind after cleanup");
    assert!(sock_path.exists());
}

// =============================================================================
// NOTE: uds_routes() is defined in cognitod's binary (main.rs api module),
// not lib.rs, so it can't be tested from integration tests directly.
// The function is exercised at compile time and via the full daemon startup.
// =============================================================================
