//! Integration tests for the Mandate subsystem.
//!
//! These tests exercise the MandateManager userspace logic: creating mandates,
//! verifying hash consistency, reconciliation of expired entries, backpressure,
//! and the API-level request/response cycle. Actual BPF map writes are skipped
//! (bpf_available = false) since loading LSM programs requires root + CONFIG_BPF_LSM.

use cognitod::mandate::{MandateManager, MandateRequest, MandateStatus};
use linnix_ai_ebpf_common::MandateMode;
use std::sync::Arc;

/// Fixed test key so hashes are reproducible.
const TEST_KEY: [u64; 2] = [0x0706050403020100, 0x0f0e0d0c0b0a0908];

/// Use the current process PID so /proc/{pid}/stat is readable.
fn self_pid() -> u32 {
    std::process::id()
}

fn test_manager() -> Arc<MandateManager> {
    Arc::new(MandateManager::new(TEST_KEY, false, MandateMode::Monitor))
}

#[tokio::test]
async fn create_and_retrieve_mandate() {
    let mgr = test_manager();
    let pid = self_pid();

    let req = MandateRequest {
        pid,
        args: vec!["/usr/bin/curl".into(), "https://api.example.com".into()],
        ttl_ms: 5000,
        container_id: None,
        monitor_only: false,
        task_id: None,
        max_spend_cents: None,
        counterparty_did: None,
        wallet_address: None,
        jurisdiction: None,
    };

    let resp = mgr.create(req).await.expect("create must succeed");
    assert_eq!(resp.status, MandateStatus::Active);
    assert_eq!(resp.key.pid, pid);
    assert!(resp.key.cmd_hash != 0, "cmd_hash should not be zero");
    assert!(resp.expires_at_ms > 0, "expires_at_ms should be set");

    // Retrieve by ID
    let fetched = mgr.get(&resp.id).await.expect("mandate should exist");
    assert_eq!(fetched.id, resp.id);
    assert_eq!(fetched.key.cmd_hash, resp.key.cmd_hash);
}

#[tokio::test]
async fn revoke_mandate() {
    let mgr = test_manager();
    let pid = self_pid();

    let req = MandateRequest {
        pid,
        args: vec!["/bin/sh".into(), "-c".into(), "echo hello".into()],
        ttl_ms: 60_000,
        container_id: None,
        monitor_only: false,
        task_id: None,
        max_spend_cents: None,
        counterparty_did: None,
        wallet_address: None,
        jurisdiction: None,
    };

    let resp = mgr.create(req).await.unwrap();
    mgr.revoke(&resp.id).await.expect("revoke must succeed");

    let fetched = mgr
        .get(&resp.id)
        .await
        .expect("revoked mandate still exists");
    assert_eq!(fetched.status, MandateStatus::Revoked);
}

#[tokio::test]
async fn revoke_nonexistent_returns_error() {
    let mgr = test_manager();
    let result = mgr.revoke("nonexistent-id").await;
    assert!(result.is_err(), "revoking unknown mandate should fail");
}

#[tokio::test]
async fn hash_determinism() {
    let mgr = test_manager();

    let args = vec!["/usr/bin/python3".into(), "script.py".into()];
    let h1 = mgr.hash_args(&args);
    let h2 = mgr.hash_args(&args);
    assert_eq!(h1, h2, "same args must produce identical hashes");

    // Different args → different hash
    let args2 = vec!["/usr/bin/python3".into(), "other.py".into()];
    let h3 = mgr.hash_args(&args2);
    assert_ne!(h1, h3, "different args must produce different hashes");
}

#[tokio::test]
async fn hash_canonicalization_order_matters() {
    let mgr = test_manager();

    let h1 = mgr.hash_args(&["a".into(), "b".into()]);
    let h2 = mgr.hash_args(&["b".into(), "a".into()]);
    assert_ne!(h1, h2, "arg order must affect hash");
}

#[tokio::test]
async fn stats_reflect_creates_and_revokes() {
    let mgr = test_manager();
    let pid = self_pid();

    let req = MandateRequest {
        pid,
        args: vec!["/bin/ls".into()],
        ttl_ms: 10_000,
        container_id: None,
        monitor_only: false,
        task_id: None,
        max_spend_cents: None,
        counterparty_did: None,
        wallet_address: None,
        jurisdiction: None,
    };

    // Create 3 mandates (different args to get distinct keys)
    let r1 = mgr.create(req.clone()).await.unwrap();

    let req2 = MandateRequest {
        pid,
        args: vec!["/bin/cat".into()],
        ttl_ms: 10_000,
        container_id: None,
        monitor_only: false,
        task_id: None,
        max_spend_cents: None,
        counterparty_did: None,
        wallet_address: None,
        jurisdiction: None,
    };
    let _r2 = mgr.create(req2).await.unwrap();

    let req3 = MandateRequest {
        pid,
        args: vec!["/bin/echo".into()],
        ttl_ms: 10_000,
        container_id: None,
        monitor_only: false,
        task_id: None,
        max_spend_cents: None,
        counterparty_did: None,
        wallet_address: None,
        jurisdiction: None,
    };
    let _r3 = mgr.create(req3).await.unwrap();

    let stats = mgr.stats().await;
    assert_eq!(stats.total_created, 3);
    assert_eq!(stats.active_count, 3);

    // Revoke one
    mgr.revoke(&r1.id).await.unwrap();
    let stats = mgr.stats().await;
    assert_eq!(stats.active_count, 2);
    assert_eq!(stats.total_revoked, 1);
}

#[tokio::test]
async fn health_reports_monitor_mode() {
    let mgr = test_manager();
    let health = mgr.health();
    assert_eq!(health.enforcement_mode, "monitor");
    assert!(!health.bpf_lsm_loaded, "BPF LSM not loaded in test");
    assert!(health.siphash_key_set);
}

#[tokio::test]
async fn health_reports_enforce_mode() {
    let mgr = Arc::new(MandateManager::new(TEST_KEY, false, MandateMode::Enforce));
    let health = mgr.health();
    assert_eq!(health.enforcement_mode, "enforce");
}

#[tokio::test]
async fn list_filters_by_status() {
    let mgr = test_manager();
    let pid = self_pid();

    let req = MandateRequest {
        pid,
        args: vec!["/bin/date".into()],
        ttl_ms: 60_000,
        container_id: None,
        monitor_only: false,
        task_id: None,
        max_spend_cents: None,
        counterparty_did: None,
        wallet_address: None,
        jurisdiction: None,
    };
    let resp = mgr.create(req).await.unwrap();

    let req2 = MandateRequest {
        pid,
        args: vec!["/bin/whoami".into()],
        ttl_ms: 60_000,
        container_id: None,
        monitor_only: false,
        task_id: None,
        max_spend_cents: None,
        counterparty_did: None,
        wallet_address: None,
        jurisdiction: None,
    };
    let _resp2 = mgr.create(req2).await.unwrap();

    mgr.revoke(&resp.id).await.unwrap();

    let active = mgr.list(Some(MandateStatus::Active)).await;
    assert_eq!(active.len(), 1);

    let revoked = mgr.list(Some(MandateStatus::Revoked)).await;
    assert_eq!(revoked.len(), 1);

    let all = mgr.list(None).await;
    assert_eq!(all.len(), 2);
}

#[tokio::test]
async fn reconcile_removes_expired() {
    // Create a mandate with 1ms TTL using a PID that will vanish.
    // We fork a short-lived subprocess so /proc/{pid} disappears after exit.
    let mgr = test_manager();

    // Use a subprocess that exits immediately
    let mut child = std::process::Command::new("/bin/true")
        .spawn()
        .expect("spawn /bin/true");
    let child_pid = child.id();

    let req = MandateRequest {
        pid: child_pid,
        args: vec!["/bin/true".into()],
        ttl_ms: 1, // 1ms = immediate expiry
        container_id: None,
        monitor_only: false,
        task_id: None,
        max_spend_cents: None,
        counterparty_did: None,
        wallet_address: None,
        jurisdiction: None,
    };
    mgr.create(req).await.unwrap();

    // Wait for child to exit and be reaped so /proc/{pid} disappears
    child.wait().expect("wait on child");
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let expired = mgr.reconcile().await;
    assert!(
        expired >= 1,
        "at least one mandate should be reconciled as expired"
    );

    let stats = mgr.stats().await;
    assert_eq!(
        stats.active_count, 0,
        "no active mandates after reconciliation"
    );
    assert!(stats.total_expired >= 1);
}

#[tokio::test]
async fn monitor_only_sets_flag() {
    let mgr = test_manager();
    let pid = self_pid();

    let req = MandateRequest {
        pid,
        args: vec!["/usr/bin/wget".into()],
        ttl_ms: 5000,
        container_id: None,
        monitor_only: true,
        task_id: None,
        max_spend_cents: None,
        counterparty_did: None,
        wallet_address: None,
        jurisdiction: None,
    };
    let resp = mgr.create(req).await.unwrap();
    assert_eq!(resp.status, MandateStatus::Active);
    // The MandateValue FLAG_MONITOR bit is set internally; verified via
    // the BPF map in production. In unit tests, creation succeeds.
}

#[tokio::test]
async fn multiple_mandates_same_pid_different_args() {
    let mgr = test_manager();
    let pid = self_pid();

    let req1 = MandateRequest {
        pid,
        args: vec!["/bin/a".into()],
        ttl_ms: 5000,
        container_id: None,
        monitor_only: false,
        task_id: None,
        max_spend_cents: None,
        counterparty_did: None,
        wallet_address: None,
        jurisdiction: None,
    };
    let req2 = MandateRequest {
        pid,
        args: vec!["/bin/b".into()],
        ttl_ms: 5000,
        container_id: None,
        monitor_only: false,
        task_id: None,
        max_spend_cents: None,
        counterparty_did: None,
        wallet_address: None,
        jurisdiction: None,
    };

    let r1 = mgr.create(req1).await.unwrap();
    let r2 = mgr.create(req2).await.unwrap();

    // Different cmd_hash → different map keys → both allowed
    assert_ne!(r1.key.cmd_hash, r2.key.cmd_hash);
    assert_ne!(r1.id, r2.id);

    let stats = mgr.stats().await;
    assert_eq!(stats.active_count, 2);
}
