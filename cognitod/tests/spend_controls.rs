// SPDX-License-Identifier: AGPL-3.0-or-later
//
// cognitod/tests/spend_controls.rs — Phase 4 integration tests
//
// Verifies the full spend control + compliance + privacy pipeline.

use cognitod::compliance::{ComplianceEngine, OfacSdnProvider, StubScreeningProvider};
use cognitod::config::{ComplianceConfig, PerAgentLimit, SpendLimitsConfig};
use cognitod::payment::{
    NoopAdapter, PaymentAdapter, SettlementPath, StripeStubAdapter, TokenInfo,
};
use cognitod::privacy::{ReceiptRedactor, RedactionLevel};
use cognitod::spend::{SpendLimitViolation, SpendTracker};
use std::collections::HashMap;

// =============================================================================
// §9 — Spend Control Engine
// =============================================================================

#[tokio::test]
async fn spend_happy_path_within_all_limits() {
    let tracker = SpendTracker::new(SpendLimitsConfig::default());
    // $10 well within $50 per-mandate, $500 daily, $5000 monthly
    assert!(tracker.check_spend(1000, None).await.is_ok());
    tracker.record_spend(1000, None).await;
    let totals = tracker.totals().await;
    assert_eq!(totals.hourly_cents, 1000);
    assert_eq!(totals.daily_cents, 1000);
}

#[tokio::test]
async fn spend_per_mandate_boundary() {
    let tracker = SpendTracker::new(SpendLimitsConfig {
        per_mandate_cents: 5000,
        ..SpendLimitsConfig::default()
    });
    // Exact limit: OK
    assert!(tracker.check_spend(5000, None).await.is_ok());
    // One cent over: blocked
    let err = tracker.check_spend(5001, None).await.unwrap_err();
    assert!(matches!(err, SpendLimitViolation::PerMandate { .. }));
}

#[tokio::test]
async fn spend_daily_accumulation() {
    let tracker = SpendTracker::new(SpendLimitsConfig {
        per_mandate_cents: 50000, // raise to test daily
        daily_cents: 10000,       // $100 daily
        ..SpendLimitsConfig::default()
    });
    // Spend $80
    tracker.record_spend(8000, None).await;
    // $30 more would exceed $100
    let err = tracker.check_spend(3000, None).await.unwrap_err();
    assert!(matches!(err, SpendLimitViolation::Daily { .. }));
    // $20 is fine
    assert!(tracker.check_spend(2000, None).await.is_ok());
}

#[tokio::test]
async fn spend_per_agent_isolation() {
    let mut per_agent = HashMap::new();
    per_agent.insert(
        "did:web:cheap-agent.io".to_string(),
        PerAgentLimit { daily_cents: 500 },
    );
    per_agent.insert(
        "did:web:premium-agent.io".to_string(),
        PerAgentLimit { daily_cents: 10000 },
    );
    let tracker = SpendTracker::new(SpendLimitsConfig {
        per_mandate_cents: 50000,
        daily_cents: 100000,
        monthly_cents: 500000,
        hourly_cents: None,
        per_agent,
    });

    // Cheap agent: $4.50 spent → $1 more blocked
    tracker
        .record_spend(450, Some("did:web:cheap-agent.io".to_string()))
        .await;
    let err = tracker
        .check_spend(100, Some("did:web:cheap-agent.io"))
        .await
        .unwrap_err();
    assert!(matches!(err, SpendLimitViolation::PerAgentDaily { .. }));

    // Premium agent: still has $100 budget
    assert!(
        tracker
            .check_spend(9000, Some("did:web:premium-agent.io"))
            .await
            .is_ok()
    );

    // Unknown agent: no per-agent limit, uses global limits
    assert!(
        tracker
            .check_spend(5000, Some("did:web:new-agent.io"))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn spend_gc_preserves_recent_records() {
    let tracker = SpendTracker::new(SpendLimitsConfig::default());
    tracker.record_spend(100, None).await;
    tracker
        .record_spend(200, Some("did:web:a".to_string()))
        .await;
    tracker.gc().await;
    let totals = tracker.totals().await;
    assert_eq!(totals.record_count, 2); // Recent records preserved
}

// =============================================================================
// §8 — Payment Adapter & Amount Conversion
// =============================================================================

#[test]
fn usdc_conversion_table() {
    let usdc = TokenInfo::usdc_base();
    let cases = [
        (1u64, 10_000u128),       // 1 cent
        (15, 150_000),            // $0.15
        (100, 1_000_000),         // $1.00
        (5000, 50_000_000),       // $50.00
        (100_000, 1_000_000_000), // $1,000
    ];
    for (cents, expected_base) in cases {
        assert_eq!(
            usdc.cents_to_base_units(cents),
            expected_base,
            "cents={} failed",
            cents
        );
        assert_eq!(
            usdc.base_units_to_cents(expected_base),
            cents,
            "base_units={} failed",
            expected_base
        );
    }
}

#[test]
fn dai_18_decimal_conversion() {
    let dai = TokenInfo::dai_mainnet();
    // 1 cent = 10^16 base units (18 - 2 = 16)
    assert_eq!(dai.cents_to_base_units(1), 10_000_000_000_000_000);
    // $1 = 10^18 base units
    assert_eq!(dai.cents_to_base_units(100), 1_000_000_000_000_000_000);
}

#[tokio::test]
async fn stripe_stub_settles_successfully() {
    let adapter = StripeStubAdapter::new_stub();
    let path = adapter
        .resolve_settlement_path("did:web:vendor.com")
        .await
        .unwrap();
    assert!(matches!(path, SettlementPath::Webhook { .. }));

    let result = adapter.settle("{}", 1500, &path).await.unwrap();
    assert!(result.success);
    assert_eq!(result.settled_cents, 1500);
    assert!(result.reference.is_some());
}

#[tokio::test]
async fn noop_adapter_for_offline_mode() {
    let adapter = NoopAdapter;
    let path = adapter
        .resolve_settlement_path("did:web:any.com")
        .await
        .unwrap();
    assert_eq!(path, SettlementPath::Manual);

    let result = adapter.settle("{}", 999, &path).await.unwrap();
    assert!(result.success);
}

// =============================================================================
// §10.3 — Compliance Controls
// =============================================================================

#[tokio::test]
async fn compliance_blocks_sanctioned_jurisdictions() {
    let config = ComplianceConfig {
        enabled: true,
        blocked_jurisdictions: vec!["KP".to_string(), "IR".to_string()],
        ..ComplianceConfig::default()
    };
    let engine = ComplianceEngine::new(config, Box::new(StubScreeningProvider));

    // North Korea blocked
    let results = engine
        .pre_task_screen("did:web:nk-agent", None, Some("KP"), 100)
        .await;
    assert!(ComplianceEngine::has_hard_block(&results));

    // US allowed
    let results = engine
        .pre_task_screen("did:web:us-agent", None, Some("US"), 100)
        .await;
    assert!(!ComplianceEngine::has_hard_block(&results));
}

#[tokio::test]
async fn compliance_kyt_threshold_at_3000() {
    let config = ComplianceConfig {
        enabled: true,
        kyt_threshold_cents: 300_000,
        ..ComplianceConfig::default()
    };
    let engine = ComplianceEngine::new(config, Box::new(StubScreeningProvider));

    // $2,999.99 → no KYT
    let results = engine
        .pre_task_screen("did:web:ok", None, Some("US"), 299_999)
        .await;
    assert!(!results.iter().any(|r| r.requires_enhanced_dd()));

    // $3,000 → KYT required
    let results = engine
        .pre_task_screen("did:web:ok", None, Some("US"), 300_000)
        .await;
    assert!(results.iter().any(|r| r.requires_enhanced_dd()));
}

#[tokio::test]
async fn compliance_ofac_blocks_sanctioned_wallet() {
    let provider = OfacSdnProvider::new();
    provider
        .load_blocklist(vec!["0xbad_wallet".to_string()])
        .await;
    let config = ComplianceConfig {
        enabled: true,
        ..ComplianceConfig::default()
    };
    let engine = ComplianceEngine::new(config, Box::new(provider));

    let results = engine
        .pre_task_screen("did:web:ok", Some("0xBAD_WALLET"), Some("US"), 100)
        .await;
    assert!(ComplianceEngine::has_hard_block(&results));
}

#[tokio::test]
async fn compliance_disabled_passes_everything() {
    let config = ComplianceConfig {
        enabled: false,
        ..ComplianceConfig::default()
    };
    let engine = ComplianceEngine::new(config, Box::new(StubScreeningProvider));

    let results = engine
        .pre_task_screen("did:web:evil", None, Some("KP"), 999_999)
        .await;
    assert!(!ComplianceEngine::has_hard_block(&results));
}

#[tokio::test]
async fn compliance_travel_rule_check() {
    let config = ComplianceConfig {
        enabled: true,
        kyt_threshold_cents: 300_000,
        ..ComplianceConfig::default()
    };
    let engine = ComplianceEngine::new(config, Box::new(StubScreeningProvider));
    assert!(engine.requires_travel_rule(300_000));
    assert!(engine.requires_travel_rule(1_000_000));
    assert!(!engine.requires_travel_rule(299_999));
}

// =============================================================================
// §10.4 — Receipt Privacy & Redaction
// =============================================================================

#[test]
fn redaction_none_preserves_full_path() {
    let r = ReceiptRedactor::new(RedactionLevel::None);
    assert_eq!(r.redact_binary("/usr/bin/curl"), "/usr/bin/curl");
    assert_eq!(
        r.redact_url("https://api.secret.com/v1/data?key=abc123"),
        "https://api.secret.com/v1/data?key=abc123"
    );
}

#[test]
fn redaction_external_shows_basename_only() {
    let r = ReceiptRedactor::new(RedactionLevel::External);
    assert_eq!(r.redact_binary("/usr/bin/curl"), "curl");
    assert_eq!(r.redact_binary("/opt/custom/my-agent"), "my-agent");
    assert_eq!(
        r.redact_url("https://api.secret.com/v1/data?key=abc123"),
        "api.secret.com"
    );
}

#[test]
fn redaction_full_shows_category() {
    let r = ReceiptRedactor::new(RedactionLevel::Full);
    assert_eq!(r.redact_binary("/usr/bin/curl"), "network_transfer");
    assert_eq!(r.redact_binary("/usr/bin/python3"), "interpreter_execution");
    assert_eq!(r.redact_binary("/usr/bin/docker"), "container_tool");
    assert_eq!(r.redact_url("https://api.secret.com/v1/data"), "[redacted]");
}

#[test]
fn redaction_args_always_hash_only() {
    for level in [
        RedactionLevel::None,
        RedactionLevel::External,
        RedactionLevel::Full,
    ] {
        let r = ReceiptRedactor::new(level);
        assert!(
            r.should_redact_args(),
            "args must be hash-only at {:?}",
            level
        );
    }
}

// =============================================================================
// FULL PIPELINE: Spend + Compliance + Privacy together
// =============================================================================

#[tokio::test]
async fn full_pipeline_honest_task() {
    // 1. Compliance screening
    let compliance = ComplianceEngine::new(
        ComplianceConfig {
            enabled: true,
            ..ComplianceConfig::default()
        },
        Box::new(StubScreeningProvider),
    );
    let results = compliance
        .pre_task_screen("did:web:vendor.com", None, Some("US"), 1500)
        .await;
    assert!(!ComplianceEngine::has_hard_block(&results));

    // 2. Spend check
    let tracker = SpendTracker::new(SpendLimitsConfig::default());
    assert!(
        tracker
            .check_spend(1500, Some("did:web:vendor.com"))
            .await
            .is_ok()
    );

    // 3. Settle
    let adapter = StripeStubAdapter::new_stub();
    let path = adapter
        .resolve_settlement_path("did:web:vendor.com")
        .await
        .unwrap();
    let result = adapter.settle("{}", 1500, &path).await.unwrap();
    assert!(result.success);

    // 4. Record spend
    tracker
        .record_spend(1500, Some("did:web:vendor.com".to_string()))
        .await;

    // 5. Redact receipt
    let redactor = ReceiptRedactor::new(RedactionLevel::External);
    assert_eq!(redactor.redact_binary("/usr/bin/curl"), "curl");

    // 6. Verify totals
    let totals = tracker.totals().await;
    assert_eq!(totals.daily_cents, 1500);
}

#[tokio::test]
async fn full_pipeline_blocked_by_compliance() {
    let compliance = ComplianceEngine::new(
        ComplianceConfig {
            enabled: true,
            ..ComplianceConfig::default()
        },
        Box::new(StubScreeningProvider),
    );
    // Sanctioned jurisdiction
    let results = compliance
        .pre_task_screen("did:web:evil.kp", None, Some("KP"), 100)
        .await;
    assert!(ComplianceEngine::has_hard_block(&results));
    // Pipeline aborts — no spend check, no settlement
}

#[tokio::test]
async fn full_pipeline_blocked_by_spend_limit() {
    let compliance = ComplianceEngine::new(
        ComplianceConfig {
            enabled: true,
            ..ComplianceConfig::default()
        },
        Box::new(StubScreeningProvider),
    );
    // Compliance: OK
    let results = compliance
        .pre_task_screen("did:web:vendor.com", None, Some("US"), 100)
        .await;
    assert!(!ComplianceEngine::has_hard_block(&results));

    // Spend: blocked (over per-mandate limit)
    let tracker = SpendTracker::new(SpendLimitsConfig {
        per_mandate_cents: 5000,
        ..SpendLimitsConfig::default()
    });
    let err = tracker.check_spend(6000, Some("did:web:vendor.com")).await;
    assert!(err.is_err());
    // Pipeline aborts — no settlement
}

// =============================================================================
// Config parsing integration
// =============================================================================

#[test]
fn config_round_trip_spend_limits() {
    let toml = r#"
[spend_limits]
per_mandate_cents = 10000
daily_cents = 80000
monthly_cents = 800000

[spend_limits.per_agent."did:web:limited.io"]
daily_cents = 2000
"#;
    let cfg: cognitod::Config = toml::from_str(toml).unwrap();
    assert_eq!(cfg.spend_limits.per_mandate_cents, 10000);
    assert_eq!(cfg.spend_limits.daily_cents, 80000);
    assert_eq!(
        cfg.spend_limits
            .per_agent
            .get("did:web:limited.io")
            .unwrap()
            .daily_cents,
        2000
    );
}

#[test]
fn config_round_trip_compliance() {
    let toml = r#"
[compliance]
enabled = true
screening_provider = "chainalysis"
kyt_threshold_cents = 500000
blocked_jurisdictions = ["KP", "IR", "CU"]
"#;
    let cfg: cognitod::Config = toml::from_str(toml).unwrap();
    assert!(cfg.compliance.enabled);
    assert_eq!(cfg.compliance.screening_provider, "chainalysis");
    assert_eq!(cfg.compliance.kyt_threshold_cents, 500000);
}

#[test]
fn config_round_trip_receipt_privacy() {
    let toml = r#"
[receipt_privacy]
redaction_level = "full"
retention_days = 30
encrypt_db = true
"#;
    let cfg: cognitod::Config = toml::from_str(toml).unwrap();
    assert_eq!(cfg.receipt_privacy.redaction_level, "full");
    assert_eq!(cfg.receipt_privacy.retention_days, 30);
    assert!(cfg.receipt_privacy.encrypt_db);
}
