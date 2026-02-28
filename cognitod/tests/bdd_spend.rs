// SPDX-License-Identifier: AGPL-3.0-or-later
//
// cognitod/tests/bdd_spend.rs — BDD step definitions for Phase 4
//
// Cucumber-rs test runner linking Gherkin `.feature` files to Rust code.
// Run: cargo test --test bdd_spend
//
// Feature files in: cognitod/tests/features/

use std::collections::HashMap;

use cognitod::compliance::{
    ComplianceEngine, OfacSdnProvider, ScreeningResult, StubScreeningProvider,
};
use cognitod::config::{ComplianceConfig, PerAgentLimit, SpendLimitsConfig};
use cognitod::payment::{
    NoopAdapter, PaymentAdapter, PaymentResult, SettlementPath, StripeStubAdapter, TokenInfo,
};
use cognitod::privacy::{ReceiptRedactor, RedactionLevel};
use cognitod::spend::{SpendLimitViolation, SpendTracker};
use cucumber::{World, given, then, when};

// =============================================================================
// WORLD — shared test state across steps
// =============================================================================

#[derive(Debug, World)]
#[world(init = Self::new)]
pub struct ClawWorld {
    // ── Spend tracker state ──
    spend_limits: SpendLimitsConfig,
    spend_tracker: Option<SpendTracker>,
    spend_result: Option<Result<(), SpendLimitViolation>>,
    per_agent_overrides: HashMap<String, u64>,

    // ── Compliance state ──
    compliance_config: ComplianceConfig,
    compliance_results: Vec<ScreeningResult>,
    ofac_blocked_wallets: Vec<String>,
    ofac_blocked_dids: Vec<String>,
    compliance_engine: Option<ComplianceEngine>,
    compliance_checked: bool,

    // ── Payment state ──
    token: Option<TokenInfo>,
    conversion_result: Option<u128>,
    round_trip_cents: Option<u64>,
    payment_result: Option<PaymentResult>,
    settlement_path: Option<SettlementPath>,

    // ── Privacy state ──
    redaction_level: Option<RedactionLevel>,
    redacted_result: Option<String>,

    // ── Adapter marker ──
    use_noop_adapter: bool,

    // ── Pipeline state ──
    pipeline_compliance_passed: bool,
    pipeline_spend_passed: bool,
    pipeline_settled: bool,
    pipeline_settled_amount: u64,
}

impl ClawWorld {
    fn new() -> Self {
        Self {
            spend_limits: SpendLimitsConfig::default(),
            spend_tracker: None,
            spend_result: None,
            per_agent_overrides: HashMap::new(),
            compliance_config: ComplianceConfig::default(),
            compliance_results: Vec::new(),
            ofac_blocked_wallets: Vec::new(),
            ofac_blocked_dids: Vec::new(),
            compliance_engine: None,
            compliance_checked: false,
            token: None,
            conversion_result: None,
            round_trip_cents: None,
            payment_result: None,
            settlement_path: None,
            use_noop_adapter: false,
            redaction_level: None,
            redacted_result: None,
            pipeline_compliance_passed: false,
            pipeline_spend_passed: false,
            pipeline_settled: false,
            pipeline_settled_amount: 0,
        }
    }

    fn ensure_tracker(&mut self) {
        if self.spend_tracker.is_none() {
            let mut limits = self.spend_limits.clone();
            for (did, daily) in &self.per_agent_overrides {
                limits.per_agent.insert(
                    did.clone(),
                    PerAgentLimit {
                        daily_cents: *daily,
                    },
                );
            }
            self.spend_tracker = Some(SpendTracker::new(limits));
        }
    }

    async fn ensure_compliance_engine(&mut self) {
        if self.compliance_engine.is_none() {
            if !self.ofac_blocked_wallets.is_empty() || !self.ofac_blocked_dids.is_empty() {
                let provider = OfacSdnProvider::new();
                let mut blocklist: Vec<String> = self.ofac_blocked_wallets.clone();
                blocklist.extend(self.ofac_blocked_dids.clone());
                provider.load_blocklist(blocklist).await;
                self.compliance_engine = Some(ComplianceEngine::new(
                    self.compliance_config.clone(),
                    Box::new(provider),
                ));
            } else {
                self.compliance_engine = Some(ComplianceEngine::new(
                    self.compliance_config.clone(),
                    Box::new(StubScreeningProvider),
                ));
            }
        }
    }
}

// =============================================================================
// SPEND CONTROL STEPS
// =============================================================================

#[given("the default spend limits are configured")]
fn default_limits(world: &mut ClawWorld) {
    world.spend_limits = SpendLimitsConfig {
        per_mandate_cents: 5000,
        hourly_cents: None,
        daily_cents: 50000,
        monthly_cents: 500000,
        per_agent: HashMap::new(),
    };
}

#[given(expr = "{int} cents have already been spent today")]
async fn pre_spend_today(world: &mut ClawWorld, cents: u64) {
    world.ensure_tracker();
    let tracker = world.spend_tracker.as_ref().unwrap();
    // Record as a single lump (within per-mandate by using elevated limits)
    tracker.record_spend(cents, None).await;
}

#[given(expr = "an hourly limit of {int} cents is configured")]
fn set_hourly_limit(world: &mut ClawWorld, cents: u64) {
    world.spend_limits.hourly_cents = Some(cents);
    world.spend_tracker = None; // force re-create
}

#[given(expr = "{int} cents have been spent in the last hour")]
async fn pre_spend_hour(world: &mut ClawWorld, cents: u64) {
    world.ensure_tracker();
    let tracker = world.spend_tracker.as_ref().unwrap();
    tracker.record_spend(cents, None).await;
}

#[given(expr = "{int} cents have already been spent this month")]
async fn pre_spend_month(world: &mut ClawWorld, cents: u64) {
    // Raise per-mandate and daily to allow recording large amounts
    world.spend_limits.per_mandate_cents = 1_000_000;
    world.spend_limits.daily_cents = 1_000_000;
    world.spend_tracker = None;
    world.ensure_tracker();
    let tracker = world.spend_tracker.as_ref().unwrap();
    tracker.record_spend(cents, None).await;
    // Restore original per-mandate for subsequent checks
    // (the tracker is already created, so we modify via a fresh check)
}

#[given(expr = "a per-agent override for {string} of {int} cents daily")]
fn set_per_agent_override(world: &mut ClawWorld, did: String, cents: u64) {
    world.per_agent_overrides.insert(did, cents);
    world.spend_tracker = None; // force re-create with new overrides
}

#[given(expr = "the agent {string} has spent {int} cents today")]
async fn agent_pre_spend(world: &mut ClawWorld, did: String, cents: u64) {
    world.ensure_tracker();
    let tracker = world.spend_tracker.as_ref().unwrap();
    tracker.record_spend(cents, Some(did)).await;
}

#[when(expr = "an agent requests a mandate for {int} cents")]
async fn check_spend_anonymous(world: &mut ClawWorld, cents: u64) {
    world.ensure_tracker();
    let tracker = world.spend_tracker.as_ref().unwrap();
    world.spend_result = Some(tracker.check_spend(cents, None).await);
}

#[when(expr = "{string} requests a mandate for {int} cents")]
async fn check_spend_agent(world: &mut ClawWorld, did: String, cents: u64) {
    world.ensure_tracker();
    let tracker = world.spend_tracker.as_ref().unwrap();
    world.spend_result = Some(tracker.check_spend(cents, Some(&did)).await);
}

// (Monthly scenario split into two separate scenarios; no compound step needed)

#[then("the spend check should pass")]
fn spend_passes(world: &mut ClawWorld) {
    let result = world
        .spend_result
        .take()
        .expect("no spend check was performed");
    assert!(result.is_ok(), "expected spend to pass, got: {:?}", result);
}

#[then(expr = "the spend check should fail with {string}")]
fn spend_fails_with(world: &mut ClawWorld, violation_type: String) {
    let result = world
        .spend_result
        .take()
        .expect("no spend check was performed");
    let err = result.expect_err("expected spend to fail, but it passed");
    let err_debug = format!("{:?}", err);
    assert!(
        err_debug.starts_with(&violation_type),
        "expected {} violation, got: {}",
        violation_type,
        err_debug
    );
}

// =============================================================================
// COMPLIANCE STEPS
// =============================================================================

#[given(expr = "compliance is enabled with blocked jurisdictions {string}")]
fn compliance_with_jurisdictions(world: &mut ClawWorld, jurisdictions: String) {
    world.compliance_config = ComplianceConfig {
        enabled: true,
        blocked_jurisdictions: jurisdictions
            .split(',')
            .map(|s| s.trim().to_string())
            .collect(),
        ..ComplianceConfig::default()
    };
    world.compliance_engine = None;
}

#[given(expr = "compliance is enabled with KYT threshold of {int} cents")]
fn compliance_with_kyt(world: &mut ClawWorld, threshold: u64) {
    world.compliance_config = ComplianceConfig {
        enabled: true,
        kyt_threshold_cents: threshold,
        ..ComplianceConfig::default()
    };
    world.compliance_engine = None;
}

#[given("compliance is disabled")]
fn compliance_disabled(world: &mut ClawWorld) {
    world.compliance_config = ComplianceConfig {
        enabled: false,
        ..ComplianceConfig::default()
    };
    world.compliance_engine = None;
}

#[given(expr = "the OFAC SDN list contains wallet {string}")]
fn ofac_add_wallet(world: &mut ClawWorld, wallet: String) {
    world.ofac_blocked_wallets.push(wallet);
    // Ensure compliance is enabled when using OFAC lists
    world.compliance_config.enabled = true;
    world.compliance_engine = None;
}

#[given(expr = "the OFAC SDN list contains DID {string}")]
fn ofac_add_did(world: &mut ClawWorld, did: String) {
    world.ofac_blocked_dids.push(did);
    // Ensure compliance is enabled when using OFAC lists
    world.compliance_config.enabled = true;
    world.compliance_engine = None;
}

#[when(expr = "a task is proposed with counterparty {string} in jurisdiction {string}")]
async fn propose_task_jurisdiction(world: &mut ClawWorld, did: String, jurisdiction: String) {
    world.ensure_compliance_engine().await;
    let engine = world.compliance_engine.as_ref().unwrap();
    world.compliance_results = engine
        .pre_task_screen(&did, None, Some(&jurisdiction), 100)
        .await;
    world.compliance_checked = true;
}

#[when(expr = "a task involves wallet {string} for {int} cents")]
async fn propose_task_wallet(world: &mut ClawWorld, wallet: String, cents: u64) {
    world.ensure_compliance_engine().await;
    let engine = world.compliance_engine.as_ref().unwrap();
    world.compliance_results = engine
        .pre_task_screen("did:web:test", Some(&wallet), Some("US"), cents)
        .await;
    world.compliance_checked = true;
}

#[when(expr = "a task is proposed for {int} cents")]
async fn propose_task_amount(world: &mut ClawWorld, cents: u64) {
    world.ensure_compliance_engine().await;
    let engine = world.compliance_engine.as_ref().unwrap();
    world.compliance_results = engine
        .pre_task_screen("did:web:test", None, Some("US"), cents)
        .await;
    world.compliance_checked = true;
}

#[then("the compliance check should hard-block")]
fn compliance_blocks(world: &mut ClawWorld) {
    assert!(
        world.compliance_checked,
        "no compliance check was performed"
    );
    assert!(
        ComplianceEngine::has_hard_block(&world.compliance_results),
        "expected hard block, got: {:?}",
        world.compliance_results
    );
}

#[then("the compliance check should pass")]
fn compliance_passes(world: &mut ClawWorld) {
    assert!(
        world.compliance_checked,
        "no compliance check was performed"
    );
    assert!(
        !ComplianceEngine::has_hard_block(&world.compliance_results),
        "expected pass, got hard block: {:?}",
        world.compliance_results
    );
}

#[then("the compliance result should require enhanced due diligence")]
fn compliance_requires_edd(world: &mut ClawWorld) {
    assert!(
        world
            .compliance_results
            .iter()
            .any(|r| r.requires_enhanced_dd()),
        "expected KYT required, got: {:?}",
        world.compliance_results
    );
}

#[then("the compliance result should not require enhanced due diligence")]
fn compliance_no_edd(world: &mut ClawWorld) {
    assert!(
        !world
            .compliance_results
            .iter()
            .any(|r| r.requires_enhanced_dd()),
        "expected no KYT, got: {:?}",
        world.compliance_results
    );
}

#[then(expr = "Travel Rule data is required for {int} cents")]
async fn travel_rule_required(world: &mut ClawWorld, cents: u64) {
    world.ensure_compliance_engine().await;
    let engine = world.compliance_engine.as_ref().unwrap();
    assert!(
        engine.requires_travel_rule(cents),
        "expected Travel Rule required for {} cents",
        cents
    );
}

#[then(expr = "Travel Rule data is not required for {int} cents")]
async fn travel_rule_not_required(world: &mut ClawWorld, cents: u64) {
    world.ensure_compliance_engine().await;
    let engine = world.compliance_engine.as_ref().unwrap();
    assert!(
        !engine.requires_travel_rule(cents),
        "expected Travel Rule NOT required for {} cents",
        cents
    );
}

// =============================================================================
// PAYMENT ADAPTER STEPS
// =============================================================================

#[given(expr = "the token is USDC with {int} decimals")]
fn set_token_usdc(world: &mut ClawWorld, _decimals: u32) {
    world.token = Some(TokenInfo::usdc_base());
}

#[given(expr = "the token is DAI with {int} decimals")]
fn set_token_dai(world: &mut ClawWorld, _decimals: u32) {
    world.token = Some(TokenInfo::dai_mainnet());
}

#[given("a Stripe stub payment adapter")]
fn set_stripe_adapter(world: &mut ClawWorld) {
    // adapter created on-the-fly in when-step
    let _ = world; // no state needed beyond marker
}

#[given("a noop payment adapter")]
fn set_noop_adapter(world: &mut ClawWorld) {
    world.use_noop_adapter = true;
}

#[when(expr = "converting {int} cents to base units")]
fn convert_to_base(world: &mut ClawWorld, cents: u64) {
    let token = world.token.as_ref().expect("token not set");
    world.conversion_result = Some(token.cents_to_base_units(cents));
}

#[when(expr = "converting {int} cents to base units and back")]
fn convert_round_trip(world: &mut ClawWorld, cents: u64) {
    let token = world.token.as_ref().expect("token not set");
    let base = token.cents_to_base_units(cents);
    let back = token.base_units_to_cents(base);
    world.round_trip_cents = Some(back);
}

#[when(expr = "settling a receipt for {int} cents")]
async fn settle_receipt(world: &mut ClawWorld, cents: u64) {
    // Use the adapter type marker set by Given steps
    let adapter: Box<dyn PaymentAdapter> = if world.use_noop_adapter {
        Box::new(NoopAdapter)
    } else {
        Box::new(StripeStubAdapter::new_stub())
    };
    let path = adapter
        .resolve_settlement_path("did:web:test")
        .await
        .unwrap();
    let result = adapter.settle("{}", cents, &path).await.unwrap();
    world.settlement_path = Some(path);
    world.payment_result = Some(result);
}

#[then(expr = "the result should be {int} base units")]
fn check_base_units(world: &mut ClawWorld, expected: u128) {
    let actual = world.conversion_result.expect("no conversion result");
    assert_eq!(
        actual, expected,
        "expected {} base units, got {}",
        expected, actual
    );
}

#[then(expr = "the round-trip result should equal {int} cents")]
fn check_round_trip(world: &mut ClawWorld, expected: u64) {
    let actual = world.round_trip_cents.expect("no round-trip result");
    assert_eq!(actual, expected);
}

#[then("the settlement should succeed")]
fn settlement_succeeds(world: &mut ClawWorld) {
    let result = world.payment_result.as_ref().expect("no payment result");
    assert!(result.success, "settlement failed: {}", result.message);
}

#[then(expr = "the settled amount should be {int} cents")]
fn check_settled_amount(world: &mut ClawWorld, expected: u64) {
    let result = world.payment_result.as_ref().expect("no payment result");
    assert_eq!(result.settled_cents, expected);
}

#[then(expr = "the settlement path should be {string}")]
fn check_settlement_path(world: &mut ClawWorld, expected: String) {
    let path = world.settlement_path.as_ref().expect("no settlement path");
    let path_str = format!("{:?}", path);
    assert!(
        path_str.contains(&expected),
        "expected path containing '{}', got: {}",
        expected,
        path_str
    );
}

// =============================================================================
// RECEIPT PRIVACY STEPS
// =============================================================================

#[given(expr = "redaction level is {string}")]
fn set_redaction_level(world: &mut ClawWorld, level: String) {
    world.redaction_level = Some(level.parse().expect("invalid redaction level"));
}

#[when(expr = "redacting binary {string}")]
fn redact_binary(world: &mut ClawWorld, binary: String) {
    let level = world.redaction_level.expect("redaction level not set");
    let redactor = ReceiptRedactor::new(level);
    world.redacted_result = Some(redactor.redact_binary(&binary));
}

#[when(expr = "redacting URL {string}")]
fn redact_url(world: &mut ClawWorld, url: String) {
    let level = world.redaction_level.expect("redaction level not set");
    let redactor = ReceiptRedactor::new(level);
    world.redacted_result = Some(redactor.redact_url(&url));
}

#[then(expr = "the result should be {string}")]
fn check_redacted_result(world: &mut ClawWorld, expected: String) {
    let actual = world.redacted_result.as_ref().expect("no redacted result");
    assert_eq!(
        actual, &expected,
        "expected '{}', got '{}'",
        expected, actual
    );
}

#[then("arguments should be hash-only")]
fn args_hash_only(world: &mut ClawWorld) {
    let level = world.redaction_level.expect("redaction level not set");
    let redactor = ReceiptRedactor::new(level);
    assert!(
        redactor.should_redact_args(),
        "args must be hash-only at {:?}",
        level
    );
}

// =============================================================================
// FULL PIPELINE STEPS
// =============================================================================

#[given(expr = "the spend limit is {int} cents per mandate")]
fn pipeline_spend_limit(world: &mut ClawWorld, cents: u64) {
    world.spend_limits.per_mandate_cents = cents;
    world.spend_tracker = None;
}

#[given(expr = "compliance is enabled with {word} jurisdiction allowed")]
fn pipeline_compliance_allowed(world: &mut ClawWorld, _jurisdiction: String) {
    world.compliance_config = ComplianceConfig {
        enabled: true,
        ..ComplianceConfig::default()
    };
    world.compliance_engine = None;
}

#[given(expr = "compliance is enabled with {word} jurisdiction blocked")]
fn pipeline_compliance_blocked(world: &mut ClawWorld, jurisdiction: String) {
    world.compliance_config = ComplianceConfig {
        enabled: true,
        blocked_jurisdictions: vec![jurisdiction],
        ..ComplianceConfig::default()
    };
    world.compliance_engine = None;
}

#[when(expr = "agent {string} in {string} proposes a {int}-cent task")]
async fn pipeline_propose(world: &mut ClawWorld, did: String, jurisdiction: String, cents: u64) {
    // Step 1: Compliance
    world.ensure_compliance_engine().await;
    let engine = world.compliance_engine.as_ref().unwrap();
    world.compliance_results = engine
        .pre_task_screen(&did, None, Some(&jurisdiction), cents)
        .await;
    world.compliance_checked = true;
    world.pipeline_compliance_passed = !ComplianceEngine::has_hard_block(&world.compliance_results);

    if !world.pipeline_compliance_passed {
        return;
    }

    // Step 2: Spend check
    world.ensure_tracker();
    let tracker = world.spend_tracker.as_ref().unwrap();
    let spend_result = tracker.check_spend(cents, Some(&did)).await;
    world.pipeline_spend_passed = spend_result.is_ok();
    world.spend_result = Some(spend_result);

    if !world.pipeline_spend_passed {
        return;
    }

    // Step 3: Settle
    let adapter = StripeStubAdapter::new_stub();
    let path = adapter.resolve_settlement_path(&did).await.unwrap();
    let result = adapter.settle("{}", cents, &path).await.unwrap();
    world.pipeline_settled = result.success;
    world.pipeline_settled_amount = result.settled_cents;
    world.payment_result = Some(result);
}

#[then("compliance screening passes")]
fn pipeline_compliance_passes(world: &mut ClawWorld) {
    assert!(
        world.pipeline_compliance_passed,
        "compliance was expected to pass but blocked: {:?}",
        world.compliance_results
    );
}

#[then("compliance screening blocks the task")]
fn pipeline_compliance_blocks(world: &mut ClawWorld) {
    assert!(
        !world.pipeline_compliance_passed,
        "compliance was expected to block but passed"
    );
}

#[then("the spend check passes")]
fn pipeline_spend_passes(world: &mut ClawWorld) {
    assert!(
        world.pipeline_spend_passed,
        "spend check was expected to pass"
    );
}

#[then(expr = "the spend check fails with {string}")]
fn pipeline_spend_fails(world: &mut ClawWorld, violation_type: String) {
    assert!(
        !world.pipeline_spend_passed,
        "spend check passed unexpectedly"
    );
    if let Some(Err(err)) = &world.spend_result {
        let err_debug = format!("{:?}", err);
        assert!(
            err_debug.starts_with(&violation_type),
            "expected {} violation, got: {}",
            violation_type,
            err_debug
        );
    }
}

#[then(expr = "settlement succeeds for {int} cents")]
fn pipeline_settlement_ok(world: &mut ClawWorld, cents: u64) {
    assert!(world.pipeline_settled, "settlement did not occur");
    assert_eq!(world.pipeline_settled_amount, cents);
}

#[then("no settlement occurs")]
fn pipeline_no_settlement(world: &mut ClawWorld) {
    assert!(
        !world.pipeline_settled,
        "settlement occurred but was not expected"
    );
}

#[then(expr = "the binary {string} is redacted to {string}")]
fn pipeline_redact_check(world: &mut ClawWorld, binary: String, expected: String) {
    let level = world.redaction_level.unwrap_or(RedactionLevel::External);
    let redactor = ReceiptRedactor::new(level);
    let actual = redactor.redact_binary(&binary);
    assert_eq!(actual, expected);
}

// =============================================================================
// MAIN — cucumber runner
// =============================================================================

fn main() {
    let runner = ClawWorld::cucumber().max_concurrent_scenarios(Some(4));

    // Run synchronously (cucumber handles its own async runtime)
    futures::executor::block_on(runner.run("tests/features/"));
}
