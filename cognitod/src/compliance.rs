// SPDX-License-Identifier: AGPL-3.0-or-later
//
// cognitod/src/compliance.rs — Linnix-Claw compliance controls (§10.3)
//
// Implements OFAC SDN screening, KYT (Know Your Transaction) threshold
// enforcement, Travel Rule metadata, and geographic restrictions.
//
// This module is feature-gated: compile with `--features compliance`.
// Without the feature, all checks are no-ops that always pass.
//
// See docs/linnix-claw/specs.md §10.3.

use anyhow::Result;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::config::ComplianceConfig;

// =============================================================================
// SCREENING RESULT
// =============================================================================

/// Outcome of a compliance screening check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScreeningResult {
    /// Entity passed all checks.
    Clear,
    /// Entity matched a sanctions list.
    Sanctioned {
        list: String,
        match_type: String,
        details: String,
    },
    /// Entity is in a blocked jurisdiction.
    BlockedJurisdiction { jurisdiction: String },
    /// KYT threshold exceeded — enhanced due diligence required.
    KytRequired {
        amount_cents: u64,
        threshold_cents: u64,
    },
    /// Screening unavailable (API down, etc.). Policy decides whether to proceed.
    Unavailable { reason: String },
}

impl ScreeningResult {
    pub fn is_blocked(&self) -> bool {
        matches!(
            self,
            Self::Sanctioned { .. } | Self::BlockedJurisdiction { .. }
        )
    }

    pub fn requires_enhanced_dd(&self) -> bool {
        matches!(self, Self::KytRequired { .. })
    }
}

impl std::fmt::Display for ScreeningResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clear => write!(f, "CLEAR"),
            Self::Sanctioned {
                list,
                match_type,
                details,
            } => {
                write!(f, "SANCTIONED ({} via {}: {})", list, match_type, details)
            }
            Self::BlockedJurisdiction { jurisdiction } => {
                write!(f, "BLOCKED_JURISDICTION ({})", jurisdiction)
            }
            Self::KytRequired {
                amount_cents,
                threshold_cents,
            } => {
                write!(
                    f,
                    "KYT_REQUIRED (${:.2} >= ${:.2})",
                    *amount_cents as f64 / 100.0,
                    *threshold_cents as f64 / 100.0,
                )
            }
            Self::Unavailable { reason } => {
                write!(f, "UNAVAILABLE ({})", reason)
            }
        }
    }
}

// =============================================================================
// COMPLIANCE AUDIT LOG
// =============================================================================

/// A single compliance decision for the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAuditEntry {
    pub timestamp: String,
    pub counterparty_did: String,
    pub wallet_address: Option<String>,
    pub check_type: String,
    pub result: ScreeningResult,
    /// Chained hash for tamper evidence (SHA-256 of previous entry + this entry).
    pub chain_hash: String,
}

// =============================================================================
// TRAVEL RULE METADATA (§10.3)
// =============================================================================

/// Travel Rule data for transactions above $3,000 (FATF threshold).
/// Attached to the off-chain receipt, never included in on-chain calldata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TravelRuleData {
    /// Originator legal name.
    pub originator_name: String,
    /// Originator account / wallet address.
    pub originator_account: String,
    /// Originator jurisdiction (ISO 3166 alpha-2).
    pub originator_jurisdiction: String,
    /// Beneficiary legal name.
    pub beneficiary_name: String,
    /// Beneficiary account / wallet address.
    pub beneficiary_account: String,
    /// Beneficiary jurisdiction (ISO 3166 alpha-2).
    pub beneficiary_jurisdiction: String,
    /// Purpose of transaction.
    pub purpose: Option<String>,
}

// =============================================================================
// SCREENING PROVIDER TRAIT
// =============================================================================

/// Provider for sanctions screening.
///
/// Implementations can be:
/// - `OfacSdnProvider` — downloads and checks against OFAC SDN list
/// - `ChainalysisProvider` — calls Chainalysis KYT API
/// - `StubProvider` — always returns Clear (for testing)
#[async_trait::async_trait]
pub trait ScreeningProvider: Send + Sync {
    fn name(&self) -> &str;
    async fn screen_did(&self, did: &str) -> Result<ScreeningResult>;
    async fn screen_wallet(&self, address: &str) -> Result<ScreeningResult>;
}

// =============================================================================
// STUB SCREENING PROVIDER (always-clear)
// =============================================================================

/// Testing/development provider that always returns Clear.
pub struct StubScreeningProvider;

#[async_trait::async_trait]
impl ScreeningProvider for StubScreeningProvider {
    fn name(&self) -> &str {
        "stub"
    }
    async fn screen_did(&self, _did: &str) -> Result<ScreeningResult> {
        Ok(ScreeningResult::Clear)
    }
    async fn screen_wallet(&self, _address: &str) -> Result<ScreeningResult> {
        Ok(ScreeningResult::Clear)
    }
}

// =============================================================================
// OFAC SDN LIST PROVIDER
// =============================================================================

/// In-memory OFAC SDN list checker.
///
/// Downloads the Specially Designated Nationals list and checks
/// counterparty DIDs/wallet addresses against it.
pub struct OfacSdnProvider {
    /// Set of blocked identifiers (lowercased wallet addresses + DID fragments).
    blocked: Arc<RwLock<HashSet<String>>>,
    /// When the list was last refreshed.
    last_refresh: Arc<RwLock<Option<Instant>>>,
}

impl Default for OfacSdnProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl OfacSdnProvider {
    pub fn new() -> Self {
        Self {
            blocked: Arc::new(RwLock::new(HashSet::new())),
            last_refresh: Arc::new(RwLock::new(None)),
        }
    }

    /// Load a set of blocked identifiers (for testing or static loading).
    pub async fn load_blocklist(&self, entries: Vec<String>) {
        let mut blocked = self.blocked.write().await;
        blocked.clear();
        for entry in entries {
            blocked.insert(entry.to_lowercase());
        }
        *self.last_refresh.write().await = Some(Instant::now());
        info!("OFAC SDN: loaded {} blocked entries", blocked.len());
    }
}

#[async_trait::async_trait]
impl ScreeningProvider for OfacSdnProvider {
    fn name(&self) -> &str {
        "ofac_sdn"
    }

    async fn screen_did(&self, did: &str) -> Result<ScreeningResult> {
        let blocked = self.blocked.read().await;
        let normalized = did.to_lowercase();
        if blocked.contains(&normalized) {
            Ok(ScreeningResult::Sanctioned {
                list: "OFAC_SDN".to_string(),
                match_type: "did_match".to_string(),
                details: format!("DID {} matched OFAC SDN list", did),
            })
        } else {
            Ok(ScreeningResult::Clear)
        }
    }

    async fn screen_wallet(&self, address: &str) -> Result<ScreeningResult> {
        let blocked = self.blocked.read().await;
        let normalized = address.to_lowercase();
        if blocked.contains(&normalized) {
            Ok(ScreeningResult::Sanctioned {
                list: "OFAC_SDN".to_string(),
                match_type: "wallet_match".to_string(),
                details: format!("Wallet {} matched OFAC SDN list", address),
            })
        } else {
            Ok(ScreeningResult::Clear)
        }
    }
}

// =============================================================================
// SCREENING CACHE
// =============================================================================

struct CachedScreening {
    result: ScreeningResult,
    expires: Instant,
}

/// TTL-based cache for screening results.
struct ScreeningCache {
    entries: HashMap<String, CachedScreening>,
    ttl: Duration,
}

impl ScreeningCache {
    fn new(ttl_hours: u64) -> Self {
        Self {
            entries: HashMap::new(),
            ttl: Duration::from_secs(ttl_hours * 3600),
        }
    }

    fn get(&self, key: &str) -> Option<&ScreeningResult> {
        self.entries.get(key).and_then(|cached| {
            if Instant::now() < cached.expires {
                Some(&cached.result)
            } else {
                None
            }
        })
    }

    fn insert(&mut self, key: String, result: ScreeningResult) {
        self.entries.insert(
            key,
            CachedScreening {
                result,
                expires: Instant::now() + self.ttl,
            },
        );
    }

    fn gc(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, v| now < v.expires);
    }
}

// =============================================================================
// COMPLIANCE ENGINE
// =============================================================================

/// Main compliance engine that coordinates screening, KYT, and jurisdiction checks.
pub struct ComplianceEngine {
    config: ComplianceConfig,
    provider: Box<dyn ScreeningProvider>,
    cache: Arc<RwLock<ScreeningCache>>,
    blocked_jurisdictions: HashSet<String>,
}

impl std::fmt::Debug for ComplianceEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComplianceEngine")
            .field("config", &self.config)
            .field("blocked_jurisdictions", &self.blocked_jurisdictions)
            .finish_non_exhaustive()
    }
}

impl ComplianceEngine {
    /// Create a new compliance engine from config.
    pub fn new(config: ComplianceConfig, provider: Box<dyn ScreeningProvider>) -> Self {
        let cache_ttl = config.screening_cache_ttl_hours;
        let blocked: HashSet<String> = config
            .blocked_jurisdictions
            .iter()
            .map(|j| j.to_uppercase())
            .collect();

        info!(
            "compliance engine initialized: provider={}, kyt_threshold=${:.2}, blocked_jurisdictions={:?}, cache_ttl={}h",
            provider.name(),
            config.kyt_threshold_cents as f64 / 100.0,
            blocked,
            cache_ttl,
        );

        Self {
            config,
            provider,
            cache: Arc::new(RwLock::new(ScreeningCache::new(cache_ttl))),
            blocked_jurisdictions: blocked,
        }
    }

    /// Create a permissive engine that skips all checks (for non-compliance builds).
    pub fn permissive() -> Self {
        Self {
            config: ComplianceConfig::default(),
            provider: Box::new(StubScreeningProvider),
            cache: Arc::new(RwLock::new(ScreeningCache::new(24))),
            blocked_jurisdictions: HashSet::new(),
        }
    }

    /// Run all pre-task compliance checks.
    ///
    /// Returns a list of results — any blocked result should abort the task.
    pub async fn pre_task_screen(
        &self,
        counterparty_did: &str,
        wallet_address: Option<&str>,
        jurisdiction: Option<&str>,
        amount_cents: u64,
    ) -> Vec<ScreeningResult> {
        let mut results = Vec::new();

        if !self.config.enabled {
            debug!("compliance disabled, skipping all checks");
            results.push(ScreeningResult::Clear);
            return results;
        }

        // (1) Jurisdiction check
        if let Some(j) = jurisdiction {
            let j_upper = j.to_uppercase();
            if self.blocked_jurisdictions.contains(&j_upper) {
                warn!("blocked jurisdiction: {}", j_upper);
                results.push(ScreeningResult::BlockedJurisdiction {
                    jurisdiction: j_upper,
                });
                return results; // Immediate block
            }
        }

        // (2) DID screening (with cache)
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(counterparty_did) {
                debug!("screening cache hit for {}", counterparty_did);
                results.push(cached.clone());
            } else {
                drop(cache); // Release read lock
                match self.provider.screen_did(counterparty_did).await {
                    Ok(result) => {
                        self.cache
                            .write()
                            .await
                            .insert(counterparty_did.to_string(), result.clone());
                        results.push(result);
                    }
                    Err(e) => {
                        results.push(ScreeningResult::Unavailable {
                            reason: e.to_string(),
                        });
                    }
                }
            }
        }

        // (3) Wallet screening (if provided)
        if let Some(addr) = wallet_address {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(addr) {
                results.push(cached.clone());
            } else {
                drop(cache);
                match self.provider.screen_wallet(addr).await {
                    Ok(result) => {
                        self.cache
                            .write()
                            .await
                            .insert(addr.to_string(), result.clone());
                        results.push(result);
                    }
                    Err(e) => {
                        results.push(ScreeningResult::Unavailable {
                            reason: e.to_string(),
                        });
                    }
                }
            }
        }

        // (4) KYT threshold check
        if amount_cents >= self.config.kyt_threshold_cents {
            results.push(ScreeningResult::KytRequired {
                amount_cents,
                threshold_cents: self.config.kyt_threshold_cents,
            });
        }

        // If nothing was pushed, mark clear
        if results.is_empty() {
            results.push(ScreeningResult::Clear);
        }

        results
    }

    /// Check if any screening result is a hard block.
    pub fn has_hard_block(results: &[ScreeningResult]) -> bool {
        results.iter().any(|r| r.is_blocked())
    }

    /// Check if Travel Rule data is required for this amount.
    pub fn requires_travel_rule(&self, amount_cents: u64) -> bool {
        // FATF Travel Rule threshold: $3,000
        amount_cents >= self.config.kyt_threshold_cents
    }

    /// Flush expired cache entries.
    pub async fn gc(&self) {
        self.cache.write().await.gc();
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ComplianceConfig {
        ComplianceConfig {
            enabled: true,
            screening_provider: "ofac_sdn".to_string(),
            screening_api_key_env: String::new(),
            screening_cache_ttl_hours: 24,
            kyt_threshold_cents: 300_000, // $3,000
            blocked_jurisdictions: vec![
                "KP".to_string(),
                "IR".to_string(),
                "CU".to_string(),
                "SY".to_string(),
            ],
        }
    }

    #[tokio::test]
    async fn clear_screening_on_good_actor() {
        let engine = ComplianceEngine::new(test_config(), Box::new(StubScreeningProvider));
        let results = engine
            .pre_task_screen("did:web:good.com", None, Some("US"), 5000)
            .await;
        assert!(results.iter().all(|r| !r.is_blocked()));
    }

    #[tokio::test]
    async fn block_sanctioned_jurisdiction() {
        let engine = ComplianceEngine::new(test_config(), Box::new(StubScreeningProvider));
        let results = engine
            .pre_task_screen("did:web:example.kp", None, Some("KP"), 100)
            .await;
        assert!(ComplianceEngine::has_hard_block(&results));
        assert!(matches!(
            results[0],
            ScreeningResult::BlockedJurisdiction { .. }
        ));
    }

    #[tokio::test]
    async fn block_sanctioned_jurisdiction_case_insensitive() {
        let engine = ComplianceEngine::new(test_config(), Box::new(StubScreeningProvider));
        let results = engine
            .pre_task_screen("did:web:example.ir", None, Some("ir"), 100)
            .await;
        assert!(ComplianceEngine::has_hard_block(&results));
    }

    #[tokio::test]
    async fn kyt_threshold_triggers() {
        let engine = ComplianceEngine::new(test_config(), Box::new(StubScreeningProvider));
        let results = engine
            .pre_task_screen("did:web:bigcorp.com", None, Some("US"), 300_000)
            .await;
        let has_kyt = results.iter().any(|r| r.requires_enhanced_dd());
        assert!(has_kyt, "KYT should be required for $3,000+");
    }

    #[tokio::test]
    async fn kyt_below_threshold_no_trigger() {
        let engine = ComplianceEngine::new(test_config(), Box::new(StubScreeningProvider));
        let results = engine
            .pre_task_screen("did:web:smallbiz.com", None, Some("US"), 299_999)
            .await;
        let has_kyt = results.iter().any(|r| r.requires_enhanced_dd());
        assert!(!has_kyt, "KYT should NOT trigger below $3,000");
    }

    #[tokio::test]
    async fn ofac_sdn_blocks_listed_did() {
        let provider = OfacSdnProvider::new();
        provider
            .load_blocklist(vec!["did:web:evil-corp.kp".to_string()])
            .await;
        let engine = ComplianceEngine::new(test_config(), Box::new(provider));

        let results = engine
            .pre_task_screen("did:web:evil-corp.kp", None, Some("US"), 100)
            .await;
        assert!(ComplianceEngine::has_hard_block(&results));
    }

    #[tokio::test]
    async fn ofac_sdn_blocks_listed_wallet() {
        let provider = OfacSdnProvider::new();
        provider
            .load_blocklist(vec!["0xdeadbeef".to_string()])
            .await;
        let engine = ComplianceEngine::new(test_config(), Box::new(provider));

        let results = engine
            .pre_task_screen("did:web:ok.com", Some("0xDeadBeef"), Some("US"), 100)
            .await;
        assert!(ComplianceEngine::has_hard_block(&results));
    }

    #[tokio::test]
    async fn screening_cache_works() {
        let engine = ComplianceEngine::new(test_config(), Box::new(StubScreeningProvider));

        // First call: populates cache
        let r1 = engine
            .pre_task_screen("did:web:cached.com", None, Some("US"), 100)
            .await;
        // Second call: should hit cache
        let r2 = engine
            .pre_task_screen("did:web:cached.com", None, Some("US"), 200)
            .await;

        assert!(!ComplianceEngine::has_hard_block(&r1));
        assert!(!ComplianceEngine::has_hard_block(&r2));
    }

    #[tokio::test]
    async fn disabled_compliance_always_clears() {
        let mut config = test_config();
        config.enabled = false;
        let engine = ComplianceEngine::new(config, Box::new(StubScreeningProvider));

        let results = engine
            .pre_task_screen("did:web:evil.kp", None, Some("KP"), 1_000_000)
            .await;
        assert!(!ComplianceEngine::has_hard_block(&results));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], ScreeningResult::Clear);
    }

    #[tokio::test]
    async fn permissive_engine_clears_all() {
        let engine = ComplianceEngine::permissive();
        let results = engine
            .pre_task_screen("did:web:anyone", None, Some("KP"), 999_999)
            .await;
        // Permissive engine has enabled=false (from ComplianceConfig::default())
        assert!(!ComplianceEngine::has_hard_block(&results));
    }

    #[tokio::test]
    async fn travel_rule_required_above_threshold() {
        let engine = ComplianceEngine::new(test_config(), Box::new(StubScreeningProvider));
        assert!(engine.requires_travel_rule(300_000));
        assert!(engine.requires_travel_rule(500_000));
        assert!(!engine.requires_travel_rule(299_999));
        assert!(!engine.requires_travel_rule(0));
    }

    #[test]
    fn screening_result_display() {
        let clear = ScreeningResult::Clear;
        assert_eq!(clear.to_string(), "CLEAR");

        let blocked = ScreeningResult::BlockedJurisdiction {
            jurisdiction: "KP".to_string(),
        };
        assert!(blocked.to_string().contains("KP"));

        let kyt = ScreeningResult::KytRequired {
            amount_cents: 500_000,
            threshold_cents: 300_000,
        };
        assert!(kyt.to_string().contains("$5000.00"));
    }

    #[test]
    fn screening_result_is_blocked() {
        assert!(!ScreeningResult::Clear.is_blocked());
        assert!(
            ScreeningResult::Sanctioned {
                list: "OFAC".to_string(),
                match_type: "did".to_string(),
                details: "test".to_string(),
            }
            .is_blocked()
        );
        assert!(
            ScreeningResult::BlockedJurisdiction {
                jurisdiction: "KP".to_string(),
            }
            .is_blocked()
        );
        assert!(
            !ScreeningResult::KytRequired {
                amount_cents: 500_000,
                threshold_cents: 300_000,
            }
            .is_blocked()
        );
        assert!(
            !ScreeningResult::Unavailable {
                reason: "error".to_string(),
            }
            .is_blocked()
        );
    }
}
