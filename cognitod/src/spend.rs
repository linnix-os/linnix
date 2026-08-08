// SPDX-License-Identifier: AGPL-3.0-or-later
//
// cognitod/src/spend.rs — Linnix-Claw spend control engine (§9)
//
// Enforces per-mandate, per-hour, daily, monthly, and per-agent spending limits.
// All amounts are in USD cents (integer). The kernel enforces authorization
// (is this command allowed?); cognitod enforces economics (can we afford this?).
//
// See docs/linnix-claw/specs.md §9.1–§9.3.

use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

use crate::config::SpendLimitsConfig;

// =============================================================================
// SPEND LIMIT VIOLATION
// =============================================================================

/// Describes which limit was exceeded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SpendLimitViolation {
    /// Single mandate exceeds per-mandate cap.
    PerMandate {
        requested_cents: u64,
        limit_cents: u64,
    },
    /// Hourly aggregate would be exceeded.
    Hourly {
        current_cents: u64,
        requested_cents: u64,
        limit_cents: u64,
    },
    /// Daily aggregate would be exceeded.
    Daily {
        current_cents: u64,
        requested_cents: u64,
        limit_cents: u64,
    },
    /// Monthly aggregate would be exceeded.
    Monthly {
        current_cents: u64,
        requested_cents: u64,
        limit_cents: u64,
    },
    /// Per-agent daily override exceeded.
    PerAgentDaily {
        agent_did: String,
        current_cents: u64,
        requested_cents: u64,
        limit_cents: u64,
    },
}

impl std::fmt::Display for SpendLimitViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PerMandate {
                requested_cents,
                limit_cents,
            } => write!(
                f,
                "per-mandate limit exceeded: ${:.2} > ${:.2}",
                *requested_cents as f64 / 100.0,
                *limit_cents as f64 / 100.0
            ),
            Self::Hourly {
                current_cents,
                requested_cents,
                limit_cents,
            } => write!(
                f,
                "hourly limit exceeded: current ${:.2} + ${:.2} > ${:.2}",
                *current_cents as f64 / 100.0,
                *requested_cents as f64 / 100.0,
                *limit_cents as f64 / 100.0
            ),
            Self::Daily {
                current_cents,
                requested_cents,
                limit_cents,
            } => write!(
                f,
                "daily limit exceeded: current ${:.2} + ${:.2} > ${:.2}",
                *current_cents as f64 / 100.0,
                *requested_cents as f64 / 100.0,
                *limit_cents as f64 / 100.0
            ),
            Self::Monthly {
                current_cents,
                requested_cents,
                limit_cents,
            } => write!(
                f,
                "monthly limit exceeded: current ${:.2} + ${:.2} > ${:.2}",
                *current_cents as f64 / 100.0,
                *requested_cents as f64 / 100.0,
                *limit_cents as f64 / 100.0
            ),
            Self::PerAgentDaily {
                agent_did,
                current_cents,
                requested_cents,
                limit_cents,
            } => write!(
                f,
                "per-agent daily limit for {} exceeded: ${:.2} + ${:.2} > ${:.2}",
                agent_did,
                *current_cents as f64 / 100.0,
                *requested_cents as f64 / 100.0,
                *limit_cents as f64 / 100.0
            ),
        }
    }
}

// =============================================================================
// SPEND RECORD — tracks a single committed spend
// =============================================================================

#[derive(Debug, Clone)]
struct SpendRecord {
    /// Amount in cents.
    amount_cents: u64,
    /// Counterparty agent DID (if known).
    agent_did: Option<String>,
    /// Timestamp of the spend.
    timestamp: SystemTime,
}

// =============================================================================
// SPEND TRACKER
// =============================================================================

/// Tracks and enforces aggregate spending limits.
///
/// Thread-safe via `Arc<RwLock<_>>` — designed to be shared across
/// the mandate API handlers.
///
/// Limits (from §9.1):
/// - `per_mandate_cents` — max per individual mandate (default $50)
/// - `hourly_cents` — max aggregate per hour (if configured)
/// - `daily_cents` — max aggregate per day (default $500)
/// - `monthly_cents` — max aggregate per month (default $5,000)
/// - `per_agent` — per-counterparty daily overrides
pub struct SpendTracker {
    limits: SpendLimitsConfig,
    /// Rolling window of all spend records.
    ledger: Arc<RwLock<Vec<SpendRecord>>>,
}

impl std::fmt::Debug for SpendTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpendTracker")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl SpendTracker {
    /// Create a new tracker from config limits.
    pub fn new(limits: SpendLimitsConfig) -> Self {
        info!(
            "spend tracker initialized: per_mandate=${:.2}, hourly=${}, daily=${:.2}, monthly=${:.2}, per_agent_overrides={}",
            limits.per_mandate_cents as f64 / 100.0,
            limits
                .hourly_cents
                .map_or("unlimited".to_string(), |c| format!(
                    "{:.2}",
                    c as f64 / 100.0
                )),
            limits.daily_cents as f64 / 100.0,
            limits.monthly_cents as f64 / 100.0,
            limits.per_agent.len(),
        );
        Self {
            limits,
            ledger: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Check whether a proposed spend would violate any limit.
    ///
    /// Returns `Ok(())` if allowed, or `Err(SpendLimitViolation)` if not.
    /// Does NOT commit the spend — call `record_spend` after execution.
    pub async fn check_spend(
        &self,
        amount_cents: u64,
        counterparty_did: Option<&str>,
    ) -> Result<(), SpendLimitViolation> {
        // (1) Per-mandate check
        if amount_cents > self.limits.per_mandate_cents {
            return Err(SpendLimitViolation::PerMandate {
                requested_cents: amount_cents,
                limit_cents: self.limits.per_mandate_cents,
            });
        }

        let now = SystemTime::now();
        let ledger = self.ledger.read().await;

        // (2) Hourly aggregate
        if let Some(hourly_limit) = self.limits.hourly_cents {
            let hour_ago = now - Duration::from_secs(3600);
            let hourly_total: u64 = ledger
                .iter()
                .filter(|r| r.timestamp >= hour_ago)
                .map(|r| r.amount_cents)
                .sum();
            if hourly_total + amount_cents > hourly_limit {
                return Err(SpendLimitViolation::Hourly {
                    current_cents: hourly_total,
                    requested_cents: amount_cents,
                    limit_cents: hourly_limit,
                });
            }
        }

        // (3) Daily aggregate (rolling 24h window)
        let day_ago = now - Duration::from_secs(86400);
        let daily_total: u64 = ledger
            .iter()
            .filter(|r| r.timestamp >= day_ago)
            .map(|r| r.amount_cents)
            .sum();
        if daily_total + amount_cents > self.limits.daily_cents {
            return Err(SpendLimitViolation::Daily {
                current_cents: daily_total,
                requested_cents: amount_cents,
                limit_cents: self.limits.daily_cents,
            });
        }

        // (4) Monthly aggregate (rolling 30-day window)
        let month_ago = now - Duration::from_secs(30 * 86400);
        let monthly_total: u64 = ledger
            .iter()
            .filter(|r| r.timestamp >= month_ago)
            .map(|r| r.amount_cents)
            .sum();
        if monthly_total + amount_cents > self.limits.monthly_cents {
            return Err(SpendLimitViolation::Monthly {
                current_cents: monthly_total,
                requested_cents: amount_cents,
                limit_cents: self.limits.monthly_cents,
            });
        }

        // (5) Per-agent daily override (let_chains stabilized in Rust 1.82)
        if let Some(did) = counterparty_did
            && let Some(agent_limit) = self.limits.per_agent.get(did)
        {
            let agent_daily: u64 = ledger
                .iter()
                .filter(|r| r.timestamp >= day_ago)
                .filter(|r| r.agent_did.as_deref() == Some(did))
                .map(|r| r.amount_cents)
                .sum();
            if agent_daily + amount_cents > agent_limit.daily_cents {
                return Err(SpendLimitViolation::PerAgentDaily {
                    agent_did: did.to_string(),
                    current_cents: agent_daily,
                    requested_cents: amount_cents,
                    limit_cents: agent_limit.daily_cents,
                });
            }
        }

        Ok(())
    }

    /// Record a committed spend. Call after successful mandate execution.
    pub async fn record_spend(&self, amount_cents: u64, counterparty_did: Option<String>) {
        let record = SpendRecord {
            amount_cents,
            agent_did: counterparty_did,
            timestamp: SystemTime::now(),
        };
        debug!(
            "recording spend: ${:.2}{}",
            amount_cents as f64 / 100.0,
            record
                .agent_did
                .as_ref()
                .map_or(String::new(), |d| format!(" to {}", d))
        );
        self.ledger.write().await.push(record);
    }

    /// Evict records older than the retention window (31 days).
    /// Called periodically to prevent unbounded memory growth.
    pub async fn gc(&self) {
        let cutoff = SystemTime::now() - Duration::from_secs(31 * 86400);
        let mut ledger = self.ledger.write().await;
        let before = ledger.len();
        ledger.retain(|r| r.timestamp >= cutoff);
        let after = ledger.len();
        if before != after {
            info!("spend tracker GC: evicted {} old records", before - after);
        }
    }

    /// Current totals for observability.
    pub async fn totals(&self) -> SpendTotals {
        let now = SystemTime::now();
        let hour_ago = now - Duration::from_secs(3600);
        let day_ago = now - Duration::from_secs(86400);
        let month_ago = now - Duration::from_secs(30 * 86400);
        let ledger = self.ledger.read().await;

        let hourly_cents = ledger
            .iter()
            .filter(|r| r.timestamp >= hour_ago)
            .map(|r| r.amount_cents)
            .sum();
        let daily_cents = ledger
            .iter()
            .filter(|r| r.timestamp >= day_ago)
            .map(|r| r.amount_cents)
            .sum();
        let monthly_cents = ledger
            .iter()
            .filter(|r| r.timestamp >= month_ago)
            .map(|r| r.amount_cents)
            .sum();
        let record_count = ledger.len();

        SpendTotals {
            hourly_cents,
            daily_cents,
            monthly_cents,
            record_count,
        }
    }

    /// Per-agent daily totals for the last 24h.
    pub async fn per_agent_totals(&self) -> HashMap<String, u64> {
        let day_ago = SystemTime::now() - Duration::from_secs(86400);
        let ledger = self.ledger.read().await;
        let mut totals: HashMap<String, u64> = HashMap::new();
        for record in ledger.iter().filter(|r| r.timestamp >= day_ago) {
            if let Some(did) = &record.agent_did {
                *totals.entry(did.clone()).or_default() += record.amount_cents;
            }
        }
        totals
    }

    /// Get current limits (for API introspection).
    pub fn limits(&self) -> &SpendLimitsConfig {
        &self.limits
    }
}

/// Summary of aggregate spending for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendTotals {
    pub hourly_cents: u64,
    pub daily_cents: u64,
    pub monthly_cents: u64,
    pub record_count: usize,
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PerAgentLimit;

    fn default_limits() -> SpendLimitsConfig {
        SpendLimitsConfig {
            per_mandate_cents: 5000,   // $50
            hourly_cents: Some(10000), // $100/hr
            daily_cents: 50000,        // $500/day
            monthly_cents: 500000,     // $5,000/mo
            per_agent: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn allow_spend_within_limits() {
        let tracker = SpendTracker::new(default_limits());
        // Well under all limits
        assert!(tracker.check_spend(100, None).await.is_ok());
        assert!(tracker.check_spend(5000, None).await.is_ok());
    }

    #[tokio::test]
    async fn reject_per_mandate_exceeded() {
        let tracker = SpendTracker::new(default_limits());
        let err = tracker.check_spend(5001, None).await.unwrap_err();
        assert!(matches!(err, SpendLimitViolation::PerMandate { .. }));
    }

    #[tokio::test]
    async fn reject_daily_exceeded() {
        let tracker = SpendTracker::new(SpendLimitsConfig {
            per_mandate_cents: 50000, // raise per-mandate
            hourly_cents: None,       // no hourly limit
            daily_cents: 50000,       // $500/day
            monthly_cents: 500000,
            per_agent: HashMap::new(),
        });
        // Spend close to daily limit
        tracker.record_spend(49000, None).await;
        // This should push over
        let err = tracker.check_spend(2000, None).await.unwrap_err();
        assert!(matches!(err, SpendLimitViolation::Daily { .. }));
    }

    #[tokio::test]
    async fn reject_hourly_exceeded() {
        let tracker = SpendTracker::new(default_limits());
        // Spend close to hourly limit
        tracker.record_spend(9500, None).await;
        let err = tracker.check_spend(600, None).await.unwrap_err();
        assert!(matches!(err, SpendLimitViolation::Hourly { .. }));
    }

    #[tokio::test]
    async fn reject_monthly_exceeded() {
        let tracker = SpendTracker::new(SpendLimitsConfig {
            per_mandate_cents: 100000, // raise per-mandate to not hit it first
            hourly_cents: None,        // no hourly
            daily_cents: 1_000_000,    // raise daily
            monthly_cents: 500000,     // $5k/mo
            per_agent: HashMap::new(),
        });
        // Push near monthly limit in chunks ≤ per_mandate
        for _ in 0..5 {
            tracker.record_spend(99000, None).await;
        }
        // 5 * $990 = $4950 → adding $100 = $5050 > $5000
        let err = tracker.check_spend(10000, None).await.unwrap_err();
        assert!(matches!(err, SpendLimitViolation::Monthly { .. }));
    }

    #[tokio::test]
    async fn per_agent_override_blocks() {
        let mut limits = default_limits();
        limits.per_agent.insert(
            "did:web:untrusted.io".to_string(),
            PerAgentLimit { daily_cents: 1000 },
        );
        let tracker = SpendTracker::new(limits);
        let did = "did:web:untrusted.io";

        // Under global limit but at per-agent limit
        tracker.record_spend(900, Some(did.to_string())).await;
        let err = tracker.check_spend(200, Some(did)).await.unwrap_err();
        assert!(matches!(err, SpendLimitViolation::PerAgentDaily { .. }));
    }

    #[tokio::test]
    async fn per_agent_override_allows_other_agents() {
        let mut limits = default_limits();
        limits.per_agent.insert(
            "did:web:untrusted.io".to_string(),
            PerAgentLimit { daily_cents: 1000 },
        );
        let tracker = SpendTracker::new(limits);

        // Spend against the restricted agent
        tracker
            .record_spend(900, Some("did:web:untrusted.io".to_string()))
            .await;

        // A different agent should not be affected by that override
        assert!(
            tracker
                .check_spend(900, Some("did:web:trusted.io"))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn record_and_totals() {
        let tracker = SpendTracker::new(default_limits());
        tracker.record_spend(1000, None).await;
        tracker
            .record_spend(2000, Some("did:web:a".to_string()))
            .await;
        let totals = tracker.totals().await;
        assert_eq!(totals.hourly_cents, 3000);
        assert_eq!(totals.daily_cents, 3000);
        assert_eq!(totals.monthly_cents, 3000);
        assert_eq!(totals.record_count, 2);
    }

    #[tokio::test]
    async fn per_agent_totals() {
        let tracker = SpendTracker::new(default_limits());
        tracker
            .record_spend(500, Some("did:web:a".to_string()))
            .await;
        tracker
            .record_spend(300, Some("did:web:b".to_string()))
            .await;
        tracker
            .record_spend(200, Some("did:web:a".to_string()))
            .await;
        let per_agent = tracker.per_agent_totals().await;
        assert_eq!(per_agent.get("did:web:a"), Some(&700));
        assert_eq!(per_agent.get("did:web:b"), Some(&300));
    }

    #[tokio::test]
    async fn gc_preserves_recent() {
        let tracker = SpendTracker::new(default_limits());
        tracker.record_spend(1000, None).await;
        tracker.gc().await;
        let totals = tracker.totals().await;
        assert_eq!(totals.record_count, 1);
    }

    #[tokio::test]
    async fn exact_limit_allowed() {
        let tracker = SpendTracker::new(default_limits());
        // Exactly at per-mandate limit
        assert!(tracker.check_spend(5000, None).await.is_ok());
    }

    #[tokio::test]
    async fn zero_spend_always_allowed() {
        let tracker = SpendTracker::new(default_limits());
        assert!(tracker.check_spend(0, None).await.is_ok());
    }

    #[tokio::test]
    async fn violation_display_formatting() {
        let v = SpendLimitViolation::PerMandate {
            requested_cents: 10000,
            limit_cents: 5000,
        };
        let s = v.to_string();
        assert!(s.contains("$100.00"));
        assert!(s.contains("$50.00"));
    }

    #[tokio::test]
    async fn multiple_agents_independent_tracking() {
        let mut limits = default_limits();
        limits.per_agent.insert(
            "did:web:agent-a".to_string(),
            PerAgentLimit { daily_cents: 2000 },
        );
        limits.per_agent.insert(
            "did:web:agent-b".to_string(),
            PerAgentLimit { daily_cents: 3000 },
        );
        let tracker = SpendTracker::new(limits);

        // Agent A spends $19
        tracker
            .record_spend(1900, Some("did:web:agent-a".to_string()))
            .await;
        // Agent A blocked at $20 + $2 > $20
        let err = tracker
            .check_spend(200, Some("did:web:agent-a"))
            .await
            .unwrap_err();
        assert!(matches!(err, SpendLimitViolation::PerAgentDaily { .. }));

        // Agent B still has room ($30 limit, $0 spent)
        assert!(
            tracker
                .check_spend(2500, Some("did:web:agent-b"))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn no_hourly_limit_when_none() {
        let tracker = SpendTracker::new(SpendLimitsConfig {
            per_mandate_cents: 100000,
            hourly_cents: None,
            daily_cents: 200000,
            monthly_cents: 500000,
            per_agent: HashMap::new(),
        });
        // Spend way over what an hourly limit would catch,
        // but there's no hourly limit configured
        tracker.record_spend(50000, None).await;
        tracker.record_spend(50000, None).await;
        // Still under daily; no hourly check
        assert!(tracker.check_spend(50000, None).await.is_ok());
    }
}
