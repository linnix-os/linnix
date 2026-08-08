// SPDX-License-Identifier: AGPL-3.0-or-later
//
// cognitod/src/payment.rs — Linnix-Claw fiat gateway adapter (§8)
//
// Defines the `PaymentAdapter` trait for fiat ↔ stablecoin operations
// and provides a Stripe stub implementation. The adapter handles:
// - Converting cents (API/Config units) to token base units (contract units)
// - Off-chain settlement via webhooks (§8.3)
// - Invoice/billing artifact generation (§8.4)
//
// All amounts in cognitod are USD cents (integer). Convert on the boundary.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// =============================================================================
// AMOUNT CONVERSION (§8.5)
// =============================================================================

/// Token metadata for cent ↔ base-unit conversion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Human-readable name (e.g., "USD Coin").
    pub name: String,
    /// Symbol (e.g., "USDC").
    pub symbol: String,
    /// Number of decimal places (6 for USDC, 18 for DAI).
    pub decimals: u8,
    /// Contract address (hex, EIP-55 checksummed).
    pub address: String,
    /// Chain ID (e.g., 8453 for Base).
    pub chain_id: u64,
}

impl TokenInfo {
    /// Convert USD cents to token base units.
    ///
    /// Formula: `base_units = cents × 10^(decimals - 2)`
    ///
    /// # Examples
    /// - USDC (6 dec): 15 cents → 150_000 base units
    /// - DAI (18 dec): 15 cents → 150_000_000_000_000_000 base units
    pub fn cents_to_base_units(&self, cents: u64) -> u128 {
        if self.decimals < 2 {
            // Tokens with < 2 decimals: integer math rounds down
            cents as u128 / 10u128.pow(2 - self.decimals as u32)
        } else {
            cents as u128 * 10u128.pow(self.decimals as u32 - 2)
        }
    }

    /// Convert token base units to USD cents.
    ///
    /// Formula: `cents = base_units / 10^(decimals - 2)`
    pub fn base_units_to_cents(&self, base_units: u128) -> u64 {
        if self.decimals < 2 {
            (base_units * 10u128.pow(2 - self.decimals as u32)) as u64
        } else {
            (base_units / 10u128.pow(self.decimals as u32 - 2)) as u64
        }
    }

    /// Well-known USDC on Base (chain 8453).
    pub fn usdc_base() -> Self {
        Self {
            name: "USD Coin".to_string(),
            symbol: "USDC".to_string(),
            decimals: 6,
            address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".to_string(),
            chain_id: 8453,
        }
    }

    /// Well-known USDC on Base Sepolia (testnet).
    pub fn usdc_base_sepolia() -> Self {
        Self {
            name: "USD Coin".to_string(),
            symbol: "USDC".to_string(),
            decimals: 6,
            address: "0x036CbD53842c5426634e7929541eC2318f3dCF7e".to_string(),
            chain_id: 84532,
        }
    }

    /// Well-known DAI on Ethereum mainnet.
    pub fn dai_mainnet() -> Self {
        Self {
            name: "Dai Stablecoin".to_string(),
            symbol: "DAI".to_string(),
            decimals: 18,
            address: "0x6B175474E89094C44Da98b954EedeAC495271d0F".to_string(),
            chain_id: 1,
        }
    }
}

// =============================================================================
// PAYMENT ADAPTER TRAIT (§8.1–§8.3)
// =============================================================================

/// The settlement path chosen for a given task.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SettlementPath {
    /// On-chain ERC-20 transfer via TaskSettlement contract.
    OnChain { chain_id: u64, token: String },
    /// Off-chain webhook (Stripe, SAP, etc.).
    Webhook { endpoint: String },
    /// Manual / out-of-band settlement.
    Manual,
}

/// Result of a payment operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentResult {
    /// Whether the payment was successful.
    pub success: bool,
    /// Transaction reference (tx hash, invoice ID, etc.).
    pub reference: Option<String>,
    /// Human-readable status message.
    pub message: String,
    /// Amount in USD cents that was settled.
    pub settled_cents: u64,
}

/// Trait for fiat / stablecoin settlement adapters.
///
/// Implementations handle the boundary between cognitod's cents-based
/// accounting and external payment rails. The trait is object-safe
/// for dynamic dispatch.
#[async_trait]
pub trait PaymentAdapter: Send + Sync {
    /// Human-readable name of the adapter (e.g., "stripe", "on-chain-base").
    fn name(&self) -> &str;

    /// Determine the settlement path for a counterparty.
    ///
    /// Inspects the counterparty's agent card to decide: on-chain, webhook, or manual.
    async fn resolve_settlement_path(&self, counterparty_did: &str) -> Result<SettlementPath>;

    /// Submit a receipt for settlement.
    ///
    /// The adapter converts `amount_cents` to the appropriate units and
    /// submits to the chosen payment rail.
    async fn settle(
        &self,
        receipt_json: &str,
        amount_cents: u64,
        path: &SettlementPath,
    ) -> Result<PaymentResult>;

    /// Check the status of a previously submitted settlement.
    async fn check_status(&self, reference: &str) -> Result<PaymentResult>;
}

// =============================================================================
// STRIPE STUB ADAPTER
// =============================================================================

/// Stub adapter for off-chain Stripe settlement.
///
/// In production, this would call the Stripe API to create payment intents
/// or invoices. For Phase 4 (MVP), it validates the flow without real API calls.
pub struct StripeStubAdapter {
    /// Stripe API key (from env or config). Empty in stub mode.
    #[allow(dead_code)]
    api_key: String,
    /// Whether to actually call Stripe (false = stub).
    live: bool,
}

impl StripeStubAdapter {
    /// Create a new stub adapter (no real API calls).
    pub fn new_stub() -> Self {
        Self {
            api_key: String::new(),
            live: false,
        }
    }

    /// Create a live adapter with a Stripe API key.
    #[allow(dead_code)]
    pub fn new_live(api_key: String) -> Self {
        Self {
            api_key,
            live: true,
        }
    }
}

#[async_trait]
impl PaymentAdapter for StripeStubAdapter {
    fn name(&self) -> &str {
        if self.live {
            "stripe-live"
        } else {
            "stripe-stub"
        }
    }

    async fn resolve_settlement_path(&self, _counterparty_did: &str) -> Result<SettlementPath> {
        // Stub: always returns webhook path
        Ok(SettlementPath::Webhook {
            endpoint: "https://api.stripe.com/v1/payment_intents".to_string(),
        })
    }

    async fn settle(
        &self,
        _receipt_json: &str,
        amount_cents: u64,
        path: &SettlementPath,
    ) -> Result<PaymentResult> {
        if !self.live {
            log::info!(
                "stripe-stub: would settle ${:.2} via {:?}",
                amount_cents as f64 / 100.0,
                path
            );
            return Ok(PaymentResult {
                success: true,
                reference: Some(format!("stub_pi_{}", uuid::Uuid::new_v4())),
                message: "stub settlement recorded".to_string(),
                settled_cents: amount_cents,
            });
        }

        // Live mode would call Stripe here.
        // For now, return an error indicating live mode is not yet implemented.
        anyhow::bail!("Stripe live mode not yet implemented")
    }

    async fn check_status(&self, reference: &str) -> Result<PaymentResult> {
        if !self.live {
            return Ok(PaymentResult {
                success: true,
                reference: Some(reference.to_string()),
                message: "stub: payment confirmed".to_string(),
                settled_cents: 0,
            });
        }
        anyhow::bail!("Stripe live mode not yet implemented")
    }
}

// =============================================================================
// NO-OP ADAPTER (for testing / offline mode)
// =============================================================================

/// No-op adapter that always succeeds. Used in offline/test mode.
pub struct NoopAdapter;

#[async_trait]
impl PaymentAdapter for NoopAdapter {
    fn name(&self) -> &str {
        "noop"
    }

    async fn resolve_settlement_path(&self, _counterparty_did: &str) -> Result<SettlementPath> {
        Ok(SettlementPath::Manual)
    }

    async fn settle(
        &self,
        _receipt_json: &str,
        amount_cents: u64,
        _path: &SettlementPath,
    ) -> Result<PaymentResult> {
        Ok(PaymentResult {
            success: true,
            reference: None,
            message: "noop: no settlement performed".to_string(),
            settled_cents: amount_cents,
        })
    }

    async fn check_status(&self, _reference: &str) -> Result<PaymentResult> {
        Ok(PaymentResult {
            success: true,
            reference: None,
            message: "noop".to_string(),
            settled_cents: 0,
        })
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Amount conversion tests ──

    #[test]
    fn usdc_cents_to_base_units() {
        let usdc = TokenInfo::usdc_base();
        assert_eq!(usdc.cents_to_base_units(1), 10_000); // 1 cent = 10,000
        assert_eq!(usdc.cents_to_base_units(15), 150_000); // $0.15
        assert_eq!(usdc.cents_to_base_units(100), 1_000_000); // $1.00
        assert_eq!(usdc.cents_to_base_units(5000), 50_000_000); // $50.00
    }

    #[test]
    fn dai_cents_to_base_units() {
        let dai = TokenInfo::dai_mainnet();
        assert_eq!(dai.cents_to_base_units(1), 10_000_000_000_000_000);
        assert_eq!(dai.cents_to_base_units(100), 1_000_000_000_000_000_000); // 1 DAI
    }

    #[test]
    fn usdc_base_units_to_cents() {
        let usdc = TokenInfo::usdc_base();
        assert_eq!(usdc.base_units_to_cents(10_000), 1);
        assert_eq!(usdc.base_units_to_cents(150_000), 15);
        assert_eq!(usdc.base_units_to_cents(1_000_000), 100);
    }

    #[test]
    fn round_trip_conversion() {
        let usdc = TokenInfo::usdc_base();
        for cents in [0, 1, 15, 100, 999, 5000, 100_000] {
            let base = usdc.cents_to_base_units(cents);
            let back = usdc.base_units_to_cents(base);
            assert_eq!(back, cents, "round-trip failed for {} cents", cents);
        }
    }

    #[test]
    fn zero_conversion() {
        let usdc = TokenInfo::usdc_base();
        assert_eq!(usdc.cents_to_base_units(0), 0);
        assert_eq!(usdc.base_units_to_cents(0), 0);
    }

    // ── Stripe stub tests ──

    #[tokio::test]
    async fn stripe_stub_settle() {
        let adapter = StripeStubAdapter::new_stub();
        assert_eq!(adapter.name(), "stripe-stub");

        let path = adapter
            .resolve_settlement_path("did:web:example.com")
            .await
            .unwrap();
        assert!(matches!(path, SettlementPath::Webhook { .. }));

        let result = adapter.settle("{}", 1500, &path).await.unwrap();
        assert!(result.success);
        assert_eq!(result.settled_cents, 1500);
        assert!(result.reference.unwrap().starts_with("stub_pi_"));
    }

    #[tokio::test]
    async fn noop_adapter_settle() {
        let adapter = NoopAdapter;
        assert_eq!(adapter.name(), "noop");

        let path = adapter
            .resolve_settlement_path("did:web:example.com")
            .await
            .unwrap();
        assert_eq!(path, SettlementPath::Manual);

        let result = adapter.settle("{}", 500, &path).await.unwrap();
        assert!(result.success);
        assert_eq!(result.settled_cents, 500);
    }

    #[tokio::test]
    async fn stripe_stub_check_status() {
        let adapter = StripeStubAdapter::new_stub();
        let result = adapter.check_status("stub_pi_12345").await.unwrap();
        assert!(result.success);
    }
}
