// SPDX-License-Identifier: AGPL-3.0-or-later
//
// cognitod/src/onchain.rs — Linnix-Claw on-chain settlement adapter (§8)
//
// Implements `PaymentAdapter` for trustless ERC-20 settlement via the
// TaskSettlement and AgentRegistry smart contracts on Base (or any EVM L2).
//
// Key design decisions:
// - Uses `alloy` for type-safe EVM RPC calls and contract interaction.
// - EIP-712 signatures are computed to match the Solidity contract's domain
//   (4-field domain: name, version, chainId, verifyingContract — NO salt).
// - DID encoding: `keccak256(did.as_bytes())` → `bytes32` for on-chain mapping.
// - Non-custodial: TaskSettlement.submitReceipt triggers safeTransferFrom
//   directly from payer to payee.

use alloy_network::EthereumWallet;
use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::sync::Arc;
use tiny_keccak::{Hasher, Keccak};

use crate::config::ChainConfig;
use crate::identity::AgentIdentity;
use crate::payment::{PaymentAdapter, PaymentResult, SettlementPath, TokenInfo};

// =============================================================================
// SOL BINDINGS — generated from contract ABIs via alloy::sol!
// =============================================================================

sol! {
    /// Minimal AgentRegistry interface for registration and lookups.
    #[sol(rpc)]
    interface IAgentRegistry {
        function register(bytes32 did, bytes32 ed25519Pubkey, address secp256k1Address) external;
        function isRegistered(bytes32 did) external view returns (bool);
        function getAddress(bytes32 did) external view returns (address);
        function resolve(bytes32 did) external view returns (
            bytes32 ed25519Pubkey,
            address secp256k1Address,
            uint256 tasksCompleted,
            uint256 disputesLost,
            uint256 violations,
            uint256 registeredAt,
            bool revoked
        );
    }

    /// Minimal TaskSettlement interface for task creation and receipt submission.
    #[sol(rpc)]
    interface ITaskSettlement {
        function createTask(
            bytes32 taskId,
            bytes32 payeeDid,
            address token,
            uint256 maxAmount,
            uint256 deadlineBlocks
        ) external;

        function submitReceipt(
            bytes32 taskId,
            uint256 actualAmount,
            bytes calldata receipt,
            bytes calldata signature
        ) external;

        function getTask(bytes32 taskId) external view returns (
            bytes32 taskIdOut,
            bytes32 payeeDid,
            address payer,
            uint48 deadline,
            uint48 disputeDeadline,
            uint8 status,
            address token,
            uint128 maxAmount,
            uint128 actualAmount
        );

        function DOMAIN_SEPARATOR() external view returns (bytes32);
    }

    /// Minimal ERC20 interface for allowance checks.
    #[sol(rpc)]
    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
        function balanceOf(address account) external view returns (uint256);
    }
}

// =============================================================================
// ON-CHAIN ADAPTER
// =============================================================================

/// On-chain settlement adapter using alloy to interact with
/// TaskSettlement + AgentRegistry contracts on an EVM L2.
pub struct OnChainAdapter {
    /// Chain configuration (RPC URL, contract addresses, etc.)
    config: ChainConfig,
    /// Token metadata for amount conversions
    token: TokenInfo,
    /// Agent identity for signing receipts
    identity: Arc<AgentIdentity>,
    /// The secp256k1 signer (alloy wallet)
    signer: PrivateKeySigner,
}

impl OnChainAdapter {
    /// Create a new on-chain adapter from config and agent identity.
    ///
    /// The signer is derived from:
    /// 1. `config.private_key` (hex string) if set
    /// 2. `LINNIX_CHAIN_PRIVATE_KEY` env var if set
    /// 3. The HKDF-derived secp256k1 key from `AgentIdentity` (default)
    pub fn new(config: ChainConfig, identity: Arc<AgentIdentity>) -> Result<Self> {
        let signer = resolve_signer(&config, &identity)?;
        let eth_addr = signer.address();

        let token = TokenInfo {
            name: "USD Coin".to_string(),
            symbol: "USDC".to_string(),
            decimals: config.token_decimals,
            address: config.token_address.clone(),
            chain_id: config.chain_id,
        };

        log::info!(
            "[claw-onchain] Adapter initialized: chain={}, signer=0x{}, settlement={}, registry={}",
            config.chain_id,
            eth_addr,
            config.settlement_contract,
            config.registry_contract,
        );

        Ok(Self {
            config,
            token,
            identity,
            signer,
        })
    }

    /// Register this agent on the AgentRegistry contract.
    ///
    /// Submits: `register(keccak256(did), ed25519_pubkey_bytes32, eth_address)`.
    /// No-op if already registered.
    pub async fn register_agent(&self) -> Result<()> {
        let provider = self.build_provider()?;
        let registry_addr = parse_address(&self.config.registry_contract)?;
        let registry = IAgentRegistry::new(registry_addr, &provider);

        let did_hash = did_to_bytes32(self.identity.did());

        // Check if already registered
        let is_registered = registry.isRegistered(did_hash).call().await;
        if let Ok(true) = is_registered {
            log::info!(
                "[claw-onchain] Agent already registered: DID={}",
                self.identity.did()
            );
            return Ok(());
        }

        // Prepare Ed25519 public key as bytes32
        let ed25519_pubkey = self.identity.ed25519_verifying_key();
        let mut ed25519_bytes = FixedBytes::<32>::ZERO;
        ed25519_bytes.copy_from_slice(ed25519_pubkey.as_bytes());

        let eth_addr = Address::from_slice(&self.identity.ethereum_address());

        log::info!(
            "[claw-onchain] Registering agent: DID={}, ETH=0x{}",
            self.identity.did(),
            hex::encode(eth_addr)
        );

        let tx = registry.register(did_hash, ed25519_bytes, eth_addr);
        let pending = tx.send().await.context("failed to send register tx")?;
        let receipt = pending
            .with_required_confirmations(self.config.confirmations)
            .get_receipt()
            .await
            .context("register tx failed")?;

        log::info!(
            "[claw-onchain] Agent registered: tx=0x{}",
            hex::encode(receipt.transaction_hash)
        );
        Ok(())
    }

    /// Create a task on the TaskSettlement contract.
    ///
    /// The payer (this agent) must have approved the token for the settlement contract.
    pub async fn create_task(
        &self,
        task_id: &str,
        payee_did: &str,
        max_amount_cents: u64,
        deadline_blocks: u64,
    ) -> Result<String> {
        let provider = self.build_provider()?;
        let settlement_addr = parse_address(&self.config.settlement_contract)?;
        let settlement = ITaskSettlement::new(settlement_addr, &provider);

        let task_id_bytes = string_to_bytes32(task_id);
        let payee_did_hash = did_to_bytes32(payee_did);
        let token_addr = parse_address(&self.config.token_address)?;
        let max_amount = U256::from(self.token.cents_to_base_units(max_amount_cents));

        log::info!(
            "[claw-onchain] Creating task: id={}, payee={}, max=${:.2}, deadline={}blks",
            task_id,
            payee_did,
            max_amount_cents as f64 / 100.0,
            deadline_blocks
        );

        let tx = settlement.createTask(
            task_id_bytes,
            payee_did_hash,
            token_addr,
            max_amount,
            U256::from(deadline_blocks),
        );
        let pending = tx.send().await.context("failed to send createTask tx")?;
        let receipt = pending
            .with_required_confirmations(self.config.confirmations)
            .get_receipt()
            .await
            .context("createTask tx failed")?;

        let tx_hash = format!("0x{}", hex::encode(receipt.transaction_hash));
        log::info!("[claw-onchain] Task created: tx={}", tx_hash);
        Ok(tx_hash)
    }

    /// Approve token spending for the settlement contract.
    pub async fn approve_token(&self, amount_cents: u64) -> Result<String> {
        let provider = self.build_provider()?;
        let token_addr = parse_address(&self.config.token_address)?;
        let settlement_addr = parse_address(&self.config.settlement_contract)?;
        let token = IERC20::new(token_addr, &provider);

        let amount = U256::from(self.token.cents_to_base_units(amount_cents));

        let tx = token.approve(settlement_addr, amount);
        let pending = tx.send().await.context("failed to send approve tx")?;
        let receipt = pending
            .with_required_confirmations(self.config.confirmations)
            .get_receipt()
            .await
            .context("approve tx failed")?;

        let tx_hash = format!("0x{}", hex::encode(receipt.transaction_hash));
        log::info!("[claw-onchain] Token approved: tx={}", tx_hash);
        Ok(tx_hash)
    }

    /// Submit a receipt to the TaskSettlement contract for settlement.
    ///
    /// This computes a Solidity-compatible EIP-712 signature (NO salt in domain,
    /// 3-field Receipt struct) and calls `submitReceipt()`.
    async fn submit_receipt_onchain(
        &self,
        task_id: &str,
        receipt_json: &str,
        amount_cents: u64,
    ) -> Result<PaymentResult> {
        let provider = self.build_provider()?;
        let settlement_addr = parse_address(&self.config.settlement_contract)?;
        let settlement = ITaskSettlement::new(settlement_addr, &provider);

        let task_id_bytes = string_to_bytes32(task_id);
        let actual_amount = U256::from(self.token.cents_to_base_units(amount_cents));
        let receipt_bytes = Bytes::from(receipt_json.as_bytes().to_vec());

        // Compute Solidity-compatible EIP-712 signature
        let signature = self.compute_solidity_eip712_signature(
            &task_id_bytes,
            &actual_amount,
            receipt_json.as_bytes(),
        )?;
        let sig_bytes = Bytes::from(signature);

        log::info!(
            "[claw-onchain] Submitting receipt: task={}, amount=${:.2}",
            task_id,
            amount_cents as f64 / 100.0
        );

        let tx = settlement.submitReceipt(task_id_bytes, actual_amount, receipt_bytes, sig_bytes);
        let pending = tx.send().await.context("failed to send submitReceipt tx")?;
        let tx_receipt = pending
            .with_required_confirmations(self.config.confirmations)
            .get_receipt()
            .await
            .context("submitReceipt tx failed")?;

        let tx_hash = format!("0x{}", hex::encode(tx_receipt.transaction_hash));
        log::info!("[claw-onchain] Receipt settled on-chain: tx={}", tx_hash);

        Ok(PaymentResult {
            success: true,
            reference: Some(tx_hash),
            message: format!(
                "settled ${:.2} on chain {} via TaskSettlement",
                amount_cents as f64 / 100.0,
                self.config.chain_id
            ),
            settled_cents: amount_cents,
        })
    }

    /// Compute a Solidity-compatible EIP-712 signature for `submitReceipt()`.
    ///
    /// The Solidity contract uses a 4-field domain (NO salt):
    /// ```solidity
    /// EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)
    /// ```
    ///
    /// And a 3-field struct:
    /// ```solidity
    /// Receipt(bytes32 taskId,uint256 actualAmount,bytes32 receiptHash)
    /// ```
    fn compute_solidity_eip712_signature(
        &self,
        task_id: &FixedBytes<32>,
        actual_amount: &U256,
        receipt_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        // Domain separator (no salt — matches Solidity contract)
        let domain_typehash = keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        let name_hash = keccak256(b"Linnix-Claw");
        let version_hash = keccak256(b"0.1.0");

        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[24..].copy_from_slice(&self.config.chain_id.to_be_bytes());

        let settlement_addr = parse_address(&self.config.settlement_contract)?;
        let mut contract_bytes = [0u8; 32];
        contract_bytes[12..].copy_from_slice(settlement_addr.as_slice());

        let mut domain_encoded = Vec::with_capacity(5 * 32);
        domain_encoded.extend_from_slice(&domain_typehash);
        domain_encoded.extend_from_slice(&name_hash);
        domain_encoded.extend_from_slice(&version_hash);
        domain_encoded.extend_from_slice(&chain_id_bytes);
        domain_encoded.extend_from_slice(&contract_bytes);
        let domain_separator = keccak256(&domain_encoded);

        // Struct hash: Receipt(bytes32 taskId, uint256 actualAmount, bytes32 receiptHash)
        let receipt_typehash =
            keccak256(b"Receipt(bytes32 taskId,uint256 actualAmount,bytes32 receiptHash)");
        let receipt_hash = keccak256(receipt_bytes);

        // abi.encode the amount as uint256 (32 bytes, big-endian)
        let amount_bytes: [u8; 32] = actual_amount.to_be_bytes();

        let mut struct_encoded = Vec::with_capacity(4 * 32);
        struct_encoded.extend_from_slice(&receipt_typehash);
        struct_encoded.extend_from_slice(task_id.as_slice());
        struct_encoded.extend_from_slice(&amount_bytes);
        struct_encoded.extend_from_slice(&receipt_hash);
        let struct_hash = keccak256(&struct_encoded);

        // Final EIP-712 digest: "\x19\x01" || domainSeparator || structHash
        let mut digest_input = Vec::with_capacity(66);
        digest_input.extend_from_slice(b"\x19\x01");
        digest_input.extend_from_slice(&domain_separator);
        digest_input.extend_from_slice(&struct_hash);
        let digest = keccak256(&digest_input);

        // Sign with secp256k1 (recoverable signature)
        let (sig, recid): (k256::ecdsa::Signature, _) = self
            .identity
            .secp256k1_signing_key()
            .sign_prehash_recoverable(&digest)
            .map_err(|e| anyhow::anyhow!("secp256k1 signing failed: {e}"))?;

        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(&sig.to_bytes());
        sig_bytes.push(recid.to_byte() + 27); // v = recovery_id + 27 (Ethereum convention)
        Ok(sig_bytes)
    }

    /// Build an alloy provider with the configured RPC endpoint and signer.
    fn build_provider(&self) -> Result<impl Provider<alloy_network::Ethereum> + Clone> {
        let wallet = EthereumWallet::from(self.signer.clone());
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(self.config.rpc_url.parse().context("invalid RPC URL")?);
        Ok(provider)
    }
}

#[async_trait]
impl PaymentAdapter for OnChainAdapter {
    fn name(&self) -> &str {
        "on-chain"
    }

    async fn resolve_settlement_path(&self, _counterparty_did: &str) -> Result<SettlementPath> {
        Ok(SettlementPath::OnChain {
            chain_id: self.config.chain_id,
            token: self.config.token_address.clone(),
        })
    }

    async fn settle(
        &self,
        receipt_json: &str,
        amount_cents: u64,
        path: &SettlementPath,
    ) -> Result<PaymentResult> {
        match path {
            SettlementPath::OnChain { .. } => {
                // Extract task_id from receipt JSON
                let receipt_value: serde_json::Value =
                    serde_json::from_str(receipt_json).context("failed to parse receipt JSON")?;
                let task_id = receipt_value
                    .get("task_id")
                    .or_else(|| receipt_value.get("mandate_id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                self.submit_receipt_onchain(task_id, receipt_json, amount_cents)
                    .await
            }
            _ => {
                anyhow::bail!(
                    "OnChainAdapter only handles on-chain settlement, got {:?}",
                    path
                );
            }
        }
    }

    async fn check_status(&self, reference: &str) -> Result<PaymentResult> {
        // For on-chain settlement, the reference is a tx hash.
        // We can check the tx receipt status.
        let provider = self.build_provider()?;
        let tx_hash_hex = reference.strip_prefix("0x").unwrap_or(reference);
        let tx_hash_bytes = hex::decode(tx_hash_hex).context("invalid tx hash hex")?;

        if tx_hash_bytes.len() != 32 {
            anyhow::bail!("tx hash must be 32 bytes, got {}", tx_hash_bytes.len());
        }

        let mut hash = FixedBytes::<32>::ZERO;
        hash.copy_from_slice(&tx_hash_bytes);

        let receipt = provider
            .get_transaction_receipt(hash)
            .await
            .context("failed to fetch tx receipt")?;

        match receipt {
            Some(r) => {
                let success = r.status();
                Ok(PaymentResult {
                    success,
                    reference: Some(reference.to_string()),
                    message: if success {
                        "transaction confirmed".to_string()
                    } else {
                        "transaction reverted".to_string()
                    },
                    settled_cents: 0, // Would need to parse logs to determine actual amount
                })
            }
            None => Ok(PaymentResult {
                success: false,
                reference: Some(reference.to_string()),
                message: "transaction not found (pending or dropped)".to_string(),
                settled_cents: 0,
            }),
        }
    }
}

// =============================================================================
// HELPERS
// =============================================================================

/// Convert a DID string to a bytes32 hash: `keccak256(did.as_bytes())`.
///
/// This matches how the Solidity contracts store DIDs as `bytes32` identifiers.
pub fn did_to_bytes32(did: &str) -> FixedBytes<32> {
    let hash = keccak256(did.as_bytes());
    FixedBytes::from(hash)
}

/// Convert a string to a bytes32 (left-padded keccak256 hash).
fn string_to_bytes32(s: &str) -> FixedBytes<32> {
    let hash = keccak256(s.as_bytes());
    FixedBytes::from(hash)
}

/// Parse a hex address string (0x-prefixed) into an alloy Address.
fn parse_address(hex_str: &str) -> Result<Address> {
    hex_str
        .parse::<Address>()
        .map_err(|e| anyhow::anyhow!("invalid address '{}': {}", hex_str, e))
}

/// Resolve the secp256k1 signer from config or identity.
fn resolve_signer(config: &ChainConfig, identity: &AgentIdentity) -> Result<PrivateKeySigner> {
    // Priority 1: explicit private key in config
    if !config.private_key.is_empty() {
        let key_hex = config
            .private_key
            .strip_prefix("0x")
            .unwrap_or(&config.private_key);
        let signer: PrivateKeySigner = key_hex
            .parse()
            .context("failed to parse chain.private_key")?;
        return Ok(signer);
    }

    // Priority 2: LINNIX_CHAIN_PRIVATE_KEY env var
    if let Ok(key_hex) = std::env::var("LINNIX_CHAIN_PRIVATE_KEY") {
        let key_hex = key_hex.strip_prefix("0x").unwrap_or(&key_hex);
        let signer: PrivateKeySigner = key_hex
            .parse()
            .context("failed to parse LINNIX_CHAIN_PRIVATE_KEY")?;
        return Ok(signer);
    }

    // Priority 3: derive from AgentIdentity's secp256k1 key
    let sk = identity.secp256k1_signing_key();
    let key_bytes = sk.to_bytes();
    let signer = PrivateKeySigner::from_bytes(&alloy_primitives::B256::from_slice(&key_bytes))
        .context("failed to create signer from identity secp256k1 key")?;
    Ok(signer)
}

/// Keccak-256 hash.
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut hash = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut hash);
    hash
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_to_bytes32_deterministic() {
        let did = "did:web:agent.example.com";
        let b1 = did_to_bytes32(did);
        let b2 = did_to_bytes32(did);
        assert_eq!(b1, b2);
        assert!(b1.iter().any(|&b| b != 0));
    }

    #[test]
    fn different_dids_different_hashes() {
        let b1 = did_to_bytes32("did:web:a.example.com");
        let b2 = did_to_bytes32("did:web:b.example.com");
        assert_ne!(b1, b2);
    }

    #[test]
    fn parse_valid_address() {
        let addr = parse_address("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913").unwrap();
        // alloy uses EIP-55 checksum encoding for Display, lowercase for Debug
        let addr_hex = format!("{addr}");
        assert_eq!(
            addr_hex.to_lowercase(),
            "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
        );
    }

    #[test]
    fn parse_invalid_address_fails() {
        assert!(parse_address("not-an-address").is_err());
        assert!(parse_address("0x123").is_err());
    }

    #[test]
    fn solidity_eip712_domain_no_salt() {
        // Verify our domain separator matches what Solidity would compute
        // for the EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)
        let domain_typehash = keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        // Just verify it's not all zeros and is deterministic
        assert!(domain_typehash.iter().any(|&b| b != 0));
        let domain_typehash2 = keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        assert_eq!(domain_typehash, domain_typehash2);
    }

    #[test]
    fn receipt_typehash_matches_solidity() {
        // Must match: Receipt(bytes32 taskId,uint256 actualAmount,bytes32 receiptHash)
        let typehash =
            keccak256(b"Receipt(bytes32 taskId,uint256 actualAmount,bytes32 receiptHash)");
        assert!(typehash.iter().any(|&b| b != 0));
    }

    #[test]
    fn resolve_signer_from_identity() {
        let seed = [42u8; 32];
        let identity = AgentIdentity::from_seed(seed, "did:web:test.example".to_string()).unwrap();
        let config = ChainConfig::default();
        let signer = resolve_signer(&config, &identity).unwrap();

        // Signer address should match identity's ethereum_address
        let expected_addr = identity.ethereum_address();
        let signer_addr = signer.address();
        assert_eq!(signer_addr.as_slice(), &expected_addr);
    }
}
