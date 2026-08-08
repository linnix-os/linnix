// SPDX-License-Identifier: AGPL-3.0-or-later
//
// cognitod/src/receipt.rs — Linnix-Claw execution receipt builder (§5.1, §5.2)
//
// Constructs and signs receipts proving mandated command execution.
// Dual signatures: Ed25519 (off-chain) + secp256k1/EIP-712 (on-chain).

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

use crate::identity::AgentIdentity;

// =============================================================================
// RECEIPT STRUCTURE (§5.1)
// =============================================================================

/// A signed execution receipt proving a mandated command ran.
///
/// This is the complete receipt returned by `GET /mandates/{id}/receipt`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    /// Receipt format version.
    pub version: String,

    /// Mandate identifier (matches the API mandate ID).
    pub mandate_id: String,

    /// Optional task identifier for billing correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,

    /// Agent DID that produced this receipt.
    pub agent_did: String,

    /// Execution details.
    pub execution: ExecutionDetails,

    /// Kernel attestation metadata.
    pub attestation: AttestationDetails,

    /// EIP-712 domain separator fields.
    pub domain: DomainSeparator,

    /// Ed25519 signature (off-chain verification).
    /// Format: "ed25519:<base64-encoded-64-byte-signature>"
    pub signature: String,

    /// secp256k1 recoverable signature (on-chain verification).
    /// Format: "0x<65-byte-hex>" (r[32] || s[32] || v[1])
    pub secp256k1_signature: String,
}

/// Details about the executed process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionDetails {
    /// Process ID that was authorized.
    pub pid: u32,

    /// Parent process ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,

    /// Binary path that was executed.
    pub binary: String,

    /// SipHash-2-4 of the canonicalized arguments.
    pub args_hash: String,

    /// Process exit code (0 = success).
    pub exit_code: i32,

    /// Execution start timestamp (nanoseconds since epoch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at_ns: Option<u64>,

    /// Execution finish timestamp (nanoseconds since epoch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at_ns: Option<u64>,

    /// Execution duration in milliseconds.
    pub duration_ms: u64,

    /// CPU usage percentage during execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_pct: Option<f32>,

    /// Memory usage percentage during execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_pct: Option<f32>,
}

/// Kernel-level attestation proving the execution was LSM-gated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDetails {
    /// Kernel sequence number from the SequencedSlot ring.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_seq: Option<u64>,

    /// Kernel boot ID (from /proc/sys/kernel/random/boot_id).
    pub kernel_boot_id: String,

    /// Size of the sequencer ring (slots).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequencer_ring_size: Option<u64>,

    /// Which LSM hook authorized this execution.
    pub lsm_hook: String,

    /// Enforcement mode when the mandate was checked.
    pub enforcement_mode: String,
}

/// EIP-712 domain separator for anti-replay protection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainSeparator {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: String,
    pub salt: String,
}

impl Default for DomainSeparator {
    fn default() -> Self {
        Self {
            name: "Linnix-Claw".to_string(),
            version: "0.1.0".to_string(),
            chain_id: 8453, // Base mainnet
            verifying_contract: "0x0000000000000000000000000000000000000000".to_string(),
            salt: read_boot_id().unwrap_or_else(|| "unknown".to_string()),
        }
    }
}

// =============================================================================
// RECEIPT BUILDER
// =============================================================================

/// Builder for constructing and signing execution receipts.
pub struct ReceiptBuilder {
    mandate_id: String,
    task_id: Option<String>,
    execution: ExecutionDetails,
    attestation: AttestationDetails,
    domain: DomainSeparator,
}

impl ReceiptBuilder {
    /// Start building a receipt for the given mandate.
    pub fn new(mandate_id: String, execution: ExecutionDetails) -> Self {
        let boot_id = read_boot_id().unwrap_or_else(|| "unknown".to_string());

        Self {
            mandate_id,
            task_id: None,
            execution,
            attestation: AttestationDetails {
                kernel_seq: None,
                kernel_boot_id: boot_id.clone(),
                sequencer_ring_size: None,
                lsm_hook: "bprm_check_security".to_string(),
                enforcement_mode: "monitor".to_string(),
            },
            domain: DomainSeparator {
                salt: boot_id,
                ..Default::default()
            },
        }
    }

    pub fn task_id(mut self, id: String) -> Self {
        self.task_id = Some(id);
        self
    }

    pub fn kernel_seq(mut self, seq: u64) -> Self {
        self.attestation.kernel_seq = Some(seq);
        self
    }

    pub fn enforcement_mode(mut self, mode: &str) -> Self {
        self.attestation.enforcement_mode = mode.to_string();
        self
    }

    pub fn lsm_hook(mut self, hook: &str) -> Self {
        self.attestation.lsm_hook = hook.to_string();
        self
    }

    pub fn chain_id(mut self, id: u64) -> Self {
        self.domain.chain_id = id;
        self
    }

    pub fn verifying_contract(mut self, addr: &str) -> Self {
        self.domain.verifying_contract = addr.to_string();
        self
    }

    /// Sign and finalize the receipt using the agent's dual keypair.
    ///
    /// 1. Constructs the receipt JSON without signatures.
    /// 2. Computes canonical JSON (keys sorted, no whitespace).
    /// 3. Signs canonical JSON with Ed25519.
    /// 4. Computes EIP-712 typed data hash and signs with secp256k1.
    /// 5. Returns the complete receipt with both signatures.
    pub fn sign(self, identity: &AgentIdentity) -> Result<ExecutionReceipt> {
        // Build unsigned receipt for canonical JSON computation
        let unsigned = UnsignedReceipt {
            version: "0.1.0".to_string(),
            mandate_id: self.mandate_id.clone(),
            task_id: self.task_id.clone(),
            agent_did: identity.did().to_string(),
            execution: self.execution.clone(),
            attestation: self.attestation.clone(),
            domain: self.domain.clone(),
        };

        // ── Ed25519 signature ────────────────────────────────────────
        let canonical_json = canonical_json(&unsigned)?;
        let ed25519_sig = sign_ed25519(identity, canonical_json.as_bytes());

        // ── secp256k1 / EIP-712 signature ────────────────────────────
        let eip712_hash = compute_eip712_hash(&unsigned)?;
        let secp256k1_sig = sign_secp256k1(identity, &eip712_hash)?;

        Ok(ExecutionReceipt {
            version: unsigned.version,
            mandate_id: unsigned.mandate_id,
            task_id: unsigned.task_id,
            agent_did: unsigned.agent_did,
            execution: unsigned.execution,
            attestation: unsigned.attestation,
            domain: unsigned.domain,
            signature: format!("ed25519:{}", BASE64.encode(ed25519_sig.as_slice())),
            secp256k1_signature: format!("0x{}", hex::encode(secp256k1_sig)),
        })
    }
}

// =============================================================================
// UNSIGNED RECEIPT (for canonical JSON computation)
// =============================================================================

/// Receipt without signatures — used to compute the signing payload.
/// Keys are sorted alphabetically in serialization (via serde default).
#[derive(Debug, Serialize, Deserialize)]
struct UnsignedReceipt {
    version: String,
    mandate_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    task_id: Option<String>,
    agent_did: String,
    execution: ExecutionDetails,
    attestation: AttestationDetails,
    domain: DomainSeparator,
}

// =============================================================================
// SIGNING FUNCTIONS
// =============================================================================

/// Sign message bytes with Ed25519.
fn sign_ed25519(identity: &AgentIdentity, message: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let sig = identity.ed25519_signing_key().sign(message);
    sig.to_bytes().to_vec()
}

/// Sign an EIP-712 hash with secp256k1, producing a 65-byte recoverable signature.
///
/// Returns [r (32 bytes) || s (32 bytes) || v (1 byte)].
fn sign_secp256k1(identity: &AgentIdentity, digest: &[u8; 32]) -> Result<Vec<u8>> {
    use k256::ecdsa::Signature;

    let (sig, recid): (Signature, _) = identity
        .secp256k1_signing_key()
        .sign_prehash_recoverable(digest)
        .map_err(|e| anyhow::anyhow!("secp256k1 signing failed: {e}"))?;

    let mut bytes = Vec::with_capacity(65);
    bytes.extend_from_slice(&sig.to_bytes()); // r || s (64 bytes)
    bytes.push(recid.to_byte() + 27); // v = recovery_id + 27 (Ethereum convention)
    Ok(bytes)
}

/// Compute canonical JSON for Ed25519 signing (§5.2).
///
/// Keys sorted alphabetically, no whitespace, UTF-8 encoded.
/// We use serde_json::to_value → sort keys → serialize.
fn canonical_json(receipt: &UnsignedReceipt) -> Result<String> {
    let value = serde_json::to_value(receipt).context("failed to serialize receipt to JSON")?;
    let sorted = sort_json_value(&value);
    serde_json::to_string(&sorted).context("failed to serialize canonical JSON")
}

/// Recursively sort JSON keys alphabetically.
fn sort_json_value(val: &serde_json::Value) -> serde_json::Value {
    match val {
        serde_json::Value::Object(map) => {
            let mut sorted: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                sorted.insert(key.clone(), sort_json_value(&map[key]));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_json_value).collect())
        }
        other => other.clone(),
    }
}

// =============================================================================
// EIP-712 TYPED DATA HASH (§5.2)
// =============================================================================

/// Compute EIP-712 typed structured data hash for secp256k1 signing.
///
/// `hash = keccak256("\x19\x01" || domain_separator || struct_hash)`
fn compute_eip712_hash(receipt: &UnsignedReceipt) -> Result<[u8; 32]> {
    let domain_sep = compute_domain_separator(&receipt.domain);
    let struct_hash = compute_receipt_struct_hash(receipt)?;

    let mut data = Vec::with_capacity(66);
    data.extend_from_slice(b"\x19\x01");
    data.extend_from_slice(&domain_sep);
    data.extend_from_slice(&struct_hash);

    Ok(keccak256(&data))
}

/// EIP-712 domain separator hash.
///
/// ```solidity
/// keccak256(abi.encode(
///     DOMAIN_TYPEHASH,
///     keccak256("Linnix-Claw"),
///     keccak256("0.1.0"),
///     chainId,
///     verifyingContract,
///     salt
/// ))
/// ```
fn compute_domain_separator(domain: &DomainSeparator) -> [u8; 32] {
    let typehash = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
    );

    let name_hash = keccak256(domain.name.as_bytes());
    let version_hash = keccak256(domain.version.as_bytes());

    let mut chain_id_bytes = [0u8; 32];
    chain_id_bytes[24..].copy_from_slice(&domain.chain_id.to_be_bytes());

    let mut contract_bytes = [0u8; 32];
    if let Some(hex_str) = domain.verifying_contract.strip_prefix("0x")
        && let Ok(decoded) = hex::decode(hex_str)
    {
        let start = 32 - decoded.len().min(32);
        contract_bytes[start..start + decoded.len().min(32)]
            .copy_from_slice(&decoded[..decoded.len().min(32)]);
    }

    // Salt: keccak256 of the boot_id string (fits in bytes32)
    let salt_hash = keccak256(domain.salt.as_bytes());

    // abi.encode all components
    let mut encoded = Vec::with_capacity(6 * 32);
    encoded.extend_from_slice(&typehash);
    encoded.extend_from_slice(&name_hash);
    encoded.extend_from_slice(&version_hash);
    encoded.extend_from_slice(&chain_id_bytes);
    encoded.extend_from_slice(&contract_bytes);
    encoded.extend_from_slice(&salt_hash);

    keccak256(&encoded)
}

/// EIP-712 struct hash for the receipt.
///
/// We hash key receipt fields that the on-chain contract needs to verify:
/// mandate_id, agent_did, binary, args_hash, exit_code, duration_ms, enforcement_mode.
fn compute_receipt_struct_hash(receipt: &UnsignedReceipt) -> Result<[u8; 32]> {
    let typehash = keccak256(
        b"ExecutionReceipt(string mandateId,string agentDid,uint32 pid,string binary,string argsHash,int32 exitCode,uint64 durationMs,string enforcementMode)",
    );

    let mandate_id_hash = keccak256(receipt.mandate_id.as_bytes());
    let agent_did_hash = keccak256(receipt.agent_did.as_bytes());

    let mut pid_bytes = [0u8; 32];
    pid_bytes[28..].copy_from_slice(&receipt.execution.pid.to_be_bytes());

    let binary_hash = keccak256(receipt.execution.binary.as_bytes());
    let args_hash_hash = keccak256(receipt.execution.args_hash.as_bytes());

    let mut exit_code_bytes = [0u8; 32];
    exit_code_bytes[28..].copy_from_slice(&receipt.execution.exit_code.to_be_bytes());

    let mut duration_bytes = [0u8; 32];
    duration_bytes[24..].copy_from_slice(&receipt.execution.duration_ms.to_be_bytes());

    let enforcement_hash = keccak256(receipt.attestation.enforcement_mode.as_bytes());

    let mut encoded = Vec::with_capacity(9 * 32);
    encoded.extend_from_slice(&typehash);
    encoded.extend_from_slice(&mandate_id_hash);
    encoded.extend_from_slice(&agent_did_hash);
    encoded.extend_from_slice(&pid_bytes);
    encoded.extend_from_slice(&binary_hash);
    encoded.extend_from_slice(&args_hash_hash);
    encoded.extend_from_slice(&exit_code_bytes);
    encoded.extend_from_slice(&duration_bytes);
    encoded.extend_from_slice(&enforcement_hash);

    Ok(keccak256(&encoded))
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
// VERIFICATION (for tests and offline verification)
// =============================================================================

/// Verify an execution receipt's Ed25519 signature.
///
/// Re-constructs the canonical JSON from the receipt fields and verifies
/// against the provided public key.
pub fn verify_ed25519(
    receipt: &ExecutionReceipt,
    pubkey: &ed25519_dalek::VerifyingKey,
) -> Result<bool> {
    // Strip "ed25519:" prefix and decode
    let sig_b64 = receipt
        .signature
        .strip_prefix("ed25519:")
        .context("signature missing 'ed25519:' prefix")?;
    let sig_bytes = BASE64
        .decode(sig_b64)
        .context("failed to decode Ed25519 signature from base64")?;

    if sig_bytes.len() != 64 {
        anyhow::bail!(
            "Ed25519 signature must be 64 bytes, got {}",
            sig_bytes.len()
        );
    }
    let sig = ed25519_dalek::Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());

    // Re-construct unsigned receipt
    let unsigned = UnsignedReceipt {
        version: receipt.version.clone(),
        mandate_id: receipt.mandate_id.clone(),
        task_id: receipt.task_id.clone(),
        agent_did: receipt.agent_did.clone(),
        execution: receipt.execution.clone(),
        attestation: receipt.attestation.clone(),
        domain: receipt.domain.clone(),
    };

    let canonical = canonical_json(&unsigned)?;

    use ed25519_dalek::Verifier;
    Ok(pubkey.verify(canonical.as_bytes(), &sig).is_ok())
}

/// Verify an execution receipt's secp256k1/EIP-712 signature.
///
/// Recovers the signer address from the recoverable signature and compares
/// against the expected Ethereum address.
pub fn verify_secp256k1(receipt: &ExecutionReceipt, expected_address: &[u8; 20]) -> Result<bool> {
    // Strip "0x" prefix and decode
    let hex_str = receipt
        .secp256k1_signature
        .strip_prefix("0x")
        .context("secp256k1_signature missing '0x' prefix")?;
    let sig_bytes =
        hex::decode(hex_str).context("failed to decode secp256k1 signature from hex")?;

    if sig_bytes.len() != 65 {
        anyhow::bail!(
            "secp256k1 signature must be 65 bytes, got {}",
            sig_bytes.len()
        );
    }

    // Split into r||s (64 bytes) and v (1 byte)
    let v = sig_bytes[64];
    let recid = k256::ecdsa::RecoveryId::try_from(v.wrapping_sub(27))
        .map_err(|e| anyhow::anyhow!("invalid recovery id: {e}"))?;
    let sig = k256::ecdsa::Signature::try_from(&sig_bytes[..64])
        .map_err(|e| anyhow::anyhow!("invalid secp256k1 signature: {e}"))?;

    // Re-compute EIP-712 hash
    let unsigned = UnsignedReceipt {
        version: receipt.version.clone(),
        mandate_id: receipt.mandate_id.clone(),
        task_id: receipt.task_id.clone(),
        agent_did: receipt.agent_did.clone(),
        execution: receipt.execution.clone(),
        attestation: receipt.attestation.clone(),
        domain: receipt.domain.clone(),
    };
    let eip712_hash = compute_eip712_hash(&unsigned)?;

    // Recover public key from signature
    let recovered_key = k256::ecdsa::VerifyingKey::recover_from_prehash(&eip712_hash, &sig, recid)
        .map_err(|e| anyhow::anyhow!("failed to recover secp256k1 key: {e}"))?;

    // Derive Ethereum address from recovered key
    let point = recovered_key.to_encoded_point(false);
    let pubkey_bytes = &point.as_bytes()[1..];

    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(pubkey_bytes);
    keccak.finalize(&mut hash);

    let mut recovered_addr = [0u8; 20];
    recovered_addr.copy_from_slice(&hash[12..]);

    Ok(&recovered_addr == expected_address)
}

// =============================================================================
// UTILITIES
// =============================================================================

/// Read the kernel boot ID from /proc/sys/kernel/random/boot_id.
fn read_boot_id() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string())
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentIdentity;

    fn test_identity() -> AgentIdentity {
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        AgentIdentity::from_seed(seed, "did:web:test.agent.example".into()).unwrap()
    }

    fn test_execution() -> ExecutionDetails {
        ExecutionDetails {
            pid: 12345,
            ppid: Some(12300),
            binary: "/usr/bin/curl".to_string(),
            args_hash: "0xa1b2c3d4e5f60718".to_string(),
            exit_code: 0,
            started_at_ns: Some(1740000001234000000),
            finished_at_ns: Some(1740000001567000000),
            duration_ms: 333,
            cpu_pct: Some(2.3),
            mem_pct: Some(0.1),
        }
    }

    #[test]
    fn receipt_sign_produces_valid_structure() {
        let identity = test_identity();
        let receipt = ReceiptBuilder::new("mnd_00000001".to_string(), test_execution())
            .task_id("task_abc".to_string())
            .kernel_seq(1234)
            .enforcement_mode("monitor")
            .sign(&identity)
            .unwrap();

        assert_eq!(receipt.version, "0.1.0");
        assert_eq!(receipt.mandate_id, "mnd_00000001");
        assert_eq!(receipt.task_id, Some("task_abc".to_string()));
        assert_eq!(receipt.agent_did, "did:web:test.agent.example");
        assert!(receipt.signature.starts_with("ed25519:"));
        assert!(receipt.secp256k1_signature.starts_with("0x"));
        assert_eq!(receipt.execution.pid, 12345);
        assert_eq!(receipt.execution.exit_code, 0);
    }

    #[test]
    fn receipt_ed25519_verify_roundtrip() {
        let identity = test_identity();
        let receipt = ReceiptBuilder::new("mnd_verify_ed".to_string(), test_execution())
            .sign(&identity)
            .unwrap();

        let pubkey = identity.ed25519_verifying_key();
        assert!(
            verify_ed25519(&receipt, &pubkey).unwrap(),
            "Ed25519 signature verification failed"
        );
    }

    #[test]
    fn receipt_secp256k1_verify_roundtrip() {
        let identity = test_identity();
        let receipt = ReceiptBuilder::new("mnd_verify_secp".to_string(), test_execution())
            .sign(&identity)
            .unwrap();

        let addr = identity.ethereum_address();
        assert!(
            verify_secp256k1(&receipt, &addr).unwrap(),
            "secp256k1/EIP-712 signature verification failed"
        );
    }

    #[test]
    fn receipt_dual_verify() {
        let identity = test_identity();
        let receipt = ReceiptBuilder::new("mnd_dual".to_string(), test_execution())
            .kernel_seq(42)
            .enforcement_mode("enforce")
            .chain_id(8453)
            .sign(&identity)
            .unwrap();

        // Both signatures must verify
        let ed_ok = verify_ed25519(&receipt, &identity.ed25519_verifying_key()).unwrap();
        let secp_ok = verify_secp256k1(&receipt, &identity.ethereum_address()).unwrap();
        assert!(ed_ok, "Ed25519 failed");
        assert!(secp_ok, "secp256k1 failed");
    }

    #[test]
    fn tampered_receipt_fails_ed25519() {
        let identity = test_identity();
        let mut receipt = ReceiptBuilder::new("mnd_tamper".to_string(), test_execution())
            .sign(&identity)
            .unwrap();

        // Tamper with the mandate_id
        receipt.mandate_id = "mnd_TAMPERED".to_string();

        let pubkey = identity.ed25519_verifying_key();
        assert!(
            !verify_ed25519(&receipt, &pubkey).unwrap(),
            "Ed25519 should reject tampered receipt"
        );
    }

    #[test]
    fn tampered_receipt_fails_secp256k1() {
        let identity = test_identity();
        let mut receipt = ReceiptBuilder::new("mnd_tamper2".to_string(), test_execution())
            .sign(&identity)
            .unwrap();

        // Tamper with exit code
        receipt.execution.exit_code = 1;

        let addr = identity.ethereum_address();
        assert!(
            !verify_secp256k1(&receipt, &addr).unwrap(),
            "secp256k1 should reject tampered receipt"
        );
    }

    #[test]
    fn wrong_key_fails_ed25519() {
        let identity = test_identity();
        let receipt = ReceiptBuilder::new("mnd_wrongkey".to_string(), test_execution())
            .sign(&identity)
            .unwrap();

        // Verify with a different identity's key
        let other = AgentIdentity::from_seed([0xFF; 32], "did:web:other".into()).unwrap();
        let result = verify_ed25519(&receipt, &other.ed25519_verifying_key()).unwrap();
        assert!(!result, "should fail with wrong key");
    }

    #[test]
    fn wrong_address_fails_secp256k1() {
        let identity = test_identity();
        let receipt = ReceiptBuilder::new("mnd_wrongaddr".to_string(), test_execution())
            .sign(&identity)
            .unwrap();

        // Verify with wrong Ethereum address
        let wrong_addr = [0xAA; 20];
        let result = verify_secp256k1(&receipt, &wrong_addr).unwrap();
        assert!(!result, "should fail with wrong address");
    }

    #[test]
    fn canonical_json_is_deterministic() {
        let unsigned = UnsignedReceipt {
            version: "0.1.0".to_string(),
            mandate_id: "test".to_string(),
            task_id: None,
            agent_did: "did:web:x".to_string(),
            execution: test_execution(),
            attestation: AttestationDetails {
                kernel_seq: Some(1),
                kernel_boot_id: "boot-1".to_string(),
                sequencer_ring_size: None,
                lsm_hook: "bprm_check_security".to_string(),
                enforcement_mode: "monitor".to_string(),
            },
            domain: DomainSeparator {
                name: "Linnix-Claw".to_string(),
                version: "0.1.0".to_string(),
                chain_id: 8453,
                verifying_contract: "0x0".to_string(),
                salt: "test-salt".to_string(),
            },
        };

        let json1 = canonical_json(&unsigned).unwrap();
        let json2 = canonical_json(&unsigned).unwrap();
        assert_eq!(json1, json2, "canonical JSON must be deterministic");

        // Verify keys are actually sorted
        assert!(
            json1.find("\"agent_did\"").unwrap() < json1.find("\"attestation\"").unwrap(),
            "keys should be alphabetically sorted"
        );
    }

    #[test]
    fn eip712_hash_is_deterministic() {
        let unsigned = UnsignedReceipt {
            version: "0.1.0".to_string(),
            mandate_id: "test-eip712".to_string(),
            task_id: None,
            agent_did: "did:web:eip".to_string(),
            execution: test_execution(),
            attestation: AttestationDetails {
                kernel_seq: None,
                kernel_boot_id: "boot-2".to_string(),
                sequencer_ring_size: None,
                lsm_hook: "bprm_check_security".to_string(),
                enforcement_mode: "enforce".to_string(),
            },
            domain: DomainSeparator::default(),
        };

        let hash1 = compute_eip712_hash(&unsigned).unwrap();
        let hash2 = compute_eip712_hash(&unsigned).unwrap();
        assert_eq!(hash1, hash2, "EIP-712 hash must be deterministic");
        assert!(hash1.iter().any(|&b| b != 0), "hash shouldn't be all zeros");
    }

    #[test]
    fn receipt_serializes_to_json() {
        let identity = test_identity();
        let receipt = ReceiptBuilder::new("mnd_json".to_string(), test_execution())
            .sign(&identity)
            .unwrap();

        let json = serde_json::to_string_pretty(&receipt).unwrap();
        assert!(json.contains("\"version\": \"0.1.0\""));
        assert!(json.contains("\"mandate_id\": \"mnd_json\""));
        assert!(json.contains("\"signature\": \"ed25519:"));
        assert!(json.contains("\"secp256k1_signature\": \"0x"));

        // Roundtrip deserialization
        let parsed: ExecutionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mandate_id, "mnd_json");
    }

    #[test]
    fn different_chain_ids_produce_different_secp256k1_sigs() {
        let identity = test_identity();

        let r1 = ReceiptBuilder::new("mnd_chain1".to_string(), test_execution())
            .chain_id(8453)
            .sign(&identity)
            .unwrap();

        let r2 = ReceiptBuilder::new("mnd_chain1".to_string(), test_execution())
            .chain_id(42161)
            .sign(&identity)
            .unwrap();

        assert_ne!(
            r1.secp256k1_signature, r2.secp256k1_signature,
            "different chain IDs must produce different secp256k1 signatures (anti-replay)"
        );
    }
}
