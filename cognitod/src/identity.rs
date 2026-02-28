// SPDX-License-Identifier: AGPL-3.0-or-later
//
// cognitod/src/identity.rs — Linnix-Claw dual-key identity management (§5.4)
//
// Derives Ed25519 + secp256k1 keypairs from a single 32-byte seed via HKDF-SHA256.
// Ed25519: off-chain receipt verification (RFC 8032).
// secp256k1: on-chain verification via Solidity's ecrecover (EIP-712).

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use hkdf::Hkdf;
use k256::ecdsa::{SigningKey as Secp256k1SigningKey, VerifyingKey as Secp256k1VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;

/// HKDF info strings — domain-separate the two derived keys.
const ED25519_INFO: &[u8] = b"linnix-claw-ed25519";
const SECP256K1_INFO: &[u8] = b"linnix-claw-secp256k1";

/// Identity file version.
const IDENTITY_VERSION: u32 = 1;

// =============================================================================
// IDENTITY FILE FORMAT (§5.4)
// =============================================================================

/// Persisted identity file stored at `config.mandate.identity_path`.
///
/// ```json
/// {
///   "version": 1,
///   "did": "did:web:agent.example.com",
///   "seed": "<base64-encoded-32-bytes>",
///   "ed25519_pubkey": "<base64>",
///   "secp256k1_address": "0x1234...abcd",
///   "created_at": "2026-02-16T00:00:00Z",
///   "rotated_from": null
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityFile {
    pub version: u32,
    pub did: String,
    pub seed: String, // base64-encoded 32-byte seed
    pub ed25519_pubkey: String,
    pub secp256k1_address: String,
    pub created_at: String,
    pub rotated_from: Option<String>,
}

// =============================================================================
// AGENT IDENTITY (in-memory)
// =============================================================================

/// In-memory agent identity holding both keypairs.
///
/// Created from a 32-byte seed via HKDF-SHA256 derivation.
pub struct AgentIdentity {
    /// The raw seed (32 bytes). Stored to enable serialization.
    seed: [u8; 32],

    /// Ed25519 signing key for off-chain receipt signatures.
    ed25519_signing: Ed25519SigningKey,

    /// secp256k1 signing key for on-chain EIP-712 receipt signatures.
    secp256k1_signing: Secp256k1SigningKey,

    /// Agent's DID (e.g., "did:web:agent.example.com").
    did: String,

    /// Timestamp when this identity was created (ISO 8601).
    created_at: String,
}

impl AgentIdentity {
    /// Derive both keypairs from a 32-byte seed via HKDF-SHA256 (§5.4).
    ///
    /// - Ed25519: `HKDF(seed, info="linnix-claw-ed25519")` → 32-byte signing key
    /// - secp256k1: `HKDF(seed, info="linnix-claw-secp256k1")` → 32-byte private key
    pub fn from_seed(seed: [u8; 32], did: String) -> Result<Self> {
        let ed25519_signing = derive_ed25519(&seed)?;
        let secp256k1_signing = derive_secp256k1(&seed)?;
        let created_at = chrono::Utc::now().to_rfc3339();

        Ok(Self {
            seed,
            ed25519_signing,
            secp256k1_signing,
            did,
            created_at,
        })
    }

    /// Generate a new identity with a random 32-byte seed.
    pub fn generate(did: String) -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom(&mut seed)?;
        Self::from_seed(seed, did)
    }

    /// Load identity from a file path. If the file doesn't exist, generate
    /// a new identity and save it.
    pub fn load_or_generate(path: &Path, default_did: &str) -> Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            let identity = Self::generate(default_did.to_string())?;
            identity.save(path)?;
            Ok(identity)
        }
    }

    /// Load identity from an existing file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read identity file: {}", path.display()))?;
        let file: IdentityFile = serde_json::from_str(&content)
            .with_context(|| format!("failed to parse identity file: {}", path.display()))?;

        if file.version != IDENTITY_VERSION {
            anyhow::bail!(
                "unsupported identity file version: {} (expected {})",
                file.version,
                IDENTITY_VERSION
            );
        }

        let seed_bytes = BASE64
            .decode(&file.seed)
            .context("failed to decode seed from base64")?;
        if seed_bytes.len() != 32 {
            anyhow::bail!("seed must be 32 bytes, got {}", seed_bytes.len());
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);

        let mut identity = Self::from_seed(seed, file.did)?;
        identity.created_at = file.created_at;
        Ok(identity)
    }

    /// Save identity to a file (mode 0600).
    pub fn save(&self, path: &Path) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory: {}", parent.display()))?;
        }

        let file = self.to_identity_file();
        let content =
            serde_json::to_string_pretty(&file).context("failed to serialize identity file")?;

        std::fs::write(path, &content)
            .with_context(|| format!("failed to write identity file: {}", path.display()))?;

        // Set file permissions to 0600 (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)
                .with_context(|| format!("failed to set permissions on {}", path.display()))?;
        }

        Ok(())
    }

    /// Convert to the serializable identity file format.
    pub fn to_identity_file(&self) -> IdentityFile {
        IdentityFile {
            version: IDENTITY_VERSION,
            did: self.did.clone(),
            seed: BASE64.encode(self.seed),
            ed25519_pubkey: BASE64.encode(self.ed25519_verifying_key().as_bytes()),
            secp256k1_address: format!("0x{}", hex::encode(self.ethereum_address())),
            created_at: self.created_at.clone(),
            rotated_from: None,
        }
    }

    // ── Accessors ────────────────────────────────────────────────────────

    /// Ed25519 signing key reference (for receipt signing).
    pub fn ed25519_signing_key(&self) -> &Ed25519SigningKey {
        &self.ed25519_signing
    }

    /// Ed25519 public/verifying key.
    pub fn ed25519_verifying_key(&self) -> Ed25519VerifyingKey {
        self.ed25519_signing.verifying_key()
    }

    /// secp256k1 signing key reference (for EIP-712 receipt signing).
    pub fn secp256k1_signing_key(&self) -> &Secp256k1SigningKey {
        &self.secp256k1_signing
    }

    /// secp256k1 public/verifying key.
    pub fn secp256k1_verifying_key(&self) -> Secp256k1VerifyingKey {
        *self.secp256k1_signing.verifying_key()
    }

    /// Derive Ethereum-style address from secp256k1 public key.
    ///
    /// `keccak256(uncompressed_pubkey_bytes[1..])[12..]` → 20-byte address
    pub fn ethereum_address(&self) -> [u8; 20] {
        use tiny_keccak::{Hasher, Keccak};

        let pubkey = self.secp256k1_verifying_key();
        let point = pubkey.to_encoded_point(false); // uncompressed: 65 bytes
        let pubkey_bytes = &point.as_bytes()[1..]; // skip 0x04 prefix

        let mut keccak = Keccak::v256();
        let mut hash = [0u8; 32];
        keccak.update(pubkey_bytes);
        keccak.finalize(&mut hash);

        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);
        addr
    }

    /// Agent DID string.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Raw 32-byte seed (for tests / backup).
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
}

// =============================================================================
// KEY DERIVATION
// =============================================================================

/// Derive Ed25519 signing key from seed via HKDF-SHA256.
///
/// `HKDF-SHA256(ikm=seed, salt=None, info="linnix-claw-ed25519")` → 32 bytes
fn derive_ed25519(seed: &[u8; 32]) -> Result<Ed25519SigningKey> {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut okm = [0u8; 32];
    hk.expand(ED25519_INFO, &mut okm)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed for Ed25519: {e}"))?;
    Ok(Ed25519SigningKey::from_bytes(&okm))
}

/// Derive secp256k1 signing key from seed via HKDF-SHA256.
///
/// `HKDF-SHA256(ikm=seed, salt=None, info="linnix-claw-secp256k1")` → 32 bytes
fn derive_secp256k1(seed: &[u8; 32]) -> Result<Secp256k1SigningKey> {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut okm = [0u8; 32];
    hk.expand(SECP256K1_INFO, &mut okm)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed for secp256k1: {e}"))?;
    Secp256k1SigningKey::from_bytes((&okm).into())
        .map_err(|e| anyhow::anyhow!("invalid secp256k1 key material: {e}"))
}

/// Read 32 bytes from /dev/urandom.
fn getrandom(buf: &mut [u8; 32]) -> Result<()> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").context("failed to open /dev/urandom")?;
    f.read_exact(buf)
        .context("failed to read 32 bytes from /dev/urandom")?;
    Ok(())
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use tempfile::TempDir;

    /// Fixed test seed for reproducibility.
    fn test_seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        s
    }

    #[test]
    fn derive_keys_from_seed_is_deterministic() {
        let seed = test_seed();
        let id1 = AgentIdentity::from_seed(seed, "did:web:test.example".into()).unwrap();
        let id2 = AgentIdentity::from_seed(seed, "did:web:test.example".into()).unwrap();

        assert_eq!(
            id1.ed25519_verifying_key().as_bytes(),
            id2.ed25519_verifying_key().as_bytes(),
            "Ed25519 keys must be deterministic from same seed"
        );

        assert_eq!(
            id1.ethereum_address(),
            id2.ethereum_address(),
            "Ethereum addresses must be deterministic from same seed"
        );
    }

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let id = AgentIdentity::from_seed(test_seed(), "did:web:test".into()).unwrap();
        let message = b"hello world receipt";

        use ed25519_dalek::Signer;
        let sig = id.ed25519_signing_key().sign(message);
        let vk = id.ed25519_verifying_key();
        assert!(vk.verify(message, &sig).is_ok());
    }

    #[test]
    fn secp256k1_sign_verify_roundtrip() {
        let id = AgentIdentity::from_seed(test_seed(), "did:web:test".into()).unwrap();
        let message = b"hello world receipt";

        use k256::ecdsa::{Signature, signature::Signer};
        let sig: Signature = id.secp256k1_signing_key().sign(message);
        let vk = id.secp256k1_verifying_key();
        assert!(vk.verify(message, &sig).is_ok());
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        let id1 = AgentIdentity::from_seed([0xAA; 32], "did:web:a".into()).unwrap();
        let id2 = AgentIdentity::from_seed([0xBB; 32], "did:web:b".into()).unwrap();

        assert_ne!(
            id1.ed25519_verifying_key().as_bytes(),
            id2.ed25519_verifying_key().as_bytes()
        );
        assert_ne!(id1.ethereum_address(), id2.ethereum_address());
    }

    #[test]
    fn ethereum_address_is_20_bytes() {
        let id = AgentIdentity::from_seed(test_seed(), "did:web:test".into()).unwrap();
        let addr = id.ethereum_address();
        assert_eq!(addr.len(), 20);
        // Address should not be all zeros (highly unlikely from real key)
        assert!(addr.iter().any(|&b| b != 0));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("identity.json");

        let id1 = AgentIdentity::from_seed(test_seed(), "did:web:roundtrip".into()).unwrap();
        id1.save(&path).unwrap();

        let id2 = AgentIdentity::load(&path).unwrap();

        assert_eq!(id1.did(), id2.did());
        assert_eq!(
            id1.ed25519_verifying_key().as_bytes(),
            id2.ed25519_verifying_key().as_bytes()
        );
        assert_eq!(id1.ethereum_address(), id2.ethereum_address());
    }

    #[test]
    fn load_or_generate_creates_new_if_missing() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("subdir/identity.json");

        // File doesn't exist — should generate and save
        let id = AgentIdentity::load_or_generate(&path, "did:web:auto-generated").unwrap();
        assert!(path.exists());
        assert_eq!(id.did(), "did:web:auto-generated");

        // Load again — should get same keys
        let id2 = AgentIdentity::load(&path).unwrap();
        assert_eq!(
            id.ed25519_verifying_key().as_bytes(),
            id2.ed25519_verifying_key().as_bytes()
        );
    }

    #[test]
    fn identity_file_has_correct_version() {
        let id = AgentIdentity::from_seed(test_seed(), "did:web:v".into()).unwrap();
        let file = id.to_identity_file();
        assert_eq!(file.version, 1);
    }

    #[test]
    fn identity_file_permissions_are_0600() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("identity.json");
        let id = AgentIdentity::from_seed(test_seed(), "did:web:perms".into()).unwrap();
        id.save(&path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }
    }
}
