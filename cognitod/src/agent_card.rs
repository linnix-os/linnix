// SPDX-License-Identifier: AGPL-3.0-or-later
//
// cognitod/src/agent_card.rs — A2A Agent Card with Linnix-Claw extension (§4)
//
// Serves `GET /.well-known/agent-card.json` per the A2A v0.3.0 spec
// (Linux Foundation) with the `x-linnix-claw` extension advertising
// kernel attestation, settlement preferences, and pricing.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::Serialize;

use crate::identity::AgentIdentity;

// =============================================================================
// AGENT CARD STRUCTURES (§4)
// =============================================================================

/// A2A-compliant agent card with Linnix-Claw extensions.
#[derive(Debug, Clone, Serialize)]
pub struct AgentCard {
    pub name: String,
    pub description: String,
    pub version: String,

    #[serde(rename = "supportedInterfaces")]
    pub supported_interfaces: Vec<SupportedInterface>,

    pub capabilities: Capabilities,

    pub skills: Vec<Skill>,

    /// Linnix-Claw extension namespace (§4).
    #[serde(rename = "x-linnix-claw")]
    pub x_linnix_claw: ClawExtension,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupportedInterface {
    pub url: String,
    #[serde(rename = "protocolBinding")]
    pub protocol_binding: String,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Capabilities {
    pub streaming: bool,
    #[serde(rename = "pushNotifications")]
    pub push_notifications: bool,
    #[serde(rename = "kernelAttestation")]
    pub kernel_attestation: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Skill {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    #[serde(rename = "inputModes")]
    pub input_modes: Vec<String>,
    #[serde(rename = "outputModes")]
    pub output_modes: Vec<String>,
}

/// Linnix-Claw-specific extension fields (§4).
#[derive(Debug, Clone, Serialize)]
pub struct ClawExtension {
    pub version: String,
    pub did: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "ethereumAddress")]
    pub ethereum_address: String,
    #[serde(rename = "kernelAttestation")]
    pub kernel_attestation: bool,
    #[serde(rename = "enforcementMode")]
    pub enforcement_mode: String,
    pub settlement: SettlementInfo,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettlementInfo {
    pub chains: Vec<ChainInfo>,
    #[serde(rename = "acceptedTokens")]
    pub accepted_tokens: Vec<TokenInfo>,
    #[serde(rename = "receiptAuth")]
    pub receipt_auth: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainInfo {
    pub network: String,
    #[serde(rename = "chainId")]
    pub chain_id: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenInfo {
    pub symbol: String,
    pub address: String,
    #[serde(rename = "chainId")]
    pub chain_id: u64,
}

// =============================================================================
// BUILDER
// =============================================================================

/// Build the agent card from runtime state.
pub fn build_agent_card(
    identity: Option<&AgentIdentity>,
    bpf_lsm_available: bool,
    enforcement_mode: &str,
    listen_addr: &str,
) -> AgentCard {
    let hostname = std::fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let (did, public_key, eth_address) = if let Some(id) = identity {
        (
            id.did().to_string(),
            format!(
                "ed25519:{}",
                BASE64.encode(id.ed25519_verifying_key().as_bytes())
            ),
            format!("0x{}", hex::encode(id.ethereum_address())),
        )
    } else {
        (
            format!("did:linnix:{hostname}"),
            "none".to_string(),
            "0x0000000000000000000000000000000000000000".to_string(),
        )
    };

    let base_url = if listen_addr.starts_with("0.0.0.0") {
        format!(
            "http://{}:{}",
            hostname,
            listen_addr.split(':').next_back().unwrap_or("3000")
        )
    } else {
        format!("http://{listen_addr}")
    };

    AgentCard {
        name: format!("Linnix Agent ({hostname})"),
        description: "eBPF-powered Linux observability agent with kernel-level mandate enforcement"
            .to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),

        supported_interfaces: vec![SupportedInterface {
            url: format!("{base_url}/a2a"),
            protocol_binding: "jsonrpc".to_string(),
            protocol_version: "0.3.0".to_string(),
        }],

        capabilities: Capabilities {
            streaming: true,
            push_notifications: false,
            kernel_attestation: bpf_lsm_available,
        },

        skills: vec![
            Skill {
                id: "authorize-command".to_string(),
                name: "Authorize Command Execution".to_string(),
                description: "Create a time-bounded kernel mandate for a specific command"
                    .to_string(),
                tags: vec!["security".into(), "ebpf".into(), "mandate".into()],
                input_modes: vec!["application/json".into()],
                output_modes: vec!["application/json".into()],
            },
            Skill {
                id: "verify-receipt".to_string(),
                name: "Verify Execution Receipt".to_string(),
                description: "Verify dual-signed (Ed25519 + secp256k1) execution receipt"
                    .to_string(),
                tags: vec!["crypto".into(), "receipt".into(), "verification".into()],
                input_modes: vec!["application/json".into()],
                output_modes: vec!["application/json".into()],
            },
            Skill {
                id: "observe-processes".to_string(),
                name: "Observe Process Lifecycle".to_string(),
                description:
                    "Stream real-time process fork/exec/exit events with CPU/memory telemetry"
                        .to_string(),
                tags: vec!["observability".into(), "ebpf".into(), "telemetry".into()],
                input_modes: vec!["text/plain".into()],
                output_modes: vec!["text/event-stream".into()],
            },
        ],

        x_linnix_claw: ClawExtension {
            version: "0.1.0".to_string(),
            did,
            public_key,
            ethereum_address: eth_address,
            kernel_attestation: bpf_lsm_available,
            enforcement_mode: enforcement_mode.to_string(),
            settlement: SettlementInfo {
                chains: vec![
                    ChainInfo {
                        network: "base".to_string(),
                        chain_id: 8453,
                    },
                    ChainInfo {
                        network: "arbitrum".to_string(),
                        chain_id: 42161,
                    },
                ],
                accepted_tokens: vec![
                    TokenInfo {
                        symbol: "USDC".to_string(),
                        address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".to_string(),
                        chain_id: 8453,
                    },
                    TokenInfo {
                        symbol: "USDC".to_string(),
                        address: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831".to_string(),
                        chain_id: 42161,
                    },
                ],
                receipt_auth: "ed25519+secp256k1".to_string(),
            },
        },
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_card_has_required_fields() {
        let card = build_agent_card(None, true, "monitor", "0.0.0.0:3000");
        assert_eq!(card.x_linnix_claw.version, "0.1.0");
        assert!(card.x_linnix_claw.kernel_attestation);
        assert_eq!(card.x_linnix_claw.enforcement_mode, "monitor");
        assert!(!card.skills.is_empty());
        assert!(!card.x_linnix_claw.settlement.chains.is_empty());
    }

    #[test]
    fn agent_card_serializes_to_json() {
        let card = build_agent_card(None, false, "enforce", "127.0.0.1:3000");
        let json = serde_json::to_string_pretty(&card).unwrap();
        assert!(json.contains("x-linnix-claw"));
        assert!(json.contains("kernelAttestation"));
        assert!(json.contains("supportedInterfaces"));
        assert!(json.contains("authorize-command"));
    }

    #[test]
    fn agent_card_with_identity() {
        let id = crate::identity::AgentIdentity::from_seed([42u8; 32], "did:web:test.local".into())
            .unwrap();
        let card = build_agent_card(Some(&id), true, "enforce", "0.0.0.0:3000");
        assert_eq!(card.x_linnix_claw.did, "did:web:test.local");
        assert!(card.x_linnix_claw.public_key.starts_with("ed25519:"));
        assert!(card.x_linnix_claw.ethereum_address.starts_with("0x"));
        assert_eq!(card.x_linnix_claw.ethereum_address.len(), 42); // 0x + 40 hex chars
    }

    #[test]
    fn settlement_chains_default() {
        let card = build_agent_card(None, true, "monitor", "0.0.0.0:3000");
        let chain_ids: Vec<u64> = card
            .x_linnix_claw
            .settlement
            .chains
            .iter()
            .map(|c| c.chain_id)
            .collect();
        assert!(chain_ids.contains(&8453)); // Base
        assert!(chain_ids.contains(&42161)); // Arbitrum
    }
}
