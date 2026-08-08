// SPDX-License-Identifier: AGPL-3.0-or-later
//
// cognitod/src/commerce.rs — Commerce policy enforcement (§11.1)
//
// Determines whether commerce operations (mandates with settlement fields)
// are allowed based on kernel enforcement availability.
//
// Default policy: refuse commerce without BPF LSM unless operator explicitly
// opts in via `allow_commerce_without_lsm = true`.

use serde::Serialize;

// =============================================================================
// DEPLOYMENT MODE
// =============================================================================

/// The three deployment modes per §11.1 commerce policy table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    /// BPF LSM loaded and mandate mode = "enforce".
    /// Commerce: allowed. Receipts: kernel-attested. Risk: lowest.
    FullEnforcement,

    /// BPF LSM loaded but mandate mode = "monitor".
    /// Commerce: allowed with `degraded=true` in receipts. Risk: medium.
    MonitorOnly,

    /// BPF LSM not available (observability-only).
    /// Commerce: only if `allow_commerce_without_lsm = true`. Risk: high.
    ObservabilityOnly,
}

impl DeploymentMode {
    /// Human-readable enforcement mode string for receipts and API responses.
    pub fn enforcement_mode_str(&self) -> &'static str {
        match self {
            Self::FullEnforcement => "enforce",
            Self::MonitorOnly => "monitor",
            Self::ObservabilityOnly => "none",
        }
    }

    /// Whether receipts from this mode carry kernel attestation.
    pub fn is_kernel_attested(&self) -> bool {
        matches!(self, Self::FullEnforcement)
    }

    /// Whether receipts should be tagged as degraded.
    pub fn is_degraded(&self) -> bool {
        !matches!(self, Self::FullEnforcement)
    }
}

// =============================================================================
// COMMERCE POLICY
// =============================================================================

/// Encapsulates the commerce policy decision logic.
///
/// The policy answers: "Should we allow this mandate to proceed?"
///
/// Key invariant from §11.1:
///   If BPF LSM is unavailable AND `allow_commerce_without_lsm = false`,
///   commerce mandates (those with `task_id` or `max_spend_cents`) are
///   rejected with 503.
#[derive(Debug, Clone)]
pub struct CommercePolicy {
    /// Current deployment mode (detected at startup).
    pub mode: DeploymentMode,

    /// Whether the operator has opted in to degraded commerce.
    pub allow_commerce_without_lsm: bool,
}

impl CommercePolicy {
    /// Create a commerce policy from runtime state.
    pub fn new(bpf_lsm_available: bool, mandate_mode: &str, allow_without_lsm: bool) -> Self {
        let mode = if bpf_lsm_available {
            if mandate_mode == "enforce" {
                DeploymentMode::FullEnforcement
            } else {
                DeploymentMode::MonitorOnly
            }
        } else {
            DeploymentMode::ObservabilityOnly
        };

        Self {
            mode,
            allow_commerce_without_lsm: allow_without_lsm,
        }
    }

    /// Check whether a mandate with settlement fields should be allowed.
    ///
    /// Returns `Ok(())` if allowed, or `Err(CommerceRejection)` if the
    /// policy blocks it.
    pub fn check_commerce(&self, is_commerce_request: bool) -> Result<(), CommerceRejection> {
        // Non-commerce mandates (pure observability) are always allowed
        if !is_commerce_request {
            return Ok(());
        }

        // In observability-only mode, commerce requires explicit opt-in
        if self.mode == DeploymentMode::ObservabilityOnly && !self.allow_commerce_without_lsm {
            return Err(CommerceRejection {
                enforcement_mode: self.mode.enforcement_mode_str().to_string(),
                message: "BPF LSM not available. Set mandate.allow_commerce_without_lsm=true to enable degraded commerce.".to_string(),
            });
        }

        Ok(())
    }

    /// Whether mandates created under this policy are kernel-enforced.
    pub fn is_enforced(&self) -> bool {
        self.mode == DeploymentMode::FullEnforcement
    }
}

/// Error returned when commerce policy blocks a mandate.
#[derive(Debug, Clone, Serialize)]
pub struct CommerceRejection {
    pub enforcement_mode: String,
    pub message: String,
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_enforcement_allows_commerce() {
        let policy = CommercePolicy::new(true, "enforce", false);
        assert_eq!(policy.mode, DeploymentMode::FullEnforcement);
        assert!(policy.check_commerce(true).is_ok());
        assert!(policy.is_enforced());
    }

    #[test]
    fn monitor_mode_allows_commerce() {
        let policy = CommercePolicy::new(true, "monitor", false);
        assert_eq!(policy.mode, DeploymentMode::MonitorOnly);
        assert!(policy.check_commerce(true).is_ok());
        assert!(!policy.is_enforced());
    }

    #[test]
    fn observability_only_blocks_commerce_by_default() {
        let policy = CommercePolicy::new(false, "monitor", false);
        assert_eq!(policy.mode, DeploymentMode::ObservabilityOnly);
        let result = policy.check_commerce(true);
        assert!(result.is_err());
        let rejection = result.unwrap_err();
        assert_eq!(rejection.enforcement_mode, "none");
        assert!(rejection.message.contains("allow_commerce_without_lsm"));
    }

    #[test]
    fn observability_only_allows_commerce_with_opt_in() {
        let policy = CommercePolicy::new(false, "monitor", true);
        assert_eq!(policy.mode, DeploymentMode::ObservabilityOnly);
        assert!(policy.check_commerce(true).is_ok());
        assert!(!policy.is_enforced());
    }

    #[test]
    fn non_commerce_mandates_always_allowed() {
        // Even in the most restrictive mode
        let policy = CommercePolicy::new(false, "monitor", false);
        assert!(policy.check_commerce(false).is_ok());
    }

    #[test]
    fn deployment_mode_strings() {
        assert_eq!(
            DeploymentMode::FullEnforcement.enforcement_mode_str(),
            "enforce"
        );
        assert_eq!(
            DeploymentMode::MonitorOnly.enforcement_mode_str(),
            "monitor"
        );
        assert_eq!(
            DeploymentMode::ObservabilityOnly.enforcement_mode_str(),
            "none"
        );
    }

    #[test]
    fn degraded_flag() {
        assert!(!DeploymentMode::FullEnforcement.is_degraded());
        assert!(DeploymentMode::MonitorOnly.is_degraded());
        assert!(DeploymentMode::ObservabilityOnly.is_degraded());
    }

    #[test]
    fn kernel_attested_flag() {
        assert!(DeploymentMode::FullEnforcement.is_kernel_attested());
        assert!(!DeploymentMode::MonitorOnly.is_kernel_attested());
        assert!(!DeploymentMode::ObservabilityOnly.is_kernel_attested());
    }
}
