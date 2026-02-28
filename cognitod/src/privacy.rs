// SPDX-License-Identifier: AGPL-3.0-or-later
//
// cognitod/src/privacy.rs — Linnix-Claw receipt privacy & redaction (§10.4)
//
// Three redaction levels for receipts before sending to counterparties:
//   - `none`     — full binary path, hash only for args (dev/internal)
//   - `external` — basename only (e.g., "curl"), hash only for args (default)
//   - `full`     — category label (e.g., "tool_execution"), hash only for args
//
// See docs/linnix-claw/specs.md §10.4.

use serde::{Deserialize, Serialize};
use std::path::Path;

// =============================================================================
// REDACTION LEVEL
// =============================================================================

/// Receipt redaction level (§10.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RedactionLevel {
    /// Full binary path exposed. For internal/dev environments.
    None,
    /// Basename only (e.g., `/usr/bin/curl` → `curl`). Default.
    External,
    /// Generic category label (e.g., `tool_execution`). Maximum privacy.
    Full,
}

impl Default for RedactionLevel {
    fn default() -> Self {
        Self::External
    }
}

impl std::fmt::Display for RedactionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::External => write!(f, "external"),
            Self::Full => write!(f, "full"),
        }
    }
}

impl std::str::FromStr for RedactionLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(Self::None),
            "external" => Ok(Self::External),
            "full" => Ok(Self::Full),
            other => Err(format!(
                "invalid redaction level '{}': expected none, external, or full",
                other
            )),
        }
    }
}

// =============================================================================
// BINARY CLASSIFICATION (for "full" redaction)
// =============================================================================

/// Classify a binary path into a generic category.
///
/// Used when `redaction_level = "full"` to replace the binary field
/// with a non-revealing label.
fn classify_binary(binary_path: &str) -> &'static str {
    let basename = Path::new(binary_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(binary_path);

    match basename {
        // Network tools
        "curl" | "wget" | "fetch" | "httpie" | "aria2c" => "network_transfer",
        // Data processing
        "jq" | "yq" | "csvtool" | "awk" | "sed" | "grep" | "sort" | "uniq" | "cut" | "tr" => {
            "data_processing"
        }
        // Shells
        "bash" | "sh" | "zsh" | "fish" | "dash" => "shell_execution",
        // Python / interpreters
        "python" | "python3" | "python3.11" | "python3.12" | "node" | "ruby" | "perl" => {
            "interpreter_execution"
        }
        // Compilers / build tools
        "gcc" | "g++" | "clang" | "rustc" | "cargo" | "make" | "cmake" | "ninja" => "build_tool",
        // Container / orchestration
        "docker" | "podman" | "kubectl" | "helm" | "crictl" => "container_tool",
        // Package managers
        "apt" | "apt-get" | "yum" | "dnf" | "pip" | "pip3" | "npm" | "yarn" | "pnpm" => {
            "package_manager"
        }
        // File operations
        "cp" | "mv" | "rm" | "mkdir" | "chmod" | "chown" | "tar" | "zip" | "unzip" | "gzip" => {
            "file_operation"
        }
        // System inspection
        "ps" | "top" | "htop" | "lsof" | "strace" | "ltrace" | "perf" | "vmstat" | "iostat" => {
            "system_inspection"
        }
        // Default
        _ => "tool_execution",
    }
}

// =============================================================================
// RECEIPT REDACTOR
// =============================================================================

/// Redacts receipt fields based on the configured level.
pub struct ReceiptRedactor {
    level: RedactionLevel,
}

impl ReceiptRedactor {
    pub fn new(level: RedactionLevel) -> Self {
        Self { level }
    }

    /// Redact a binary path according to the configured level.
    ///
    /// - `none` → `/usr/bin/curl` (unchanged)
    /// - `external` → `curl` (basename only)
    /// - `full` → `network_transfer` (category)
    pub fn redact_binary(&self, binary_path: &str) -> String {
        match self.level {
            RedactionLevel::None => binary_path.to_string(),
            RedactionLevel::External => Path::new(binary_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(binary_path)
                .to_string(),
            RedactionLevel::Full => classify_binary(binary_path).to_string(),
        }
    }

    /// Determine if args should be included as-is or hash-only.
    /// Args are ALWAYS hash-only at all levels per §10.4.
    pub fn should_redact_args(&self) -> bool {
        true // Always true — args are always hash-only
    }

    /// Redact an optional task context / URL field.
    ///
    /// - `none` → unchanged
    /// - `external` → domain only (strip path/query)
    /// - `full` → "[redacted]"
    pub fn redact_url(&self, url: &str) -> String {
        match self.level {
            RedactionLevel::None => url.to_string(),
            RedactionLevel::External => {
                // Extract domain: "https://api.example.com/v1/data?key=secret"
                //                → "api.example.com"
                if let Some(start) = url.find("://") {
                    let after_scheme = &url[start + 3..];
                    let end = after_scheme.find('/').unwrap_or(after_scheme.len());
                    after_scheme[..end].to_string()
                } else {
                    url.split('/').next().unwrap_or(url).to_string()
                }
            }
            RedactionLevel::Full => "[redacted]".to_string(),
        }
    }

    /// Get current redaction level.
    pub fn level(&self) -> RedactionLevel {
        self.level
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── RedactionLevel parsing ──

    #[test]
    fn parse_redaction_levels() {
        assert_eq!(
            "none".parse::<RedactionLevel>().unwrap(),
            RedactionLevel::None
        );
        assert_eq!(
            "external".parse::<RedactionLevel>().unwrap(),
            RedactionLevel::External
        );
        assert_eq!(
            "full".parse::<RedactionLevel>().unwrap(),
            RedactionLevel::Full
        );
        assert_eq!(
            "EXTERNAL".parse::<RedactionLevel>().unwrap(),
            RedactionLevel::External
        );
        assert!("invalid".parse::<RedactionLevel>().is_err());
    }

    #[test]
    fn display_redaction_level() {
        assert_eq!(RedactionLevel::None.to_string(), "none");
        assert_eq!(RedactionLevel::External.to_string(), "external");
        assert_eq!(RedactionLevel::Full.to_string(), "full");
    }

    #[test]
    fn default_redaction_level() {
        assert_eq!(RedactionLevel::default(), RedactionLevel::External);
    }

    // ── Binary redaction ──

    #[test]
    fn redact_binary_none() {
        let r = ReceiptRedactor::new(RedactionLevel::None);
        assert_eq!(r.redact_binary("/usr/bin/curl"), "/usr/bin/curl");
        assert_eq!(
            r.redact_binary("/usr/local/bin/python3"),
            "/usr/local/bin/python3"
        );
    }

    #[test]
    fn redact_binary_external() {
        let r = ReceiptRedactor::new(RedactionLevel::External);
        assert_eq!(r.redact_binary("/usr/bin/curl"), "curl");
        assert_eq!(r.redact_binary("/usr/local/bin/python3"), "python3");
        assert_eq!(r.redact_binary("docker"), "docker"); // already basename
    }

    #[test]
    fn redact_binary_full() {
        let r = ReceiptRedactor::new(RedactionLevel::Full);
        assert_eq!(r.redact_binary("/usr/bin/curl"), "network_transfer");
        assert_eq!(r.redact_binary("/usr/bin/jq"), "data_processing");
        assert_eq!(r.redact_binary("/usr/bin/bash"), "shell_execution");
        assert_eq!(r.redact_binary("/usr/bin/python3"), "interpreter_execution");
        assert_eq!(r.redact_binary("/usr/bin/gcc"), "build_tool");
        assert_eq!(r.redact_binary("/usr/bin/docker"), "container_tool");
        assert_eq!(r.redact_binary("/usr/bin/npm"), "package_manager");
        assert_eq!(r.redact_binary("/usr/bin/cp"), "file_operation");
        assert_eq!(r.redact_binary("/usr/bin/lsof"), "system_inspection");
        assert_eq!(r.redact_binary("/opt/custom/my-tool"), "tool_execution");
    }

    // ── URL redaction ──

    #[test]
    fn redact_url_none() {
        let r = ReceiptRedactor::new(RedactionLevel::None);
        assert_eq!(
            r.redact_url("https://api.example.com/v1/data?key=secret"),
            "https://api.example.com/v1/data?key=secret"
        );
    }

    #[test]
    fn redact_url_external() {
        let r = ReceiptRedactor::new(RedactionLevel::External);
        assert_eq!(
            r.redact_url("https://api.example.com/v1/data?key=secret"),
            "api.example.com"
        );
        assert_eq!(
            r.redact_url("http://internal:8080/metrics"),
            "internal:8080"
        );
    }

    #[test]
    fn redact_url_full() {
        let r = ReceiptRedactor::new(RedactionLevel::Full);
        assert_eq!(
            r.redact_url("https://api.example.com/v1/data"),
            "[redacted]"
        );
    }

    // ── Args always redacted ──

    #[test]
    fn args_always_hash_only() {
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

    // ── Binary classification ──

    #[test]
    fn classify_known_binaries() {
        assert_eq!(classify_binary("/usr/bin/curl"), "network_transfer");
        assert_eq!(classify_binary("wget"), "network_transfer");
        assert_eq!(classify_binary("awk"), "data_processing");
        assert_eq!(classify_binary("bash"), "shell_execution");
        assert_eq!(classify_binary("node"), "interpreter_execution");
        assert_eq!(classify_binary("cargo"), "build_tool");
        assert_eq!(classify_binary("kubectl"), "container_tool");
        assert_eq!(classify_binary("pip3"), "package_manager");
        assert_eq!(classify_binary("tar"), "file_operation");
        assert_eq!(classify_binary("vmstat"), "system_inspection");
    }

    #[test]
    fn classify_unknown_binary() {
        assert_eq!(classify_binary("my-custom-agent"), "tool_execution");
        assert_eq!(classify_binary("/opt/unknown"), "tool_execution");
    }

    // ── Retention config test ──

    #[test]
    fn redactor_reports_level() {
        let r = ReceiptRedactor::new(RedactionLevel::Full);
        assert_eq!(r.level(), RedactionLevel::Full);
    }
}
