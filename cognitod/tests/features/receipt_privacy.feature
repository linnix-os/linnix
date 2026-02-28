Feature: Receipt Privacy & Redaction (§10.4)
  As a privacy-conscious operator
  I want configurable redaction levels for execution receipts
  So that sensitive operational details are not leaked to counterparties

  # ── Redaction Level: None ──

  Scenario: No redaction exposes full binary path
    Given redaction level is "none"
    When redacting binary "/usr/bin/curl"
    Then the result should be "/usr/bin/curl"

  Scenario: No redaction exposes full URL
    Given redaction level is "none"
    When redacting URL "https://api.secret.com/v1/data?key=abc"
    Then the result should be "https://api.secret.com/v1/data?key=abc"

  # ── Redaction Level: External (default) ──

  Scenario: External redaction shows basename only
    Given redaction level is "external"
    When redacting binary "/usr/bin/curl"
    Then the result should be "curl"

  Scenario: External redaction extracts domain from URL
    Given redaction level is "external"
    When redacting URL "https://api.secret.com/v1/data?key=abc"
    Then the result should be "api.secret.com"

  # ── Redaction Level: Full ──

  Scenario: Full redaction classifies curl as network_transfer
    Given redaction level is "full"
    When redacting binary "/usr/bin/curl"
    Then the result should be "network_transfer"

  Scenario: Full redaction classifies python3 as interpreter_execution
    Given redaction level is "full"
    When redacting binary "/usr/bin/python3"
    Then the result should be "interpreter_execution"

  Scenario: Full redaction classifies docker as container_tool
    Given redaction level is "full"
    When redacting binary "/usr/local/bin/docker"
    Then the result should be "container_tool"

  Scenario: Full redaction replaces URL with [redacted]
    Given redaction level is "full"
    When redacting URL "https://api.secret.com/v1/data"
    Then the result should be "[redacted]"

  Scenario: Full redaction classifies unknown binary as tool_execution
    Given redaction level is "full"
    When redacting binary "/opt/custom/my-proprietary-agent"
    Then the result should be "tool_execution"

  # ── Args are always hash-only ──

  Scenario Outline: Arguments are always hash-only regardless of level
    Given redaction level is "<level>"
    Then arguments should be hash-only

    Examples:
      | level    |
      | none     |
      | external |
      | full     |
