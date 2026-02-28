Feature: Spend Controls (§9)
  As a platform operator
  I want configurable spending limits on agent commerce
  So that a compromised or buggy agent cannot drain funds

  Background:
    Given the default spend limits are configured
      | limit             | value  |
      | per_mandate_cents | 5000   |
      | daily_cents       | 50000  |
      | monthly_cents     | 500000 |

  # ── Per-Mandate Limits ──

  Scenario: Allow a spend within the per-mandate limit
    When an agent requests a mandate for 4999 cents
    Then the spend check should pass

  Scenario: Block a spend exceeding the per-mandate limit
    When an agent requests a mandate for 5001 cents
    Then the spend check should fail with "PerMandate"

  Scenario: Exactly at the per-mandate limit is allowed
    When an agent requests a mandate for 5000 cents
    Then the spend check should pass

  # ── Daily Aggregate Limits ──

  Scenario: Accumulate daily spend and block at threshold
    Given 48000 cents have already been spent today
    When an agent requests a mandate for 3000 cents
    Then the spend check should fail with "Daily"

  Scenario: Daily spend just under the limit passes
    Given 48000 cents have already been spent today
    When an agent requests a mandate for 2000 cents
    Then the spend check should pass

  # ── Monthly Aggregate Limits ──

  Scenario: Allow spend just under monthly ceiling
    Given 495000 cents have already been spent this month
    When an agent requests a mandate for 5000 cents
    Then the spend check should pass

  Scenario: Block spend that exceeds monthly ceiling
    Given 495000 cents have already been spent this month
    And 5000 cents have already been spent today
    When an agent requests a mandate for 1 cents
    Then the spend check should fail with "Monthly"

  # ── Per-Agent Overrides ──

  Scenario: Restrict an untrusted agent to lower daily limit
    Given a per-agent override for "did:web:untrusted.io" of 1000 cents daily
    And the agent "did:web:untrusted.io" has spent 900 cents today
    When "did:web:untrusted.io" requests a mandate for 200 cents
    Then the spend check should fail with "PerAgentDaily"

  Scenario: Trusted agent is unaffected by untrusted override
    Given a per-agent override for "did:web:untrusted.io" of 1000 cents daily
    And the agent "did:web:untrusted.io" has spent 900 cents today
    When "did:web:trusted.io" requests a mandate for 4000 cents
    Then the spend check should pass

  # ── Zero and Edge Cases ──

  Scenario: Zero-cent mandate is always allowed
    Given 49999 cents have already been spent today
    When an agent requests a mandate for 0 cents
    Then the spend check should pass

  # ── Hourly Limit ──

  Scenario: Hourly limit blocks burst spending
    Given an hourly limit of 10000 cents is configured
    And 9500 cents have been spent in the last hour
    When an agent requests a mandate for 600 cents
    Then the spend check should fail with "Hourly"
