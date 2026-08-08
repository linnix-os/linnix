Feature: Full Agent Commerce Pipeline
  As an AI agent platform
  I want spend checks, compliance screening, settlement, and privacy
  to work together as a single pipeline
  So that each transaction is safe, legal, and private

  Scenario: Honest task succeeds end-to-end
    Given the spend limit is 5000 cents per mandate
    And compliance is enabled with US jurisdiction allowed
    And redaction level is "external"
    When agent "did:web:vendor.com" in "US" proposes a 1500-cent task
    Then compliance screening passes
    And the spend check passes
    And settlement succeeds for 1500 cents
    And the binary "/usr/bin/curl" is redacted to "curl"

  Scenario: Sanctioned jurisdiction blocks the entire pipeline
    Given the spend limit is 5000 cents per mandate
    And compliance is enabled with KP jurisdiction blocked
    When agent "did:web:evil.kp" in "KP" proposes a 100-cent task
    Then compliance screening blocks the task
    And no settlement occurs

  Scenario: Spend limit blocks after compliance passes
    Given the spend limit is 5000 cents per mandate
    And compliance is enabled with US jurisdiction allowed
    When agent "did:web:vendor.com" in "US" proposes a 6000-cent task
    Then compliance screening passes
    But the spend check fails with "PerMandate"
    And no settlement occurs
