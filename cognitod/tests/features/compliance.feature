Feature: Compliance Screening (§10.3)
  As a regulated platform operator
  I want sanctions screening, KYT thresholds, and jurisdiction blocks
  So that agent commerce complies with financial regulations

  # ── Jurisdiction Blocks ──

  Scenario: Block transaction with sanctioned jurisdiction
    Given compliance is enabled with blocked jurisdictions "KP,IR,CU,SY"
    When a task is proposed with counterparty "did:web:nk-agent" in jurisdiction "KP"
    Then the compliance check should hard-block

  Scenario: Allow transaction from permitted jurisdiction
    Given compliance is enabled with blocked jurisdictions "KP,IR,CU,SY"
    When a task is proposed with counterparty "did:web:us-agent" in jurisdiction "US"
    Then the compliance check should pass

  Scenario: Jurisdiction check is case-insensitive
    Given compliance is enabled with blocked jurisdictions "KP,IR,CU,SY"
    When a task is proposed with counterparty "did:web:ir-agent" in jurisdiction "ir"
    Then the compliance check should hard-block

  # ── OFAC SDN Screening ──

  Scenario: Block a wallet on the OFAC SDN list
    Given the OFAC SDN list contains wallet "0xbadwallet123"
    When a task involves wallet "0xBadWallet123" for 100 cents
    Then the compliance check should hard-block

  Scenario: Clear a wallet not on any list
    Given the OFAC SDN list contains wallet "0xbadwallet123"
    When a task involves wallet "0xgoodwallet456" for 100 cents
    Then the compliance check should pass

  Scenario: Block a DID on the OFAC SDN list
    Given the OFAC SDN list contains DID "did:web:sanctioned-entity.kp"
    When a task is proposed with counterparty "did:web:sanctioned-entity.kp" in jurisdiction "US"
    Then the compliance check should hard-block

  # ── KYT (Know Your Transaction) ──

  Scenario: Trigger KYT for high-value transaction
    Given compliance is enabled with KYT threshold of 300000 cents
    When a task is proposed for 300000 cents
    Then the compliance result should require enhanced due diligence

  Scenario: No KYT for transaction below threshold
    Given compliance is enabled with KYT threshold of 300000 cents
    When a task is proposed for 299999 cents
    Then the compliance result should not require enhanced due diligence

  # ── Travel Rule ──

  Scenario: Travel Rule required at $3,000
    Given compliance is enabled with KYT threshold of 300000 cents
    Then Travel Rule data is required for 300000 cents
    But Travel Rule data is not required for 299999 cents

  # ── Compliance Disabled ──

  Scenario: All checks pass when compliance is disabled
    Given compliance is disabled
    When a task is proposed with counterparty "did:web:evil.kp" in jurisdiction "KP"
    Then the compliance check should pass
