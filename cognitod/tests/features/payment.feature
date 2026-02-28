Feature: Payment Adapter & Amount Conversion (§8)
  As an agent commerce platform
  I want correct conversion between USD cents and token base units
  So that on-chain settlements match off-chain accounting

  # ── USDC (6 decimals) ──

  Scenario Outline: USDC cent-to-base-unit conversion
    Given the token is USDC with 6 decimals
    When converting <cents> cents to base units
    Then the result should be <base_units> base units

    Examples:
      | cents  | base_units   |
      | 1      | 10000        |
      | 15     | 150000       |
      | 100    | 1000000      |
      | 5000   | 50000000     |

  # ── DAI (18 decimals) ──

  Scenario: DAI 18-decimal conversion
    Given the token is DAI with 18 decimals
    When converting 100 cents to base units
    Then the result should be 1000000000000000000 base units

  # ── Round-trip ──

  Scenario: USDC round-trip conversion preserves value
    Given the token is USDC with 6 decimals
    When converting 4215 cents to base units and back
    Then the round-trip result should equal 4215 cents

  # ── Settlement Adapters ──

  Scenario: Stripe stub settles successfully
    Given a Stripe stub payment adapter
    When settling a receipt for 1500 cents
    Then the settlement should succeed
    And the settled amount should be 1500 cents

  Scenario: Noop adapter for offline mode
    Given a noop payment adapter
    When settling a receipt for 999 cents
    Then the settlement should succeed
    And the settlement path should be "Manual"
