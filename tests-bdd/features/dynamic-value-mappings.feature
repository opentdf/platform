@dynamic-value-mappings
Feature: Encrypt and decrypt with dynamic value mappings
  Validates that a Dynamic Value Mapping entitles a subject to decrypt a TDF
  bound to an attribute value under the mapped definition, without a per-value
  subject mapping. Entitlement is resolved at decision time by comparing the
  requested resource value segment against a selector on the entity
  representation (keycloak ERS). Requires allow_dynamic_value_mappings.

  Background:
    Given a user exists with username "alice" and email "alice@example.com" and the following attributes:
      | name       | value            |
      | department | ["engineering"]  |
      | clearance  | ["alpha","beta"] |
    And a user exists with username "bob" and email "bob@example.com" and the following attributes:
      | name       | value       |
      | department | ["finance"] |
      | clearance  | ["alpha"]   |
    And a user exists with username "carol" and email "carol@example.com" and the following attributes:
      | name       | value           |
      | department | ["engineering"] |
      | clearance  | ["beta"]        |
    And a local platform with platform template "cukes/resources/platform.dynamic_value_mappings.template" and keycloak template "cukes/resources/keycloak_base.template"
    And a user token for "alice" stored as "alice_tok"
    And a user token for "bob" stored as "bob_tok"
    And a user token for "carol" stored as "carol_tok"
    And I submit a request to create a namespace with name "example.com" and reference id "ns1"
    And I send a request to create an attribute with:
      | namespace_id | name      | rule  | values             |
      | ns1          | team      | anyOf | engineering,finance |
      | ns1          | project   | anyOf | engineer            |
      | ns1          | clearance | allOf | alpha,beta          |
    Then the response should be successful

  Scenario: IN operator permits an exact department match and denies others
    Given I send a request to create a dynamic value mapping with:
      | attribute_definition_fqn      | selector               | operator | standard actions | reference_id |
      | https://example.com/attr/team | .attributes.department[] | IN       | read             | dvm_team     |
    And the response should be successful
    When I encrypt plaintext "team engineering" with attributes "https://example.com/attr/team/value/engineering" stored as "tdf_in"
    And using token "alice_tok", decrypt "tdf_in" stored as "alice_in"
    And using token "bob_tok", decrypt "tdf_in" stored as "bob_in"
    Then the decryption stored as "alice_in" should succeed with plaintext "team engineering"
    And the decryption stored as "bob_in" should be denied

  Scenario: IN_CONTAINS operator permits a substring match
    Given I send a request to create a dynamic value mapping with:
      | attribute_definition_fqn         | selector               | operator    | standard actions | reference_id |
      | https://example.com/attr/project | .attributes.department[] | IN_CONTAINS | read             | dvm_project  |
    And the response should be successful
    When I encrypt plaintext "substring match" with attributes "https://example.com/attr/project/value/engineer" stored as "tdf_contains"
    And using token "alice_tok", decrypt "tdf_contains" stored as "alice_contains"
    And using token "bob_tok", decrypt "tdf_contains" stored as "bob_contains"
    Then the decryption stored as "alice_contains" should succeed with plaintext "substring match"
    And the decryption stored as "bob_contains" should be denied

  Scenario: Static pre-gate must also pass for entitlement
    Given a condition group referenced as "cg_alpha" with an "or" operator with conditions:
      | selector_value        | operator | values |
      | .attributes.clearance[] | in       | alpha  |
    And a subject set referenced as "ss_alpha" containing the condition groups "cg_alpha"
    And I send a request to create a subject condition set referenced as "scs_alpha" containing subject sets "ss_alpha"
    And I send a request to create a dynamic value mapping with:
      | attribute_definition_fqn      | selector               | operator | standard actions | condition_set_name | reference_id |
      | https://example.com/attr/team | .attributes.department[] | IN       | read             | scs_alpha          | dvm_gated    |
    And the response should be successful
    When I encrypt plaintext "gated engineering" with attributes "https://example.com/attr/team/value/engineering" stored as "tdf_gated"
    And using token "alice_tok", decrypt "tdf_gated" stored as "alice_gated"
    And using token "carol_tok", decrypt "tdf_gated" stored as "carol_gated"
    Then the decryption stored as "alice_gated" should succeed with plaintext "gated engineering"
    # carol matches the mapping (department engineering) but fails the static pre-gate (no clearance alpha)
    And the decryption stored as "carol_gated" should be denied

  Scenario: ALL_OF multi-value requires entitlement to every bound value
    Given I send a request to create a dynamic value mapping with:
      | attribute_definition_fqn           | selector              | operator | standard actions | reference_id  |
      | https://example.com/attr/clearance | .attributes.clearance[] | IN       | read             | dvm_clearance |
    And the response should be successful
    When I encrypt plaintext "all of clearance" with attributes "https://example.com/attr/clearance/value/alpha,https://example.com/attr/clearance/value/beta" stored as "tdf_allof"
    And using token "alice_tok", decrypt "tdf_allof" stored as "alice_allof"
    And using token "bob_tok", decrypt "tdf_allof" stored as "bob_allof"
    Then the decryption stored as "alice_allof" should succeed with plaintext "all of clearance"
    And the decryption stored as "bob_allof" should be denied
