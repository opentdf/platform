@claims-only-ers @stateless
Feature: Multi-strategy ERS direct claims resolution
  Validate that multi-strategy ERS resolves inline claims entities through the full
  SDK -> Connect RPC -> platform -> ERS stack. This specifically covers the
  ResolveEntities path used by authorization decisions when subject entities carry
  claims directly instead of relying on LDAP lookup.

  Background:
    Given an ERS configuration with mode "multi-strategy" and failure strategy "fail-fast"
    And an ERS provider "jwt_claims" of type "claims"
    And an ERS mapping strategy "claims_passthrough" using provider "jwt_claims"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: userName
            operator: exists
      output_mapping:
        - source_claim: userName
          claim_name: username
        - source_claim: department
          claim_name: department
      """
    And a local platform with inline ERS configuration

  Scenario: Inline claims engineering user gets PERMIT
    Given I submit a request to create a namespace with name "claims-permit.test" and reference id "ns_claims_permit"
    And I send a request to create an attribute with:
      | namespace_id      | name       | rule  | values                         |
      | ns_claims_permit  | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_claims_eng" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_claims_eng" containing the condition groups "cg_claims_eng"
    And I send a request to create a subject condition set referenced as "scs_claims_eng" containing subject sets "ss_claims_eng"
    And I send a request to create a subject mapping with:
      | reference_id  | attribute_value                                              | condition_set_name | standard actions | custom actions |
      | sm_claims_eng | https://claims-permit.test/attr/department/value/engineering | scs_claims_eng     | read             |                |
    Then the response should be successful
    Given there is a claims subject entity referenced as "diana_claims" with claims:
      """
      {"userName":"diana","department":"engineering"}
      """
    When I send a decision request for entity chain "diana_claims" for "read" action on resource "https://claims-permit.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Inline claims marketing user gets DENY for engineering resource
    Given I submit a request to create a namespace with name "claims-deny.test" and reference id "ns_claims_deny"
    And I send a request to create an attribute with:
      | namespace_id    | name       | rule  | values                         |
      | ns_claims_deny  | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_claims_eng2" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_claims_eng2" containing the condition groups "cg_claims_eng2"
    And I send a request to create a subject condition set referenced as "scs_claims_eng2" containing subject sets "ss_claims_eng2"
    And I send a request to create a subject mapping with:
      | reference_id   | attribute_value                                            | condition_set_name | standard actions | custom actions |
      | sm_claims_eng2 | https://claims-deny.test/attr/department/value/engineering | scs_claims_eng2    | read             |                |
    Then the response should be successful
    Given there is a claims subject entity referenced as "bob_claims" with claims:
      """
      {"userName":"bob","department":"marketing"}
      """
    When I send a decision request for entity chain "bob_claims" for "read" action on resource "https://claims-deny.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "DENY" decision response
