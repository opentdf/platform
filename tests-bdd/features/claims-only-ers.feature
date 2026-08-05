@claims-only-ers @stateless
Feature: Claims-only ERS resolution (no LDAP)
  Validate that Entity_Claims entities carrying claims inline can be resolved
  by a claims-only multi-strategy ERS without needing LDAP.

  Background:
    And an ERS configuration with mode "multi-strategy" and failure strategy "continue"
    And an ERS provider "jwt_claims" of type "claims"
    And an ERS mapping strategy "claims_department" using provider "jwt_claims"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: department
            operator: exists
      output_mapping:
        - source_claim: department
          claim_name: department
        - source_claim: userName
          claim_name: username
      """
    And a local platform with inline ERS configuration

  Scenario: Claims entity with engineering department gets PERMIT
    Given I submit a request to create a namespace with name "claims-only.test" and reference id "ns_claims"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_claims    | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_claims" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_claims" containing the condition groups "cg_claims"
    And I send a request to create a subject condition set referenced as "scs_claims" containing subject sets "ss_claims"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                            | condition_set_name | standard actions | custom actions |
      | sm_claims    | https://claims-only.test/attr/department/value/engineering | scs_claims         | read             |                |
    Then the response should be successful
    Given there is a claims subject entity referenced as "diana_claims" with claims:
      """
      {"userName":"diana","department":"engineering"}
      """
    When I send a decision request for entity chain "diana_claims" for "read" action on resource "https://claims-only.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Claims entity with marketing department gets DENY for engineering resource
    Given I submit a request to create a namespace with name "claims-deny.test" and reference id "ns_claims_deny"
    And I send a request to create an attribute with:
      | namespace_id   | name       | rule  | values                         |
      | ns_claims_deny | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_claims_deny" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_claims_deny" containing the condition groups "cg_claims_deny"
    And I send a request to create a subject condition set referenced as "scs_claims_deny" containing subject sets "ss_claims_deny"
    And I send a request to create a subject mapping with:
      | reference_id   | attribute_value                                           | condition_set_name | standard actions | custom actions |
      | sm_claims_deny | https://claims-deny.test/attr/department/value/engineering | scs_claims_deny    | read             |                |
    Then the response should be successful
    Given there is a claims subject entity referenced as "bob_claims" with claims:
      """
      {"userName":"bob","department":"marketing"}
      """
    When I send a decision request for entity chain "bob_claims" for "read" action on resource "https://claims-deny.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "DENY" decision response
