@ers-transformation-service @stateless
Feature: Transformations through the ERS service path
  Validate that output_mapping transformations (array, csv_to_array, lowercase)
  work correctly through the full ERS service → gRPC → authorization pipeline,
  not just at the unit test level.

  Transformation unit tests exist in claims_mapper_test.go and ldap_mapper_test.go,
  but no BDD feature exercises a transformation through the actual service path
  where OutputMapper is called (service.go:269-271). This catches integration
  issues between transformation output format and subject mapping evaluation.

  This covers Jake's gap analysis row #5.

  Background:
    And an ERS configuration with mode "multi-strategy" and failure strategy "continue"
    And an ERS provider "jwt_claims" of type "claims"
    And an ERS mapping strategy "claims_with_array_transform" using provider "jwt_claims"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: userName
            operator: exists
      output_mapping:
        - source_claim: department
          claim_name: department
          transformation: array
        - source_claim: userName
          claim_name: username
      """
    And a local platform with inline ERS configuration

  Scenario: Array transformation — string claim transformed to array matches anyOf selector
    Given I submit a request to create a namespace with name "xform-array.test" and reference id "ns_xa"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_xa        | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_xa" with an "or" operator with conditions:
      | selector_value  | operator | values      |
      | .department[]   | in       | engineering |
    And a subject set referenced as "ss_xa" containing the condition groups "cg_xa"
    And I send a request to create a subject condition set referenced as "scs_xa" containing subject sets "ss_xa"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                            | condition_set_name | standard actions | custom actions |
      | sm_xa        | https://xform-array.test/attr/department/value/engineering | scs_xa             | read             |                |
    Then the response should be successful
    Given there is a claims subject entity referenced as "alice_xa" with claims:
      """
      {"userName":"alice","department":"engineering"}
      """
    When I send a decision request for entity chain "alice_xa" for "read" action on resource "https://xform-array.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Array transformation — non-matching value gets DENY
    Given I submit a request to create a namespace with name "xform-array-deny.test" and reference id "ns_xad"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_xad       | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_xad" with an "or" operator with conditions:
      | selector_value  | operator | values      |
      | .department[]   | in       | engineering |
    And a subject set referenced as "ss_xad" containing the condition groups "cg_xad"
    And I send a request to create a subject condition set referenced as "scs_xad" containing subject sets "ss_xad"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                                 | condition_set_name | standard actions | custom actions |
      | sm_xad       | https://xform-array-deny.test/attr/department/value/engineering | scs_xad            | read             |                |
    Then the response should be successful
    Given there is a claims subject entity referenced as "bob_xad" with claims:
      """
      {"userName":"bob","department":"marketing"}
      """
    When I send a decision request for entity chain "bob_xad" for "read" action on resource "https://xform-array-deny.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "DENY" decision response

