@claims-array-ers @stateless
Feature: Array-valued claims in multi-strategy ERS
  Validate that Entity_Claims carrying array-valued claims (e.g., groups)
  survive the full pipeline: claims provider → output mapping → flattening →
  subject mapping evaluation → authorization decision.

  Array claims require the `.groups[]` wildcard selector in subject condition
  sets — the flattening library produces indexed keys (.groups[0], .groups[1])
  and wildcard keys (.groups[]) but NOT a plain .groups key for arrays.

  Background:
    And an ERS configuration with mode "multi-strategy" and failure strategy "continue"
    And an ERS provider "jwt_claims" of type "claims"
    And an ERS mapping strategy "claims_groups" using provider "jwt_claims"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: groups
            operator: exists
      output_mapping:
        - source_claim: groups
          claim_name: groups
        - source_claim: userName
          claim_name: username
      """
    And a local platform with inline ERS configuration

  Scenario: Array claim with matching element gets PERMIT
    Given I submit a request to create a namespace with name "arr-permit.test" and reference id "ns_arr_permit"
    And I send a request to create an attribute with:
      | namespace_id   | name   | rule  | values                         |
      | ns_arr_permit  | groups | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_arr_permit" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .groups[]      | in       | engineering |
    And a subject set referenced as "ss_arr_permit" containing the condition groups "cg_arr_permit"
    And I send a request to create a subject condition set referenced as "scs_arr_permit" containing subject sets "ss_arr_permit"
    And I send a request to create a subject mapping with:
      | reference_id   | attribute_value                                          | condition_set_name | standard actions | custom actions |
      | sm_arr_permit  | https://arr-permit.test/attr/groups/value/engineering    | scs_arr_permit     | read             |                |
    Then the response should be successful
    Given there is a claims subject entity referenced as "alice_arr" with claims:
      """
      {"userName":"alice","groups":["engineering","devops"]}
      """
    When I send a decision request for entity chain "alice_arr" for "read" action on resource "https://arr-permit.test/attr/groups/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Array claim with no matching element gets DENY
    Given I submit a request to create a namespace with name "arr-deny.test" and reference id "ns_arr_deny"
    And I send a request to create an attribute with:
      | namespace_id | name   | rule  | values                         |
      | ns_arr_deny  | groups | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_arr_deny" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .groups[]      | in       | engineering |
    And a subject set referenced as "ss_arr_deny" containing the condition groups "cg_arr_deny"
    And I send a request to create a subject condition set referenced as "scs_arr_deny" containing subject sets "ss_arr_deny"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                        | condition_set_name | standard actions | custom actions |
      | sm_arr_deny  | https://arr-deny.test/attr/groups/value/engineering    | scs_arr_deny       | read             |                |
    Then the response should be successful
    Given there is a claims subject entity referenced as "bob_arr" with claims:
      """
      {"userName":"bob","groups":["marketing","sales"]}
      """
    When I send a decision request for entity chain "bob_arr" for "read" action on resource "https://arr-deny.test/attr/groups/value/engineering"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: Array claim with anyOf rule matches one of multiple attribute values
    Given I submit a request to create a namespace with name "arr-anyof.test" and reference id "ns_arr_anyof"
    And I send a request to create an attribute with:
      | namespace_id  | name   | rule  | values                         |
      | ns_arr_anyof  | groups | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_arr_anyof" with an "or" operator with conditions:
      | selector_value | operator | values               |
      | .groups[]      | in       | engineering,security |
    And a subject set referenced as "ss_arr_anyof" containing the condition groups "cg_arr_anyof"
    And I send a request to create a subject condition set referenced as "scs_arr_anyof" containing subject sets "ss_arr_anyof"
    And I send a request to create a subject mapping with:
      | reference_id  | attribute_value                                         | condition_set_name | standard actions | custom actions |
      | sm_arr_anyof  | https://arr-anyof.test/attr/groups/value/security       | scs_arr_anyof      | read             |                |
    Then the response should be successful
    Given there is a claims subject entity referenced as "charlie_arr" with claims:
      """
      {"userName":"charlie","groups":["security","devops"]}
      """
    When I send a decision request for entity chain "charlie_arr" for "read" action on resource "https://arr-anyof.test/attr/groups/value/security"
    Then the response should be successful
    And I should get a "PERMIT" decision response
