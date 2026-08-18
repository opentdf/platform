@ers-condition-and-mixed @stateless
Feature: ERS condition — mixed operator AND logic
  Validate that AND logic works across different operator types on the
  same or different claims. A strategy with a regex condition plus a
  contains condition requires both to match for selection.

  Background:
    Given an LDAP directory with test users
    And an ERS configuration with mode "multi-strategy" and failure strategy "continue"
    And an ERS provider "ldap_directory" of type "ldap" connected to the LDAP directory
    And an ERS mapping strategy "mixed_ops_strat" using provider "ldap_directory"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: userName
            operator: regex
            values: ["^[a-d].*"]
          - claim: userName
            operator: contains
            values: ["an"]
      ldap_search:
        base_dn: "ou=users,dc=opentdf,dc=test"
        filter: "(&(objectClass=inetOrgPerson)(uid={username}))"
        scope: subtree
        attributes: ["uid", "mail", "departmentNumber"]
      input_mapping:
        - jwt_claim: userName
          parameter: username
      output_mapping:
        - source_attribute: departmentNumber
          claim_name: department
        - source_attribute: uid
          claim_name: username
      """
    And a local platform with inline ERS configuration

  Scenario: Both mixed conditions match — diana matches regex "^[a-d].*" and contains "an" gets PERMIT
    Given I submit a request to create a namespace with name "mixed-match.test" and reference id "ns_mixed_match"
    And I send a request to create an attribute with:
      | namespace_id    | name       | rule  | values                         |
      | ns_mixed_match  | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_mixed_match" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_mixed_match" containing the condition groups "cg_mixed_match"
    And I send a request to create a subject condition set referenced as "scs_mixed_match" containing subject sets "ss_mixed_match"
    And I send a request to create a subject mapping with:
      | reference_id    | attribute_value                                              | condition_set_name | standard actions | custom actions |
      | sm_mixed_match  | https://mixed-match.test/attr/department/value/engineering   | scs_mixed_match    | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "diana" and referenced as "diana_mixed"
    When I send a decision request for entity chain "diana_mixed" for "read" action on resource "https://mixed-match.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Regex matches but contains does not — alice matches "^[a-d].*" but not "an" gets DENY
    Given I submit a request to create a namespace with name "mixed-partial.test" and reference id "ns_mixed_partial"
    And I send a request to create an attribute with:
      | namespace_id      | name       | rule  | values                         |
      | ns_mixed_partial  | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_mixed_partial" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_mixed_partial" containing the condition groups "cg_mixed_partial"
    And I send a request to create a subject condition set referenced as "scs_mixed_partial" containing subject sets "ss_mixed_partial"
    And I send a request to create a subject mapping with:
      | reference_id      | attribute_value                                                | condition_set_name | standard actions | custom actions |
      | sm_mixed_partial  | https://mixed-partial.test/attr/department/value/engineering   | scs_mixed_partial  | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "alice" and referenced as "alice_mixed"
    When I send a decision request for entity chain "alice_mixed" for "read" action on resource "https://mixed-partial.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "DENY" decision response
