@ers-condition-and-logic @stateless
Feature: ERS condition — multiple conditions AND logic
  Validate that when a strategy has multiple JWT claim conditions, ALL
  conditions must match for the strategy to be selected (AND logic).

  Background:
    Given an LDAP directory with test users
    And an ERS configuration with mode "multi-strategy" and failure strategy "continue"
    And an ERS provider "ldap_directory" of type "ldap" connected to the LDAP directory
    And an ERS mapping strategy "multi_condition_strat" using provider "ldap_directory"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: userName
            operator: contains
            values: ["a"]
          - claim: userName
            operator: contains
            values: ["di"]
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

  Scenario: Both AND conditions match — diana contains "a" and "di" gets PERMIT
    Given I submit a request to create a namespace with name "and-match.test" and reference id "ns_and_match"
    And I send a request to create an attribute with:
      | namespace_id  | name       | rule  | values                         |
      | ns_and_match  | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_and_match" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_and_match" containing the condition groups "cg_and_match"
    And I send a request to create a subject condition set referenced as "scs_and_match" containing subject sets "ss_and_match"
    And I send a request to create a subject mapping with:
      | reference_id  | attribute_value                                           | condition_set_name | standard actions | custom actions |
      | sm_and_match  | https://and-match.test/attr/department/value/engineering  | scs_and_match      | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "diana" and referenced as "diana_and"
    When I send a decision request for entity chain "diana_and" for "read" action on resource "https://and-match.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Only one AND condition matches — alice contains "a" but not "di" gets DENY
    Given I submit a request to create a namespace with name "and-partial.test" and reference id "ns_and_partial"
    And I send a request to create an attribute with:
      | namespace_id    | name       | rule  | values                         |
      | ns_and_partial  | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_and_partial" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_and_partial" containing the condition groups "cg_and_partial"
    And I send a request to create a subject condition set referenced as "scs_and_partial" containing subject sets "ss_and_partial"
    And I send a request to create a subject mapping with:
      | reference_id    | attribute_value                                              | condition_set_name | standard actions | custom actions |
      | sm_and_partial  | https://and-partial.test/attr/department/value/engineering   | scs_and_partial    | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "alice" and referenced as "alice_and"
    When I send a decision request for entity chain "alice_and" for "read" action on resource "https://and-partial.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "DENY" decision response
