@ers-condition-contains @stateless
Feature: ERS condition operator — contains
  Validate that the "contains" condition operator performs case-insensitive
  substring matching on JWT claims to select the correct mapping strategy.

  The contains operator checks if a string claim value contains any of the
  values in condition.Values[] as a substring (case-insensitive).

  Background:
    Given an LDAP directory with test users
    And an ERS configuration with mode "multi-strategy" and failure strategy "continue"
    And an ERS provider "ldap_directory" of type "ldap" connected to the LDAP directory
    And an ERS mapping strategy "contains_ali_strat" using provider "ldap_directory"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: userName
            operator: contains
            values: ["ali"]
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

  Scenario: Contains condition matches substring — "alice" contains "ali" gets PERMIT
    Given I submit a request to create a namespace with name "ct-match.test" and reference id "ns_ct_match"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_ct_match  | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_ct_match" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_ct_match" containing the condition groups "cg_ct_match"
    And I send a request to create a subject condition set referenced as "scs_ct_match" containing subject sets "ss_ct_match"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                         | condition_set_name | standard actions | custom actions |
      | sm_ct_match  | https://ct-match.test/attr/department/value/engineering | scs_ct_match       | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "alice" and referenced as "alice_ct"
    When I send a decision request for entity chain "alice_ct" for "read" action on resource "https://ct-match.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Contains condition does not match — "bob" does not contain "ali" gets DENY
    Given I submit a request to create a namespace with name "ct-nomatch.test" and reference id "ns_ct_nomatch"
    And I send a request to create an attribute with:
      | namespace_id   | name       | rule  | values                         |
      | ns_ct_nomatch  | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_ct_nomatch" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_ct_nomatch" containing the condition groups "cg_ct_nomatch"
    And I send a request to create a subject condition set referenced as "scs_ct_nomatch" containing subject sets "ss_ct_nomatch"
    And I send a request to create a subject mapping with:
      | reference_id   | attribute_value                                            | condition_set_name | standard actions | custom actions |
      | sm_ct_nomatch  | https://ct-nomatch.test/attr/department/value/engineering  | scs_ct_nomatch     | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "bob" and referenced as "bob_ct"
    When I send a decision request for entity chain "bob_ct" for "read" action on resource "https://ct-nomatch.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "DENY" decision response
