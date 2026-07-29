@ers-condition-equals @stateless
Feature: ERS condition operator — equals
  Validate that the "equals" condition operator performs case-insensitive
  exact matching on JWT claims to select the correct mapping strategy.

  The equals operator checks if a claim value matches any of the values
  in condition.Values[] using strings.EqualFold (case-insensitive).

  Background:
    Given an LDAP directory with test users
    And an ERS configuration with mode "multi-strategy" and failure strategy "continue"
    And an ERS provider "ldap_directory" of type "ldap" connected to the LDAP directory

  Scenario: Equals condition matches — alice routed to strategy gets PERMIT
    And an ERS mapping strategy "alice_only_strategy" using provider "ldap_directory"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: userName
            operator: equals
            values: ["alice"]
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
    Given I submit a request to create a namespace with name "eq-match.test" and reference id "ns_eq_match"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_eq_match  | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_eq_match" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_eq_match" containing the condition groups "cg_eq_match"
    And I send a request to create a subject condition set referenced as "scs_eq_match" containing subject sets "ss_eq_match"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                         | condition_set_name | standard actions | custom actions |
      | sm_eq_match  | https://eq-match.test/attr/department/value/engineering | scs_eq_match       | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "alice" and referenced as "alice_eq"
    When I send a decision request for entity chain "alice_eq" for "read" action on resource "https://eq-match.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Equals condition does not match — bob skipped by alice-only strategy gets DENY
    And an ERS mapping strategy "alice_only_strat2" using provider "ldap_directory"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: userName
            operator: equals
            values: ["alice"]
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
    Given I submit a request to create a namespace with name "eq-nomatch.test" and reference id "ns_eq_nomatch"
    And I send a request to create an attribute with:
      | namespace_id   | name       | rule  | values                         |
      | ns_eq_nomatch  | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_eq_nomatch" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_eq_nomatch" containing the condition groups "cg_eq_nomatch"
    And I send a request to create a subject condition set referenced as "scs_eq_nomatch" containing subject sets "ss_eq_nomatch"
    And I send a request to create a subject mapping with:
      | reference_id   | attribute_value                                            | condition_set_name | standard actions | custom actions |
      | sm_eq_nomatch  | https://eq-nomatch.test/attr/department/value/engineering  | scs_eq_nomatch     | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "bob" and referenced as "bob_eq"
    When I send a decision request for entity chain "bob_eq" for "read" action on resource "https://eq-nomatch.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: Equals condition is case-insensitive — condition "ALICE" matches userName "alice"
    And an ERS mapping strategy "ci_alice_strat" using provider "ldap_directory"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: userName
            operator: equals
            values: ["ALICE"]
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
    Given I submit a request to create a namespace with name "eq-ci.test" and reference id "ns_eq_ci"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_eq_ci     | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_eq_ci" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_eq_ci" containing the condition groups "cg_eq_ci"
    And I send a request to create a subject condition set referenced as "scs_eq_ci" containing subject sets "ss_eq_ci"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                      | condition_set_name | standard actions | custom actions |
      | sm_eq_ci     | https://eq-ci.test/attr/department/value/engineering | scs_eq_ci          | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "alice" and referenced as "alice_ci"
    When I send a decision request for entity chain "alice_ci" for "read" action on resource "https://eq-ci.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response
