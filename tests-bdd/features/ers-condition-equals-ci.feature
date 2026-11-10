@ers-condition-equals-ci @stateless
Feature: ERS condition operator — equals case-insensitivity
  Validate that the "equals" condition operator is case-insensitive,
  using strings.EqualFold so that condition value "ALICE" matches
  userName "alice".

  Background:
    Given an LDAP directory with test users
    And an ERS configuration with mode "multi-strategy" and failure strategy "continue"
    And an ERS provider "ldap_directory" of type "ldap" connected to the LDAP directory
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

  Scenario: Equals condition is case-insensitive — condition "ALICE" matches userName "alice"
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
