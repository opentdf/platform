@ers-condition-equals-multi @stateless
Feature: ERS condition operator — equals with multi-value OR
  Validate that the "equals" operator matches if the claim value equals
  ANY of the values in the values[] array (OR-within-condition semantics).

  Background:
    Given an LDAP directory with test users
    And an ERS configuration with mode "multi-strategy" and failure strategy "continue"
    And an ERS provider "ldap_directory" of type "ldap" connected to the LDAP directory
    And an ERS mapping strategy "multi_value_strat" using provider "ldap_directory"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: userName
            operator: equals
            values: ["alice", "diana"]
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

  Scenario: First value in list matches — alice equals one of ["alice", "diana"] gets PERMIT
    Given I submit a request to create a namespace with name "mv-first.test" and reference id "ns_mv_first"
    And I send a request to create an attribute with:
      | namespace_id  | name       | rule  | values                         |
      | ns_mv_first   | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_mv_first" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_mv_first" containing the condition groups "cg_mv_first"
    And I send a request to create a subject condition set referenced as "scs_mv_first" containing subject sets "ss_mv_first"
    And I send a request to create a subject mapping with:
      | reference_id  | attribute_value                                          | condition_set_name | standard actions | custom actions |
      | sm_mv_first   | https://mv-first.test/attr/department/value/engineering  | scs_mv_first       | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "alice" and referenced as "alice_mv"
    When I send a decision request for entity chain "alice_mv" for "read" action on resource "https://mv-first.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Second value in list matches — diana equals one of ["alice", "diana"] gets PERMIT
    Given I submit a request to create a namespace with name "mv-second.test" and reference id "ns_mv_second"
    And I send a request to create an attribute with:
      | namespace_id   | name       | rule  | values                         |
      | ns_mv_second   | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_mv_second" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_mv_second" containing the condition groups "cg_mv_second"
    And I send a request to create a subject condition set referenced as "scs_mv_second" containing subject sets "ss_mv_second"
    And I send a request to create a subject mapping with:
      | reference_id   | attribute_value                                           | condition_set_name | standard actions | custom actions |
      | sm_mv_second   | https://mv-second.test/attr/department/value/engineering  | scs_mv_second      | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "diana" and referenced as "diana_mv"
    When I send a decision request for entity chain "diana_mv" for "read" action on resource "https://mv-second.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: No value in list matches — bob not in ["alice", "diana"] gets DENY
    Given I submit a request to create a namespace with name "mv-none.test" and reference id "ns_mv_none"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_mv_none   | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_mv_none" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_mv_none" containing the condition groups "cg_mv_none"
    And I send a request to create a subject condition set referenced as "scs_mv_none" containing subject sets "ss_mv_none"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                         | condition_set_name | standard actions | custom actions |
      | sm_mv_none   | https://mv-none.test/attr/department/value/engineering  | scs_mv_none        | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "bob" and referenced as "bob_mv"
    When I send a decision request for entity chain "bob_mv" for "read" action on resource "https://mv-none.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "DENY" decision response
