@multi-strategy-ers-multi-success @stateless
Feature: Multiple successful strategies under continue build multi-entity chain
  Validate that failure_strategy "continue" keeps evaluating strategies after a
  successful match, building a richer entity chain via CreateEntityChainsFromTokens.
  When both claims and LDAP strategies succeed for the same JWT token, the chain
  contains entities from both strategies. Each entity is evaluated independently
  for authorization (AND semantics), so both must be entitled for PERMIT.

  This covers Jake's gap analysis row #4: no existing test verifies the resulting
  multi-entity chain when two strategies both succeed under continue.

  Background:
    Given an LDAP directory with test users
    And a user exists with username "alice" and email "alice@opentdf.test" and the following attributes:
      | name | value |
    And a user exists with username "eve" and email "eve@opentdf.test" and the following attributes:
      | name | value |
    And an ERS configuration with mode "multi-strategy" and failure strategy "continue"
    And an ERS provider "jwt_claims" of type "claims"
    And an ERS provider "ldap_directory" of type "ldap" connected to the LDAP directory
    And an ERS mapping strategy "claims_identity" using provider "jwt_claims"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: preferred_username
            operator: exists
      output_mapping:
        - source_claim: preferred_username
          claim_name: username
      """
    And an ERS mapping strategy "ldap_department" using provider "ldap_directory"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: preferred_username
            operator: exists
      ldap_search:
        base_dn: "ou=users,dc=opentdf,dc=test"
        filter: "(&(objectClass=inetOrgPerson)(uid={username}))"
        scope: subtree
        attributes: ["uid", "departmentNumber"]
      input_mapping:
        - jwt_claim: preferred_username
          parameter: username
      output_mapping:
        - source_attribute: departmentNumber
          claim_name: department
        - source_attribute: uid
          claim_name: username
      """
    And a local platform with inline ERS configuration

  Scenario: Both strategies succeed — multi-entity chain built, both entities entitled → PERMIT
    Given I submit a request to create a namespace with name "multi-success.test" and reference id "ns_ms"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_ms        | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    # Subject mapping uses .username which both claims and LDAP entities output.
    # This ensures both entities in the multi-entity chain are entitled (AND semantics).
    Given a condition group referenced as "cg_ms" with an "or" operator with conditions:
      | selector_value | operator | values |
      | .username      | in       | alice  |
    And a subject set referenced as "ss_ms" containing the condition groups "cg_ms"
    And I send a request to create a subject condition set referenced as "scs_ms" containing subject sets "ss_ms"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                             | condition_set_name | standard actions | custom actions |
      | sm_ms        | https://multi-success.test/attr/department/value/engineering | scs_ms             | read             |                |
    Then the response should be successful
    # Alice's token triggers both strategies under continue:
    #   1. Claims strategy outputs {username: alice}
    #   2. LDAP strategy finds alice → outputs {department: engineering, username: alice}
    # Both entities have username=alice → both match subject mapping → PERMIT
    # This proves continue builds a 2-entity chain (not just the first match).
    Given a user access token for "alice" stored as "alice_token"
    When I send a decision request for token "alice_token" for "read" action on resource "https://multi-success.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Both strategies succeed — one entity not entitled → DENY (AND semantics)
    Given I submit a request to create a namespace with name "multi-success-deny.test" and reference id "ns_msd"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_msd       | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    # Subject mapping requires department=engineering. Claims entity doesn't output
    # department so it fails entitlement. Even though LDAP entity has department=operations,
    # both entities must pass (AND) → DENY.
    Given a condition group referenced as "cg_msd" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_msd" containing the condition groups "cg_msd"
    And I send a request to create a subject condition set referenced as "scs_msd" containing subject sets "ss_msd"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                                  | condition_set_name | standard actions | custom actions |
      | sm_msd       | https://multi-success-deny.test/attr/department/value/engineering | scs_msd            | read             |                |
    Then the response should be successful
    # Eve's token also triggers both strategies:
    #   1. Claims entity: no department → not entitled
    #   2. LDAP entity: department=operations (not engineering) → not entitled
    # Both entities fail → DENY
    Given a user access token for "eve" stored as "eve_token"
    When I send a decision request for token "eve_token" for "read" action on resource "https://multi-success-deny.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "DENY" decision response
