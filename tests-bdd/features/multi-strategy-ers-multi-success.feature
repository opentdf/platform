@multi-strategy-ers-multi-success @stateless
Feature: Multi-strategy chains hold one entity per category under continue
  Per the multi-strategy ERS ADR, failure_strategy only controls error handling:
    - "continue": try the next strategy if the current one fails
    - "fail_fast": stop immediately on any failure
  Neither mode adds a second entity of a category already resolved, so a chain holds at
  most one subject and one environment entity.
  See: adr/decisions/2025-07-31-multi-strategy-entity-resolution-service.md

  All three strategies below match every token, so the chain holds the environment entity
  from "client_environment" plus one subject entity from "claims_identity" — "ldap_department"
  is skipped. Authorization discards environment entities, so only the subject's claims count.

  Background:
    Given an LDAP directory with test users
    And a user exists with username "alice" and email "alice@opentdf.test" and the following attributes:
      | name | value |
    And an ERS configuration with mode "multi-strategy" and failure strategy "continue"
    And an ERS provider "jwt_claims" of type "claims"
    And an ERS provider "ldap_directory" of type "ldap" connected to the LDAP directory
    # Ordered first on purpose: every Keycloak token carries azp, so an environment strategy
    # always wins the race. This makes the scenarios below cover environment-first ordering —
    # resolution that stopped at the first match outright would leave no subject entity and
    # every decision would error instead of deciding.
    And an ERS mapping strategy "client_environment" using provider "jwt_claims"
      """
      entity_type: environment
      conditions:
        jwt_claims:
          - claim: azp
            operator: exists
      output_mapping:
        - source_claim: azp
          claim_name: client_id
      """
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
    # Emits only "department", never "username" — the asymmetry the scenarios rely on.
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
      """
    And a local platform with inline ERS configuration

  Scenario: First strategy succeeds — user entitled via first-match entity → PERMIT
    Given I submit a request to create a namespace with name "multi-success.test" and reference id "ns_ms"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_ms        | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    # Regression guard: stopping at the first match regardless of category would leave only
    # the environment entity (authz filters it away), and appending a second subject entity
    # would add one with no .username for AND semantics to veto.
    Given a condition group referenced as "cg_ms" with an "or" operator with conditions:
      | selector_value | operator | values |
      | .username      | in       | alice  |
    And a subject set referenced as "ss_ms" containing the condition groups "cg_ms"
    And I send a request to create a subject condition set referenced as "scs_ms" containing subject sets "ss_ms"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                             | condition_set_name | standard actions | custom actions |
      | sm_ms        | https://multi-success.test/attr/department/value/engineering | scs_ms             | read             |                |
    Then the response should be successful
    Given a user access token for "alice" stored as "alice_token"
    When I send a decision request for token "alice_token" for "read" action on resource "https://multi-success.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: A later strategy that would supply the attribute never runs → DENY
    # Alice is departmentNumber=engineering in LDAP, but "claims_identity" owns the subject
    # entity and emits no .department. Also catches an implementation that merges claims.
    # Fix in config: order the LDAP strategy first, or emit department from the winner.
    Given I submit a request to create a namespace with name "and-semantics-gap.test" and reference id "ns_asg"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_asg       | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_asg" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_asg" containing the condition groups "cg_asg"
    And I send a request to create a subject condition set referenced as "scs_asg" containing subject sets "ss_asg"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                                  | condition_set_name | standard actions | custom actions |
      | sm_asg       | https://and-semantics-gap.test/attr/department/value/engineering | scs_asg            | read             |                |
    Then the response should be successful
    Given a user access token for "alice" stored as "alice_and_token"
    When I send a decision request for token "alice_and_token" for "read" action on resource "https://and-semantics-gap.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "DENY" decision response
