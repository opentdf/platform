@multi-strategy-ers-multi-success @stateless
Feature: First successful strategy wins under continue (ADR: first-match-wins)
  Per the multi-strategy ERS ADR, failure_strategy only controls error handling:
    - "continue": try the next strategy if the current one fails, stop at first success
    - "fail_fast": stop immediately on any failure
  In both modes, the first successful strategy returns and no further strategies run.
  See: adr/decisions/2025-07-31-multi-strategy-entity-resolution-service.md

  Both scenarios use two strategies whose conditions match, so the chain must hold
  exactly one entity from "claims_identity". The first asserts the winner's claims
  reach the decision; the second asserts the loser's claims do not.

  This covers Jake's gap analysis row #4.

  Background:
    Given an LDAP directory with test users
    And a user exists with username "alice" and email "alice@opentdf.test" and the following attributes:
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
    # Regression guard: only "claims_identity" emits .username. If resolution kept going
    # after its success, the appended LDAP entity has no .username and AND semantics DENY.
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
    # Alice has departmentNumber=engineering in LDAP, but "claims_identity" wins and emits
    # no .department, so the mapping cannot match. Also catches an implementation that merges
    # both strategies' claims into one entity — that would wrongly PERMIT here.
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
