@multi-strategy-ers-multi-success @stateless
Feature: First successful strategy wins under continue (ADR: first-match-wins)
  Per the multi-strategy ERS ADR, failure_strategy only controls error handling:
    - "continue": try the next strategy if the current one fails, stop at first success
    - "fail_fast": stop immediately on any failure
  In both modes, the first successful strategy returns and no further strategies run.
  See: adr/decisions/2025-07-31-multi-strategy-entity-resolution-service.md

  Every scenario below uses failure_strategy "continue" with two strategies whose
  conditions both match, so the chain must always contain exactly one entity —
  the one produced by "claims_identity", which is listed first.

  This covers Jake's gap analysis row #4.

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

  Scenario: First strategy succeeds — user entitled via first-match entity → PERMIT
    Given I submit a request to create a namespace with name "multi-success.test" and reference id "ns_ms"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_ms        | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    # Subject mapping uses .username — the claims strategy (listed first) outputs this.
    # Per ADR, claims succeeds and LDAP should not run. PERMIT from single entity.
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

  Scenario: First strategy succeeds — user not entitled via first-match entity → DENY
    Given I submit a request to create a namespace with name "multi-success-deny.test" and reference id "ns_msd"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_msd       | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    # Subject mapping checks .department — claims strategy (first match) does not
    # output department. Per ADR, claims succeeds and returns, LDAP never runs.
    # Even though LDAP would provide department=operations for eve, it's irrelevant.
    Given a condition group referenced as "cg_msd" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_msd" containing the condition groups "cg_msd"
    And I send a request to create a subject condition set referenced as "scs_msd" containing subject sets "ss_msd"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                                  | condition_set_name | standard actions | custom actions |
      | sm_msd       | https://multi-success-deny.test/attr/department/value/engineering | scs_msd            | read             |                |
    Then the response should be successful
    Given a user access token for "eve" stored as "eve_token"
    When I send a decision request for token "eve_token" for "read" action on resource "https://multi-success-deny.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: A later strategy that would supply the attribute never runs → DENY
    # Regression guard for the bug where "continue" kept resolving after a success and
    # appended a second entity to the chain, which then had to pass entitlement too.
    #
    # Customer intent here is claims for routing and LDAP for department, expressed as
    # two strategies. That intent is NOT supported: "claims_identity" matches first and
    # ends resolution, so the chain holds a single entity with no .department, and the
    # subject mapping on .department cannot match — even though LDAP has
    # department=engineering for alice.
    #
    # To get department into the decision, emit it from the strategy that wins: either
    # put the LDAP strategy first, or narrow the claims strategy's conditions so it does
    # not match this token. Chaining two strategies to merge their claims is an explicit
    # "Future Considerations" item in the ADR, not current behavior.
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
