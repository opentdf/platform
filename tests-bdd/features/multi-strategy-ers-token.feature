@multi-strategy-ers-token @stateless
Feature: Multi-strategy ERS token decision flow
  Validate that a token-based decision request uses the multi-strategy ERS chain as
  the resolved authorization context, without requiring a second ERS rehydration pass.

  Background:
    Given a user exists with username "alice" and email "alice@opentdf.test" and the following attributes:
      | name       | value           |
      | department | ["engineering"] |
    And a user exists with username "bob" and email "bob@opentdf.test" and the following attributes:
      | name       | value         |
      | department | ["marketing"] |
    And an LDAP directory with test users
    And an ERS configuration with mode "multi-strategy" and failure strategy "continue"
    And an ERS provider "ldap_directory" of type "ldap" connected to the LDAP directory
    And an ERS mapping strategy "ldap_by_username" using provider "ldap_directory"
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
        attributes: ["uid", "mail", "departmentNumber"]
      input_mapping:
        - jwt_claim: preferred_username
          parameter: username
      output_mapping:
        - source_attribute: departmentNumber
          claim_name: department
        - source_attribute: mail
          claim_name: email
        - source_attribute: uid
          claim_name: username
      """
    And a local platform with inline ERS configuration

  Scenario: Token for engineering user gets PERMIT for engineering resource
    Given I submit a request to create a namespace with name "token-eng-permit.test" and reference id "ns_token_eng_permit"
    And I send a request to create an attribute with:
      | namespace_id          | name       | rule  | values                         |
      | ns_token_eng_permit   | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_token_eng" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_token_eng" containing the condition groups "cg_token_eng"
    And I send a request to create a subject condition set referenced as "scs_token_eng" containing subject sets "ss_token_eng"
    And I send a request to create a subject mapping with:
      | reference_id   | attribute_value                                                    | condition_set_name | standard actions | custom actions |
      | sm_token_eng   | https://token-eng-permit.test/attr/department/value/engineering    | scs_token_eng      | read             |                |
    Then the response should be successful
    Given a user access token for "alice" stored as "alice_access_token"
    When I send a decision request for token "alice_access_token" for "read" action on resource "https://token-eng-permit.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Token for marketing user gets DENY for engineering resource
    Given I submit a request to create a namespace with name "token-eng-deny.test" and reference id "ns_token_eng_deny"
    And I send a request to create an attribute with:
      | namespace_id         | name       | rule  | values                         |
      | ns_token_eng_deny    | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_token_eng2" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_token_eng2" containing the condition groups "cg_token_eng2"
    And I send a request to create a subject condition set referenced as "scs_token_eng2" containing subject sets "ss_token_eng2"
    And I send a request to create a subject mapping with:
      | reference_id    | attribute_value                                                   | condition_set_name | standard actions | custom actions |
      | sm_token_eng2   | https://token-eng-deny.test/attr/department/value/engineering    | scs_token_eng2     | read             |                |
    Then the response should be successful
    Given a user access token for "bob" stored as "bob_access_token"
    When I send a decision request for token "bob_access_token" for "read" action on resource "https://token-eng-deny.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "DENY" decision response
