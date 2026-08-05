@claims-ldap-fallback-ers @stateless
Feature: Claims-to-LDAP fallback via condition-based strategy routing
  Validate that condition-based strategy selection correctly routes entity
  resolution: a claims strategy with condition "department exists" is skipped
  when the entity lacks a department claim, and the LDAP strategy with
  condition "userName exists" matches and provides the department from LDAP.

  This demonstrates the fallback pattern where claims serve as a fast path
  (when claims already contain the needed attributes) and LDAP acts as the
  fallback (when claims are incomplete).

  Background:
    Given an LDAP directory with test users
    And an ERS configuration with mode "multi-strategy" and failure strategy "continue"
    And an ERS provider "jwt_claims" of type "claims"
    And an ERS provider "ldap_directory" of type "ldap" connected to the LDAP directory
    And an ERS mapping strategy "claims_with_department" using provider "jwt_claims"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: department
            operator: exists
      output_mapping:
        - source_claim: department
          claim_name: department
        - source_claim: userName
          claim_name: username
      """
    And an ERS mapping strategy "ldap_department_lookup" using provider "ldap_directory"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: userName
            operator: exists
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
        - source_attribute: mail
          claim_name: email
        - source_attribute: uid
          claim_name: username
      """
    And a local platform with inline ERS configuration

  Scenario: Entity without department claim falls back to LDAP — engineering user gets PERMIT
    Given I submit a request to create a namespace with name "fallback.test" and reference id "ns_fb"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_fb        | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_fb" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_fb" containing the condition groups "cg_fb"
    And I send a request to create a subject condition set referenced as "scs_fb" containing subject sets "ss_fb"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                         | condition_set_name | standard actions | custom actions |
      | sm_fb        | https://fallback.test/attr/department/value/engineering | scs_fb             | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "diana" and referenced as "diana_fb"
    When I send a decision request for entity chain "diana_fb" for "read" action on resource "https://fallback.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Entity without department claim falls back to LDAP — operations user gets DENY
    Given I submit a request to create a namespace with name "fallback-deny.test" and reference id "ns_fb_deny"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_fb_deny   | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_fb_deny" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_fb_deny" containing the condition groups "cg_fb_deny"
    And I send a request to create a subject condition set referenced as "scs_fb_deny" containing subject sets "ss_fb_deny"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                              | condition_set_name | standard actions | custom actions |
      | sm_fb_deny   | https://fallback-deny.test/attr/department/value/engineering | scs_fb_deny        | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "eve" and referenced as "eve_fb"
    When I send a decision request for entity chain "eve_fb" for "read" action on resource "https://fallback-deny.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "DENY" decision response
