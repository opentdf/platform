@multi-strategy-ers-input-mapping-continue @stateless
Feature: Multi-strategy ERS input_mapping required validation (continue)
  When a required input_mapping claim is absent from the JWT and the failure
  strategy is continue, the failing strategy is skipped and the next matching
  strategy resolves the entity. This validates graceful degradation — the
  claims fallback produces a PERMIT that fail-fast would have blocked.

  Background:
    Given an LDAP directory with test users

  Scenario: Continue with missing required input_mapping claim falls through to claims
    Given an ERS configuration with mode "multi-strategy" and failure strategy "continue"
    And an ERS provider "jwt_claims" of type "claims"
    And an ERS provider "ldap_directory" of type "ldap" connected to the LDAP directory
    And an ERS mapping strategy "claims_fallback_cont" using provider "jwt_claims"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: userName
            operator: exists
      output_mapping:
        - source_claim: userName
          claim_name: username
        - source_claim: department
          claim_name: department
      """
    And an ERS mapping strategy "ldap_requires_employee_id_cont" using provider "ldap_directory"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: userName
            operator: exists
      ldap_search:
        base_dn: "ou=users,dc=opentdf,dc=test"
        filter: "(&(objectClass=inetOrgPerson)(uid={employee_id}))"
        scope: subtree
        attributes: ["uid", "mail", "departmentNumber"]
      input_mapping:
        - jwt_claim: employee_id
          parameter: employee_id
          required: true
      output_mapping:
        - source_attribute: departmentNumber
          claim_name: department
        - source_attribute: uid
          claim_name: username
      """
    And a local platform with inline ERS configuration
    Given I submit a request to create a namespace with name "req-continue.test" and reference id "ns_req_cont"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_req_cont  | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_req_cont" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_req_cont" containing the condition groups "cg_req_cont"
    And I send a request to create a subject condition set referenced as "scs_req_cont" containing subject sets "ss_req_cont"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                              | condition_set_name | standard actions | custom actions |
      | sm_req_cont  | https://req-continue.test/attr/department/value/engineering  | scs_req_cont       | read             |                |
    Then the response should be successful
    Given there is a claims subject entity referenced as "user_no_empid_cont" with claims:
      """
      {"userName":"alice","department":"engineering"}
      """
    When I send a decision request for entity chain "user_no_empid_cont" for "read" action on resource "https://req-continue.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response
