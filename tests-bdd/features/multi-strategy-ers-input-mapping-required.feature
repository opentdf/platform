@multi-strategy-ers-input-mapping-required @stateless
Feature: Multi-strategy ERS input_mapping required validation (fail-fast)
  When a required input_mapping claim is absent from the JWT and the failure
  strategy is fail-fast, entity resolution fails immediately and the decision
  is DENY — even when a later claims strategy would have matched.

  Background:
    Given an LDAP directory with test users

  Scenario: Fail-fast with missing required input_mapping claim causes DENY
    Given an ERS configuration with mode "multi-strategy" and failure strategy "fail-fast"
    And an ERS provider "ldap_directory" of type "ldap" connected to the LDAP directory
    And an ERS provider "jwt_claims" of type "claims"
    And an ERS mapping strategy "ldap_requires_employee_id" using provider "ldap_directory"
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
    And an ERS mapping strategy "claims_fallback" using provider "jwt_claims"
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
    And a local platform with inline ERS configuration
    Given I submit a request to create a namespace with name "req-failfast.test" and reference id "ns_req_ff"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_req_ff    | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_req_ff" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_req_ff" containing the condition groups "cg_req_ff"
    And I send a request to create a subject condition set referenced as "scs_req_ff" containing subject sets "ss_req_ff"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                             | condition_set_name | standard actions | custom actions |
      | sm_req_ff    | https://req-failfast.test/attr/department/value/engineering | scs_req_ff         | read             |                |
    Then the response should be successful
    Given there is a claims subject entity referenced as "user_no_empid" with claims:
      """
      {"userName":"alice","department":"engineering"}
      """
    When I send a decision request for entity chain "user_no_empid" for "read" action on resource "https://req-failfast.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "DENY" decision response
