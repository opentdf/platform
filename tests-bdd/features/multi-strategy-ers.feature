@multi-strategy-ers @stateless
Feature: Multi-strategy ERS entity resolution (Claims + LDAP)
  Validate that multi-strategy ERS resolves entities from LDAP through the full
  gRPC stack (SDK -> Connect RPC -> platform -> ERS -> LDAP). This catches
  serialization bugs at the gRPC/structpb boundary that direct-call integration
  tests miss.

  Background:
    Given an LDAP directory with test users
    And an ERS configuration with mode "multi-strategy" and failure strategy "continue"
    And an ERS provider "jwt_claims" of type "claims"
    And an ERS provider "ldap_directory" of type "ldap" connected to the LDAP directory
    And an ERS mapping strategy "claims_passthrough" using provider "jwt_claims"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: userName
            operator: exists
      output_mapping:
        - source_claim: userName
          claim_name: username
      """
    And an ERS mapping strategy "ldap_by_username" using provider "ldap_directory"
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

  Scenario: LDAP-resolved engineering user gets PERMIT
    Given I submit a request to create a namespace with name "eng-permit.test" and reference id "ns_eng_permit"
    And I send a request to create an attribute with:
      | namespace_id   | name       | rule  | values                          |
      | ns_eng_permit  | department | anyOf | engineering,marketing,security  |
    Then the response should be successful
    Given a condition group referenced as "cg_eng" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_eng" containing the condition groups "cg_eng"
    And I send a request to create a subject condition set referenced as "scs_eng" containing subject sets "ss_eng"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                           | condition_set_name | standard actions | custom actions |
      | sm_eng       | https://eng-permit.test/attr/department/value/engineering | scs_eng            | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "alice" and referenced as "alice"
    When I send a decision request for entity chain "alice" for "read" action on resource "https://eng-permit.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: LDAP-resolved marketing user gets DENY for engineering resource
    Given I submit a request to create a namespace with name "eng-deny.test" and reference id "ns_eng_deny"
    And I send a request to create an attribute with:
      | namespace_id  | name       | rule  | values                          |
      | ns_eng_deny   | department | anyOf | engineering,marketing,security  |
    Then the response should be successful
    Given a condition group referenced as "cg_eng2" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_eng2" containing the condition groups "cg_eng2"
    And I send a request to create a subject condition set referenced as "scs_eng2" containing subject sets "ss_eng2"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                          | condition_set_name | standard actions | custom actions |
      | sm_eng2      | https://eng-deny.test/attr/department/value/engineering  | scs_eng2           | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "bob" and referenced as "bob"
    When I send a decision request for entity chain "bob" for "read" action on resource "https://eng-deny.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: LDAP-resolved security user gets PERMIT for security resource
    Given I submit a request to create a namespace with name "sec-permit.test" and reference id "ns_sec_permit"
    And I send a request to create an attribute with:
      | namespace_id    | name       | rule  | values                          |
      | ns_sec_permit   | department | anyOf | engineering,marketing,security  |
    Then the response should be successful
    Given a condition group referenced as "cg_sec" with an "or" operator with conditions:
      | selector_value | operator | values   |
      | .department    | in       | security |
    And a subject set referenced as "ss_sec" containing the condition groups "cg_sec"
    And I send a request to create a subject condition set referenced as "scs_sec" containing subject sets "ss_sec"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                            | condition_set_name | standard actions | custom actions |
      | sm_sec       | https://sec-permit.test/attr/department/value/security     | scs_sec            | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "charlie" and referenced as "charlie"
    When I send a decision request for entity chain "charlie" for "read" action on resource "https://sec-permit.test/attr/department/value/security"
    Then the response should be successful
    And I should get a "PERMIT" decision response
