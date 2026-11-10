@multi-strategy-ers-failfast @stateless
Feature: Multi-strategy ERS fail-fast behavior
  Validate that failure_strategy "fail-fast" stops entity resolution at the first
  strategy error, preventing fallback to subsequent strategies. This contrasts
  with the "continue" behavior tested in claims-ldap-fallback-ers.feature where
  the same user gets PERMIT because LDAP succeeds after claims fails.

  The claims_passthrough strategy fails for user_name entities because the
  claims provider requires inline claims via JWTClaimsContextKey, which is
  only populated for Entity_Claims entities — not for Entity_UserName. Under
  "fail-fast", this error aborts resolution immediately — LDAP never
  executes — so the entity has no .department claim and gets DENY.

  When an Entity_Claims entity is used, the claims provider succeeds and
  fail-fast does not trigger — proving fail-fast only blocks on actual errors,
  not universally.

  Background:
    Given an LDAP directory with test users
    And an ERS configuration with mode "multi-strategy" and failure strategy "fail-fast"
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
        - source_claim: department
          claim_name: department
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

  Scenario: Fail-fast prevents LDAP fallback — engineering user gets DENY
    Given I submit a request to create a namespace with name "eng-failfast.test" and reference id "ns_eng_ff"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_eng_ff    | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_eng_ff" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_eng_ff" containing the condition groups "cg_eng_ff"
    And I send a request to create a subject condition set referenced as "scs_eng_ff" containing subject sets "ss_eng_ff"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                             | condition_set_name | standard actions | custom actions |
      | sm_eng_ff    | https://eng-failfast.test/attr/department/value/engineering | scs_eng_ff         | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "alice" and referenced as "alice_ff"
    When I send a decision request for entity chain "alice_ff" for "read" action on resource "https://eng-failfast.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: Entity_Claims succeeds under fail-fast — claims provider does not error
    Given I submit a request to create a namespace with name "ff-claims.test" and reference id "ns_ff_claims"
    And I send a request to create an attribute with:
      | namespace_id  | name       | rule  | values                         |
      | ns_ff_claims  | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_ff_claims" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_ff_claims" containing the condition groups "cg_ff_claims"
    And I send a request to create a subject condition set referenced as "scs_ff_claims" containing subject sets "ss_ff_claims"
    And I send a request to create a subject mapping with:
      | reference_id  | attribute_value                                            | condition_set_name | standard actions | custom actions |
      | sm_ff_claims  | https://ff-claims.test/attr/department/value/engineering   | scs_ff_claims      | read             |                |
    Then the response should be successful
    Given there is a claims subject entity referenced as "diana_ff" with claims:
      """
      {"userName":"diana","department":"engineering"}
      """
    When I send a decision request for entity chain "diana_ff" for "read" action on resource "https://ff-claims.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response
