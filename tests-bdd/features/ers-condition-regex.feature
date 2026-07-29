@ers-condition-regex @stateless
Feature: ERS condition operator — regex
  Validate that the "regex" condition operator performs pattern matching
  on JWT claims to select the correct mapping strategy.

  The regex operator uses regexp.MatchString to test whether the claim
  value matches any pattern in condition.Values[]. Patterns use Go RE2 syntax.

  Background:
    Given an LDAP directory with test users
    And an ERS configuration with mode "multi-strategy" and failure strategy "continue"
    And an ERS provider "ldap_directory" of type "ldap" connected to the LDAP directory

  Scenario: Regex condition matches — userName matching "^[a-d].*" selects strategy for alice
    And an ERS mapping strategy "regex_ad_strat" using provider "ldap_directory"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: userName
            operator: regex
            values: ["^[a-d].*"]
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
        - source_attribute: uid
          claim_name: username
      """
    And a local platform with inline ERS configuration
    Given I submit a request to create a namespace with name "rx-match.test" and reference id "ns_rx_match"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_rx_match  | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_rx_match" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_rx_match" containing the condition groups "cg_rx_match"
    And I send a request to create a subject condition set referenced as "scs_rx_match" containing subject sets "ss_rx_match"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                         | condition_set_name | standard actions | custom actions |
      | sm_rx_match  | https://rx-match.test/attr/department/value/engineering | scs_rx_match       | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "alice" and referenced as "alice_rx"
    When I send a decision request for entity chain "alice_rx" for "read" action on resource "https://rx-match.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Regex condition does not match — "henry" does not match "^[a-d].*" gets DENY
    And an ERS mapping strategy "regex_ad_strat2" using provider "ldap_directory"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: userName
            operator: regex
            values: ["^[a-d].*"]
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
        - source_attribute: uid
          claim_name: username
      """
    And a local platform with inline ERS configuration
    Given I submit a request to create a namespace with name "rx-nomatch.test" and reference id "ns_rx_nomatch"
    And I send a request to create an attribute with:
      | namespace_id   | name       | rule  | values                         |
      | ns_rx_nomatch  | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_rx_nomatch" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_rx_nomatch" containing the condition groups "cg_rx_nomatch"
    And I send a request to create a subject condition set referenced as "scs_rx_nomatch" containing subject sets "ss_rx_nomatch"
    And I send a request to create a subject mapping with:
      | reference_id   | attribute_value                                            | condition_set_name | standard actions | custom actions |
      | sm_rx_nomatch  | https://rx-nomatch.test/attr/department/value/engineering  | scs_rx_nomatch     | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "henry" and referenced as "henry_rx"
    When I send a decision request for entity chain "henry_rx" for "read" action on resource "https://rx-nomatch.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: Multiple conditions with regex and exists (AND logic) — both must match
    And an ERS mapping strategy "regex_and_strat" using provider "ldap_directory"
      """
      entity_type: subject
      conditions:
        jwt_claims:
          - claim: userName
            operator: regex
            values: ["^(alice|diana)$"]
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
        - source_attribute: uid
          claim_name: username
      """
    And a local platform with inline ERS configuration
    Given I submit a request to create a namespace with name "rx-and.test" and reference id "ns_rx_and"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                         |
      | ns_rx_and    | department | anyOf | engineering,marketing,security |
    Then the response should be successful
    Given a condition group referenced as "cg_rx_and" with an "or" operator with conditions:
      | selector_value | operator | values      |
      | .department    | in       | engineering |
    And a subject set referenced as "ss_rx_and" containing the condition groups "cg_rx_and"
    And I send a request to create a subject condition set referenced as "scs_rx_and" containing subject sets "ss_rx_and"
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                                       | condition_set_name | standard actions | custom actions |
      | sm_rx_and    | https://rx-and.test/attr/department/value/engineering | scs_rx_and         | read             |                |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "alice" and referenced as "alice_rx_and"
    When I send a decision request for entity chain "alice_rx_and" for "read" action on resource "https://rx-and.test/attr/department/value/engineering"
    Then the response should be successful
    And I should get a "PERMIT" decision response
