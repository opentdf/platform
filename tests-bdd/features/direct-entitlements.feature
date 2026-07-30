@direct-entitlements
Feature: Direct entitlements decisioning
  Validates direct entitlement evaluation through the AuthorizationV2 PDP (the
  same decision path KAS rewrap invokes). A direct entitlement is carried on the
  entity representation by the claims ERS and grants a subject an action on an
  attribute value without a subject mapping. Requires allow_direct_entitlements.

  Background:
    Given a local platform with platform template "cukes/resources/platform.direct_entitlements.template" and keycloak template "cukes/resources/keycloak_base.template"
    And I submit a request to create a namespace with name "example.com" and reference id "ns1"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values     |
      | ns1          | department | anyOf | eng,hr     |
      | ns1          | project    | allOf | alpha,beta |
    Then the response should be successful

  Scenario: Direct entitlement permits a matching action
    Given there is a claims subject entity referenced as "alice" with direct entitlements:
      | attribute_value_fqn                           | actions |
      | https://example.com/attr/department/value/eng | read    |
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/department/value/eng"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Direct entitlement denies an action mismatch
    Given there is a claims subject entity referenced as "alice" with direct entitlements:
      | attribute_value_fqn                           | actions |
      | https://example.com/attr/department/value/eng | read    |
    When I send a decision request for entity chain "alice" for "update" action on resource "https://example.com/attr/department/value/eng"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: Direct entitlement denies when the entitled value differs
    Given there is a claims subject entity referenced as "alice" with direct entitlements:
      | attribute_value_fqn                           | actions |
      | https://example.com/attr/department/value/eng | read    |
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/department/value/hr"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: Direct entitlement permits a synthetic value not pre-provisioned in policy
    Given there is a claims subject entity referenced as "alice" with direct entitlements:
      | attribute_value_fqn                               | actions |
      | https://example.com/attr/department/value/finance | read    |
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/department/value/finance"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Subject mapping and direct entitlement together satisfy an ALL_OF resource
    Given there is a claims subject entity referenced as "alice" with direct entitlements:
      | attribute_value_fqn                            | actions |
      | https://example.com/attr/project/value/beta    | read    |
    And I add claims to subject entity "alice" with:
      | name       | value                 |
      | attributes | {"project":["alpha"]} |
    And a condition group referenced as "cg_project_alpha" with an "or" operator with conditions:
      | selector_value        | operator | values |
      | .attributes.project[] | in       | alpha  |
    And a subject set referenced as "ss_project_alpha" containing the condition groups "cg_project_alpha"
    And I send a request to create a subject condition set referenced as "scs_project_alpha" containing subject sets "ss_project_alpha"
    And I send a request to create a subject mapping with:
      | reference_id     | attribute_value                              | condition_set_name | standard actions | custom actions |
      | sm_project_alpha | https://example.com/attr/project/value/alpha | scs_project_alpha  | read             |                |
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/project/value/alpha,https://example.com/attr/project/value/beta"
    Then the response should be successful
    And I should get a "PERMIT" decision response
