@authorization @direct-entitlements
Feature: Direct Entitlements Decisioning
  Validate direct entitlement evaluation when allow_direct_entitlements is enabled.

  Background:
    Given a user exists with username "alice" and email "alice@example.com" and the following attributes:
      | name       | value   |
      | department | ["eng"] |
    And a local platform with platform template "cukes/resources/platform.direct_entitlements.template" and keycloak template "cukes/resources/keycloak_base.template"
    And I submit a request to create a namespace with name "example.com" and reference id "ns1"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values |
      | ns1          | department | anyOf | eng,hr |
      | ns1          | project    | allOf | alpha,beta |
    Then the response should be successful

  Scenario: Direct entitlement permits for matching action
    And there is a claims subject entity referenced as "alice" with direct entitlements:
      | attribute_value_fqn                              | actions |
      | https://example.com/attr/department/value/eng    | read    |
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/department/value/eng"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Direct entitlement denies for action mismatch
    And there is a claims subject entity referenced as "alice" with direct entitlements:
      | attribute_value_fqn                              | actions |
      | https://example.com/attr/department/value/eng    | read    |
    When I send a decision request for entity chain "alice" for "update" action on resource "https://example.com/attr/department/value/eng"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: Direct entitlement permits for another value
    And there is a claims subject entity referenced as "alice" with direct entitlements:
      | attribute_value_fqn                                  | actions |
      | https://example.com/attr/department/value/hr         | read    |
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/department/value/hr"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Direct entitlement permits for synthetic value
    And there is a claims subject entity referenced as "alice" with direct entitlements:
      | attribute_value_fqn                                  | actions |
      | https://example.com/attr/department/value/finance    | read    |
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/department/value/finance"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Subject mapping and direct entitlements both apply
    And there is a claims subject entity referenced as "alice" with direct entitlements:
      | attribute_value_fqn                              | actions |
      | https://example.com/attr/project/value/beta      | read    |
    And I add claims to subject entity "alice" with:
      | name       | value                    |
      | attributes | {"project":["alpha"]}    |
    And a condition group referenced as "cg_project_alpha" with an "or" operator with conditions:
      | selector_value        | operator | values |
      | .attributes.project[] | in       | alpha  |
    And a subject set referenced as "ss_project_alpha" containing the condition groups "cg_project_alpha"
    And I send a request to create a subject condition set referenced as "scs_project_alpha" containing subject sets "ss_project_alpha"
    And I send a request to create a subject mapping with:
      | reference_id     | attribute_value                               | condition_set_name  | standard actions | custom actions |
      | sm_project_alpha | https://example.com/attr/project/value/alpha  | scs_project_alpha   | read             |                |
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/project/value/alpha,https://example.com/attr/project/value/beta"
    Then the response should be successful
    And I should get a "PERMIT" decision response
