@authorization @attribute-rules
Feature: Attribute Rule Decisioning
  Validate basic anyOf, allOf, and hierarchy rule behavior in decisioning.

  Background:
    Given a user exists with username "alice" and email "alice@example.com" and the following attributes:
      | name        | value     |
      | department  | ["eng"]   |
      | project     | ["alpha","beta"] |
      | sensitivity | ["high"]  |
    And an empty local platform
    And I submit a request to create a namespace with name "example.com" and reference id "ns1"
    And I send a request to create an attribute with:
      | namespace_id | name        | rule      | values                     |
      | ns1          | department  | anyOf     | eng,hr                     |
      | ns1          | project     | allOf     | alpha,beta                 |
      | ns1          | sensitivity | hierarchy | critical,high,medium,low   |
    Then the response should be successful
    And a condition group referenced as "cg_department_eng" with an "or" operator with conditions:
      | selector_value           | operator | values |
      | .attributes.department[] | in       | eng    |
    And a condition group referenced as "cg_project_alpha" with an "or" operator with conditions:
      | selector_value        | operator | values |
      | .attributes.project[] | in       | alpha  |
    And a condition group referenced as "cg_project_beta" with an "or" operator with conditions:
      | selector_value        | operator | values |
      | .attributes.project[] | in       | beta   |
    And a condition group referenced as "cg_sensitivity_high" with an "or" operator with conditions:
      | selector_value             | operator | values |
      | .attributes.sensitivity[]  | in       | high   |
    And a subject set referenced as "ss_department_eng" containing the condition groups "cg_department_eng"
    And a subject set referenced as "ss_project_alpha" containing the condition groups "cg_project_alpha"
    And a subject set referenced as "ss_project_beta" containing the condition groups "cg_project_beta"
    And a subject set referenced as "ss_sensitivity_high" containing the condition groups "cg_sensitivity_high"
    And I send a request to create a subject condition set referenced as "scs_department_eng" containing subject sets "ss_department_eng"
    And I send a request to create a subject condition set referenced as "scs_project_alpha" containing subject sets "ss_project_alpha"
    And I send a request to create a subject condition set referenced as "scs_project_beta" containing subject sets "ss_project_beta"
    And I send a request to create a subject condition set referenced as "scs_sensitivity_high" containing subject sets "ss_sensitivity_high"
    And there is a "user_name" subject entity with value "alice" and referenced as "alice"

  Scenario: anyOf permits when at least one value is entitled
    And I send a request to create a subject mapping with:
      | reference_id       | attribute_value                                      | condition_set_name    | standard actions | custom actions |
      | sm_department_eng  | https://example.com/attr/department/value/eng        | scs_department_eng    | read             |                |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/department/value/eng,https://example.com/attr/department/value/hr"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: anyOf denies when no values are entitled
    And I send a request to create a subject mapping with:
      | reference_id       | attribute_value                                      | condition_set_name    | standard actions | custom actions |
      | sm_department_eng  | https://example.com/attr/department/value/eng        | scs_department_eng    | read             |                |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/department/value/hr"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: allOf denies when any value lacks entitlement
    And I send a request to create a subject mapping with:
      | reference_id     | attribute_value                                   | condition_set_name | standard actions | custom actions |
      | sm_project_alpha | https://example.com/attr/project/value/alpha      | scs_project_alpha  | read             |                |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/project/value/alpha,https://example.com/attr/project/value/beta"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: allOf permits when all values are entitled
    And I send a request to create a subject mapping with:
      | reference_id      | attribute_value                                  | condition_set_name   | standard actions | custom actions |
      | sm_project_alpha  | https://example.com/attr/project/value/alpha     | scs_project_alpha    | read             |                |
      | sm_project_beta   | https://example.com/attr/project/value/beta      | scs_project_beta     | read             |                |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/project/value/alpha,https://example.com/attr/project/value/beta"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: hierarchy permits when entitled to a higher value
    And I send a request to create a subject mapping with:
      | reference_id          | attribute_value                                      | condition_set_name       | standard actions | custom actions |
      | sm_sensitivity_high   | https://example.com/attr/sensitivity/value/high      | scs_sensitivity_high     | read             |                |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/sensitivity/value/medium"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: hierarchy denies when resource is higher than entitled value
    And I send a request to create a subject mapping with:
      | reference_id          | attribute_value                                      | condition_set_name       | standard actions | custom actions |
      | sm_sensitivity_high   | https://example.com/attr/sensitivity/value/high      | scs_sensitivity_high     | read             |                |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/sensitivity/value/critical"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: multiple attributes must all pass across requests
    And I send a request to create a subject mapping with:
      | reference_id      | attribute_value                               | condition_set_name | standard actions | custom actions |
      | sm_department_eng | https://example.com/attr/department/value/eng | scs_department_eng | read             |                |
      | sm_project_alpha  | https://example.com/attr/project/value/alpha  | scs_project_alpha  | read             |                |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/department/value/eng,https://example.com/attr/project/value/beta"
    Then the response should be successful
    And I should get a "DENY" decision response
    And I send a request to create a subject mapping with:
      | reference_id     | attribute_value                              | condition_set_name | standard actions | custom actions |
      | sm_project_beta  | https://example.com/attr/project/value/beta  | scs_project_beta   | read             |                |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/department/value/eng,https://example.com/attr/project/value/beta"
    Then the response should be successful
    And I should get a "PERMIT" decision response
