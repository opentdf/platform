@authorization @multi-resource
Feature: Multi-resource Decisioning (Non-Obligations)
  Validate per-resource decisions and response counts without obligation effects.

  Background:
    Given a user exists with username "alice" and email "alice@example.com" and the following attributes:
      | name       | value   |
      | department | ["eng"] |
      | region     | ["us"]  |
    And an empty local platform
    And I submit a request to create a namespace with name "example.com" and reference id "ns1"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values |
      | ns1          | department | anyOf | eng,hr |
      | ns1          | region     | anyOf | us,eu  |
    Then the response should be successful
    And a condition group referenced as "cg_department_eng" with an "or" operator with conditions:
      | selector_value           | operator | values |
      | .attributes.department[] | in       | eng    |
    And a condition group referenced as "cg_region_us" with an "or" operator with conditions:
      | selector_value        | operator | values |
      | .attributes.region[]  | in       | us     |
    And a subject set referenced as "ss_department_eng" containing the condition groups "cg_department_eng"
    And a subject set referenced as "ss_region_us" containing the condition groups "cg_region_us"
    And I send a request to create a subject condition set referenced as "scs_department_eng" containing subject sets "ss_department_eng"
    And I send a request to create a subject condition set referenced as "scs_region_us" containing subject sets "ss_region_us"
    And I send a request to create a subject mapping with:
      | reference_id       | attribute_value                                  | condition_set_name  | standard actions | custom actions |
      | sm_department_eng  | https://example.com/attr/department/value/eng    | scs_department_eng  | read             |                |
      | sm_region_us       | https://example.com/attr/region/value/us         | scs_region_us       | read             |                |
    Then the response should be successful
    And there is a "user_name" subject entity with value "alice" and referenced as "alice"

  Scenario: All resources permitted
    When I send a multi-resource decision request for entity chain "alice" for "read" action on resources:
      | resource                                        |
      | https://example.com/attr/department/value/eng   |
      | https://example.com/attr/region/value/us        |
    Then the response should be successful
    And I should get 2 decision responses
    And the multi-resource decision should be "PERMIT"
    And the decision response for resource "https://example.com/attr/department/value/eng" should be "PERMIT"
    And the decision response for resource "https://example.com/attr/region/value/us" should be "PERMIT"

  Scenario: Mixed permit and deny across resources
    When I send a multi-resource decision request for entity chain "alice" for "read" action on resources:
      | resource                                        |
      | https://example.com/attr/department/value/eng   |
      | https://example.com/attr/region/value/eu        |
    Then the response should be successful
    And I should get 2 decision responses
    And the multi-resource decision should be "DENY"
    And the decision response for resource "https://example.com/attr/department/value/eng" should be "PERMIT"
    And the decision response for resource "https://example.com/attr/region/value/eu" should be "DENY"

  Scenario: Action mismatch denies only the non-entitled resource
    And I send a request to create a subject mapping with:
      | reference_id               | attribute_value                                  | condition_set_name  | standard actions | custom actions |
      | sm_department_eng_update   | https://example.com/attr/department/value/eng    | scs_department_eng  | update           |                |
    Then the response should be successful
    When I send a multi-resource decision request for entity chain "alice" for "update" action on resources:
      | resource                                        |
      | https://example.com/attr/department/value/eng   |
      | https://example.com/attr/region/value/us        |
    Then the response should be successful
    And I should get 2 decision responses
    And the multi-resource decision should be "DENY"
    And the decision response for resource "https://example.com/attr/department/value/eng" should be "PERMIT"
    And the decision response for resource "https://example.com/attr/region/value/us" should be "DENY"
