@authorization @registered-resources
Feature: Registered Resource Decisioning
  Validate registered resource value decisioning without strict namespaced policy.

  Background:
    Given a user exists with username "alice" and email "alice@example.com" and the following attributes:
      | name       | value   |
      | department | ["eng"] |
    And a user exists with username "bob" and email "bob@example.com" and the following attributes:
      | name       | value   |
      | department | ["hr"]  |
    And an empty local platform
    And I submit a request to create a namespace with name "example.com" and reference id "ns1"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values |
      | ns1          | department | anyOf | eng,hr |
    Then the response should be successful
    And a condition group referenced as "cg_department_eng" with an "or" operator with conditions:
      | selector_value           | operator | values |
      | .attributes.department[] | in       | eng    |
    And a subject set referenced as "ss_department_eng" containing the condition groups "cg_department_eng"
    And I send a request to create a subject condition set referenced as "scs_department_eng" containing subject sets "ss_department_eng"
    And I send a request to create a subject mapping with:
      | reference_id      | attribute_value                                  | condition_set_name  | standard actions | custom actions |
      | sm_department_eng | https://example.com/attr/department/value/eng    | scs_department_eng  | read             |                |
    Then the response should be successful
    And I send a request to create a registered resource with:
      | reference_id | namespace_id | name       |
      | rr_entity    | ns1          | service-a  |
      | rr_target    | ns1          | service-b  |
    Then the response should be successful
    And I send a request to create a registered resource with:
      | reference_id | name            |
      | rr_legacy    | legacy-service  |
    Then the response should be successful
    And I send a request to create a registered resource value with:
      | reference_id         | resource_ref | value       | action_attribute_values                                      |
      | rrv_entity           | rr_entity    | primary-eng | read=>https://example.com/attr/department/value/eng         |
      | rrv_target_prod      | rr_target    | prod-eng    | read=>https://example.com/attr/department/value/eng         |
      | rrv_target_staging   | rr_target    | staging-hr  | read=>https://example.com/attr/department/value/hr          |
      | rrv_legacy           | rr_legacy    | legacy-eng  | read=>https://example.com/attr/department/value/eng         |
    Then the response should be successful
    And there is a "user_name" subject entity with value "alice" and referenced as "alice"

  Scenario: Registered resource value as resource permits for entitled user
    When I send a decision request for entity chain "alice" for "read" action on registered resource value "rrv_target_prod"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Registered resource value as resource denies for non-entitled user
    And there is a "user_name" subject entity with value "bob" and referenced as "bob"
    When I send a decision request for entity chain "bob" for "read" action on registered resource value "rrv_target_prod"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: Registered resource value as resource permits using legacy FQN
    When I send a decision request for entity chain "alice" for "read" action on registered resource value "https://reg_res/legacy-service/value/legacy-eng"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Registered resource value as resource denies when AAV is not entitled
    When I send a decision request for entity chain "alice" for "read" action on registered resource value "rrv_target_staging"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: Registered resource value as entity permits and denies across requests
    When I send a decision request for registered resource value entity "rrv_entity" for "read" action on resource "https://example.com/attr/department/value/eng"
    Then the response should be successful
    And I should get a "PERMIT" decision response
    When I send a decision request for registered resource value entity "rrv_entity" for "read" action on resource "https://example.com/attr/department/value/hr"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: Registered resource value as entity and resource permits
    When I send a decision request for registered resource value entity "rrv_entity" for "read" action on registered resource value "rrv_target_prod"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Registered resource value as entity and resource denies when resource AAV is not entitled
    When I send a decision request for registered resource value entity "rrv_entity" for "read" action on registered resource value "rrv_target_staging"
    Then the response should be successful
    And I should get a "DENY" decision response
