@authorization @namespaced-decisioning
Feature: Namespaced Policy Decisioning (name-only action requests)
  Validate strict namespaced decisioning behavior for action-name requests
  using both standard and custom actions.

  Background:
    Given a user exists with username "alice" and email "alice@example.com" and the following attributes:
      | name       | value     |
      | department | ["eng"] |
    And a local platform with platform template "cukes/resources/platform.namespaced_policy.template" and keycloak template "cukes/resources/keycloak_base.template"
    And I submit a request to create a namespace with name "ns-one.example.com" and reference id "ns1"
    And I submit a request to create a namespace with name "ns-two.example.com" and reference id "ns2"
    And I send a request to create an attribute with:
      | namespace_id | name           | rule      | values    |
      | ns1          | department     | anyOf     | eng       |
      | ns2          | department     | anyOf     | eng       |
    Then the response should be successful
    And a condition group referenced as "cg_eng_department" with an "or" operator with conditions:
      | selector_value           | operator | values |
      | .attributes.department[] | in       | eng    |
    And a subject set referenced as "ss_eng_department" containing the condition groups "cg_eng_department"
    And I send a request to create a subject condition set referenced as "scs_department_eng_ns1" in namespace "ns1" containing subject sets "ss_eng_department"
    And I send a request to create a subject condition set referenced as "scs_department_eng_ns2" in namespace "ns2" containing subject sets "ss_eng_department"
    And there is a "user_name" subject entity with value "alice" and referenced as "alice"

  Scenario: Standard action name permits when entitled in resource namespace
    And I send a request to create a subject mapping with:
      | reference_id   | namespace_id | attribute_value                                                | condition_set_name          | standard actions | custom actions |
      | sm_ns1_read_eng | ns1         | https://ns-one.example.com/attr/department/value/eng           | scs_department_eng_ns1      | read             |                |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "read" action on resource "https://ns-one.example.com/attr/department/value/eng"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Standard action name denies when subject mapping is unnamespaced
    And I send a request to create a subject condition set referenced as "scs_department_eng_unns" containing subject sets "ss_eng_department"
    And I send a request to create a subject mapping with:
      | reference_id        | attribute_value                                                | condition_set_name          | standard actions | custom actions |
      | sm_unns_read_eng    | https://ns-one.example.com/attr/department/value/eng           | scs_department_eng_unns     | read             |                |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "read" action on resource "https://ns-one.example.com/attr/department/value/eng"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: Standard action name denies when entitled only in different namespace
    And I send a request to create a subject mapping with:
      | reference_id   | namespace_id | attribute_value                                                | condition_set_name          | standard actions | custom actions |
      | sm_ns2_read_eng | ns2         | https://ns-two.example.com/attr/department/value/eng           | scs_department_eng_ns2      | read             |                |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "read" action on resource "https://ns-one.example.com/attr/department/value/eng"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: Custom action name permits when entitled in resource namespace
    And I send a request to create a subject mapping with:
      | reference_id     | namespace_id | attribute_value                                                | condition_set_name          | standard actions | custom actions |
      | sm_ns1_export_eng | ns1         | https://ns-one.example.com/attr/department/value/eng           | scs_department_eng_ns1      |                  | export         |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "custom_action_export" action on resource "https://ns-one.example.com/attr/department/value/eng"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Custom action name denies when subject mapping is unnamespaced
    And I send a request to create a subject condition set referenced as "scs_department_eng_unns" containing subject sets "ss_eng_department"
    And I send a request to create a subject mapping with:
      | reference_id          | attribute_value                                                | condition_set_name          | standard actions | custom actions |
      | sm_unns_export_eng    | https://ns-one.example.com/attr/department/value/eng           | scs_department_eng_unns     |                  | export         |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "custom_action_export" action on resource "https://ns-one.example.com/attr/department/value/eng"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: Custom action name denies when entitled only in different namespace
    And I send a request to create a subject mapping with:
      | reference_id     | namespace_id | attribute_value                                                | condition_set_name          | standard actions | custom actions |
      | sm_ns2_export_eng | ns2         | https://ns-two.example.com/attr/department/value/eng           | scs_department_eng_ns2      |                  | export         |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "custom_action_export" action on resource "https://ns-one.example.com/attr/department/value/eng"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: Standard action AND behavior across mixed namespaces
    And I send a request to create a subject mapping with:
      | reference_id   | namespace_id | attribute_value                                                | condition_set_name          | standard actions | custom actions |
      | sm_ns1_read_eng | ns1         | https://ns-one.example.com/attr/department/value/eng           | scs_department_eng_ns1      | read             |                |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "read" action on resource "https://ns-one.example.com/attr/department/value/eng,https://ns-two.example.com/attr/department/value/eng"
    Then the response should be successful
    And I should get a "DENY" decision response
    And I send a request to create a subject mapping with:
      | reference_id    | namespace_id | attribute_value                                                | condition_set_name          | standard actions | custom actions |
      | sm_ns2_read_eng_2 | ns2        | https://ns-two.example.com/attr/department/value/eng           | scs_department_eng_ns2      | read             |                |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "read" action on resource "https://ns-one.example.com/attr/department/value/eng,https://ns-two.example.com/attr/department/value/eng"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Custom action AND behavior across mixed namespaces
    And I send a request to create a subject mapping with:
      | reference_id     | namespace_id | attribute_value                                                | condition_set_name          | standard actions | custom actions |
      | sm_ns1_export_eng | ns1         | https://ns-one.example.com/attr/department/value/eng           | scs_department_eng_ns1      |                  | export         |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "custom_action_export" action on resource "https://ns-one.example.com/attr/department/value/eng,https://ns-two.example.com/attr/department/value/eng"
    Then the response should be successful
    And I should get a "DENY" decision response
    And I send a request to create a subject mapping with:
      | reference_id       | namespace_id | attribute_value                                                | condition_set_name          | standard actions | custom actions |
      | sm_ns2_export_eng_2 | ns2         | https://ns-two.example.com/attr/department/value/eng           | scs_department_eng_ns2      |                  | export         |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "custom_action_export" action on resource "https://ns-one.example.com/attr/department/value/eng,https://ns-two.example.com/attr/department/value/eng"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Registered resource value permits when action is entitled in same namespace
    And I send a request to create a subject mapping with:
      | reference_id    | namespace_id | attribute_value                                      | condition_set_name       | standard actions | custom actions |
      | sm_rr_ns1_read  | ns1          | https://ns-one.example.com/attr/department/value/eng | scs_department_eng_ns1   | read             |                |
    Then the response should be successful
    And I send a request to create a registered resource with:
      | reference_id | namespace_id | name          |
      | rr_ns1       | ns1          | app-config    |
    Then the response should be successful
    And I send a request to create a registered resource value with:
      | reference_id | resource_ref | value       | action_attribute_values                                      |
      | rrv_ns1      | rr_ns1       | prod-config | read=>https://ns-one.example.com/attr/department/value/eng |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "read" action on registered resource value "rrv_ns1"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Registered resource value denies when action is only entitled in different namespace
    And I send a request to create a subject mapping with:
      | reference_id    | namespace_id | attribute_value                                      | condition_set_name       | standard actions | custom actions |
      | sm_rr_ns2_read  | ns2          | https://ns-two.example.com/attr/department/value/eng | scs_department_eng_ns2   | read             |                |
    Then the response should be successful
    And I send a request to create a registered resource with:
      | reference_id | namespace_id | name          |
      | rr_ns1       | ns1          | app-config    |
    Then the response should be successful
    And I send a request to create a registered resource value with:
      | reference_id | resource_ref | value       | action_attribute_values                                      |
      | rrv_ns1      | rr_ns1       | prod-config | read=>https://ns-one.example.com/attr/department/value/eng |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "read" action on registered resource value "rrv_ns1"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: Registered resource value permits for custom action in same namespace
    And I send a request to create a subject mapping with:
      | reference_id      | namespace_id | attribute_value                                      | condition_set_name       | standard actions | custom actions |
      | sm_rr_ns1_export  | ns1          | https://ns-one.example.com/attr/department/value/eng | scs_department_eng_ns1   |                  | export         |
    Then the response should be successful
    And I send a request to create a registered resource with:
      | reference_id | namespace_id | name          |
      | rr_ns1       | ns1          | app-config    |
    Then the response should be successful
    And I send a request to create a registered resource value with:
      | reference_id | resource_ref | value       | action_attribute_values                                                       |
      | rrv_ns1      | rr_ns1       | prod-config | custom_action_export=>https://ns-one.example.com/attr/department/value/eng |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "custom_action_export" action on registered resource value "rrv_ns1"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Registered resource value denies for custom action entitled only in different namespace
    And I send a request to create a subject mapping with:
      | reference_id      | namespace_id | attribute_value                                      | condition_set_name       | standard actions | custom actions |
      | sm_rr_ns2_export  | ns2          | https://ns-two.example.com/attr/department/value/eng | scs_department_eng_ns2   |                  | export         |
    Then the response should be successful
    And I send a request to create a registered resource with:
      | reference_id | namespace_id | name          |
      | rr_ns1       | ns1          | app-config    |
    Then the response should be successful
    And I send a request to create a registered resource value with:
      | reference_id | resource_ref | value       | action_attribute_values                                                       |
      | rrv_ns1      | rr_ns1       | prod-config | custom_action_export=>https://ns-one.example.com/attr/department/value/eng |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "custom_action_export" action on registered resource value "rrv_ns1"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: Registered resources mixed-namespace decision is fail-closed (AND)
    And I send a request to create a subject mapping with:
      | reference_id        | namespace_id | attribute_value                                      | condition_set_name       | standard actions | custom actions |
      | sm_rr_mix_ns1_read  | ns1          | https://ns-one.example.com/attr/department/value/eng | scs_department_eng_ns1   | read             |                |
    Then the response should be successful
    And I send a request to create a registered resource with:
      | reference_id | namespace_id | name           |
      | rr_mix_ns1   | ns1          | app-config-a   |
      | rr_mix_ns2   | ns2          | app-config-b   |
    Then the response should be successful
    And I send a request to create a registered resource value with:
      | reference_id | resource_ref | value         | action_attribute_values                                      |
      | rrv_mix_ns1  | rr_mix_ns1   | prod-config-a | read=>https://ns-one.example.com/attr/department/value/eng |
      | rrv_mix_ns2  | rr_mix_ns2   | prod-config-b | read=>https://ns-two.example.com/attr/department/value/eng |
    Then the response should be successful
    When I send a multi-resource decision request for entity chain "alice" for "read" action on registered resource values "rrv_mix_ns1,rrv_mix_ns2"
    Then the response should be successful
    And the multi-resource decision should be "DENY"
    And I send a request to create a subject mapping with:
      | reference_id         | namespace_id | attribute_value                                      | condition_set_name       | standard actions | custom actions |
      | sm_rr_mix_ns2_read   | ns2          | https://ns-two.example.com/attr/department/value/eng | scs_department_eng_ns2   | read             |                |
    Then the response should be successful
    When I send a multi-resource decision request for entity chain "alice" for "read" action on registered resource values "rrv_mix_ns1,rrv_mix_ns2"
    Then the response should be successful
    And the multi-resource decision should be "PERMIT"
