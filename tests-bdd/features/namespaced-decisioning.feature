@authorization @namespaced-decisioning
Feature: Namespaced Policy Decisioning (name-only action requests)
  Validate strict namespaced decisioning behavior for action-name requests
  using both standard and custom actions.

  Background:
    Given a user exists with username "alice" and email "alice@example.com" and the following attributes:
      | name      | value  |
      | clearance | ["TS"] |
    And a local platform with platform template "cukes/resources/platform.namespaced_policy.template" and keycloak template "cukes/resources/keycloak_base.template"
    And I submit a request to create a namespace with name "ns-one.example.com" and reference id "ns1"
    And I submit a request to create a namespace with name "ns-two.example.com" and reference id "ns2"
    And I send a request to create an attribute with:
      | namespace_id | name           | rule      | values    |
      | ns1          | classification | hierarchy | topsecret |
      | ns2          | classification | hierarchy | topsecret |
    Then the response should be successful
    And a condition group referenced as "cg_ts_clearance" with an "or" operator with conditions:
      | selector_value          | operator | values |
      | .attributes.clearance[] | in       | TS     |
    And a subject set referenced as "ss_ts_clearance" containing the condition groups "cg_ts_clearance"
    And I send a request to create a subject condition set referenced as "scs_clearance_topsecret" containing subject sets "ss_ts_clearance"
    And there is a "user_name" subject entity with value "alice" and referenced as "alice"

  Scenario: Standard action name permits when entitled in resource namespace
    And I send a request to create a subject mapping with:
      | reference_id   | attribute_value                                                | condition_set_name      | standard actions | custom actions |
      | sm_ns1_read_ts | https://ns-one.example.com/attr/classification/value/topsecret | scs_clearance_topsecret | read             |                |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "read" action on resource "https://ns-one.example.com/attr/classification/value/topsecret"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Standard action name denies when entitled only in different namespace
    And I send a request to create a subject mapping with:
      | reference_id   | attribute_value                                                | condition_set_name      | standard actions | custom actions |
      | sm_ns2_read_ts | https://ns-two.example.com/attr/classification/value/topsecret | scs_clearance_topsecret | read             |                |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "read" action on resource "https://ns-one.example.com/attr/classification/value/topsecret"
    Then the response should be successful
    And I should get a "DENY" decision response

  Scenario: Custom action name permits when entitled in resource namespace
    And I send a request to create a subject mapping with:
      | reference_id     | attribute_value                                                | condition_set_name      | standard actions | custom actions |
      | sm_ns1_export_ts | https://ns-one.example.com/attr/classification/value/topsecret | scs_clearance_topsecret |                  | export         |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "custom_action_export" action on resource "https://ns-one.example.com/attr/classification/value/topsecret"
    Then the response should be successful
    And I should get a "PERMIT" decision response

  Scenario: Custom action name denies when entitled only in different namespace
    And I send a request to create a subject mapping with:
      | reference_id     | attribute_value                                                | condition_set_name      | standard actions | custom actions |
      | sm_ns2_export_ts | https://ns-two.example.com/attr/classification/value/topsecret | scs_clearance_topsecret |                  | export         |
    Then the response should be successful
    When I send a decision request for entity chain "alice" for "custom_action_export" action on resource "https://ns-one.example.com/attr/classification/value/topsecret"
    Then the response should be successful
    And I should get a "DENY" decision response
