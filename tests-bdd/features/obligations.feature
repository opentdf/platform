@obligations
Feature: Obligations Decisioning E2E Tests
  E2E tests for obligations decisioning feature covering obligation definition,
  value triggers, multi-resource decisions, entity chains, and ABAC scenarios.
  
  NOTE: Each scenario creates its own isolated platform instance.
  In DEBUG mode, only run ONE scenario at a time using specific scenario line numbers.
  For full test suite execution, use containerized mode (without PLATFORM_IMAGE=DEBUG).

  Background:
    Given a user exists with username "alice" and email "alice@example.com" and the following attributes:
      | name      | value  |
      | clearance | ["TS"] |
    And a user exists with username "bob" and email "bob@example.com" and the following attributes:
      | name      | value |
      | clearance | ["S"] |
    And a user exists with username "charlie" and email "charlie@example.com" and the following attributes:
      | name      | value |
      | clearance | ["C"] |
    And a empty local platform
    And I submit a request to create a namespace with name "example.com" and reference id "ns1"
    And I send a request to create an attribute with:
      | namespace_id | name           | rule      | values                                    |
      | ns1          | classification | hierarchy | topsecret,secret,confidential,unclassified|
      | ns1          | country        | anyOf     | USA,GBR,CAN                              |
    # Create subject mappings for authorization
    And a condition group referenced as "cg_ts_clearance" with an "or" operator with conditions:
      | selector_value          | operator | values |
      | .attributes.clearance[] | in       | TS     |
    And a condition group referenced as "cg_s_clearance" with an "or" operator with conditions:
      | selector_value          | operator | values |
      | .attributes.clearance[] | in       | S      |
    And a subject set referenced as "ss_ts_clearance" containing the condition groups "cg_ts_clearance"
    And a subject set referenced as "ss_s_clearance" containing the condition groups "cg_s_clearance"
    And I send a request to create a subject condition set referenced as "scs_clearance_topsecret" containing subject sets "ss_ts_clearance"
    And I send a request to create a subject condition set referenced as "scs_clearance_secret" containing subject sets "ss_s_clearance"
    And I send a request to create a subject mapping with:
      | reference_id                | attribute_value                                         | condition_set_name      | standard actions  | custom actions |
      | sm_classification_topsecret | https://example.com/attr/classification/value/topsecret | scs_clearance_topsecret | read,transmit     |                |
      | sm_classification_secret    | https://example.com/attr/classification/value/secret    | scs_clearance_secret    | read,transmit     |                |

  Scenario: Create obligation definition with value and verify in decision response
    Given I send a request to create an obligation with:
      | namespace_id | name      | values           |
      | ns1          | watermark | visible,invisible|
    Then the response should be successful
    And the obligation "watermark" should exist with values "visible,invisible"
    And I send a request to create an obligation trigger with:
      | obligation_name | obligation_value | action | attribute_value                                         |
      | watermark       | visible          | read   | https://example.com/attr/classification/value/topsecret |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "alice" and referenced as "alice"
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/classification/value/topsecret"
    Then the response should be successful
    And I should get a "PERMIT" decision response
    And the decision response should contain obligation "https://example.com/obl/watermark/value/visible"

  Scenario: Obligation scoped to client ID is required for matching client
    Given I send a request to create an obligation with:
      | namespace_id | name      | values      |
      | ns1          | audit-log | required    |
    Then the response should be successful
    And I send a request to create an obligation trigger scoped to client "test-client" with:
      | obligation_name | obligation_value | action | attribute_value                                    |
      | audit-log       | required         | read   | https://example.com/attr/classification/value/secret |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "bob" and referenced as "bob"
    And there is a "client_id" environment entity with value "test-client" and referenced as "client1"
    When I send a decision request for entity chain "bob,client1" for "read" action on resource "https://example.com/attr/classification/value/secret"
    Then the response should be successful
    And I should get a "PERMIT" decision response
    And the decision response should contain obligation "https://example.com/obl/audit-log/value/required"

  Scenario: Obligation not required when client ID does not match scope
    Given I send a request to create an obligation with:
      | namespace_id | name      | values   |
      | ns1          | audit-log | required |
    Then the response should be successful
    And I send a request to create an obligation trigger scoped to client "specific-client" with:
      | obligation_name | obligation_value | action | attribute_value                                    |
      | audit-log       | required         | read   | https://example.com/attr/classification/value/secret |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "charlie" and referenced as "charlie"
    And there is a "client_id" environment entity with value "other-client" and referenced as "client2"
    When I send a decision request for entity chain "charlie,client2" for "read" action on resource "https://example.com/attr/classification/value/secret"
    Then the response should be successful
    And I should get a "PERMIT" decision response
    And the decision response should not contain obligation "https://example.com/obl/audit-log/value/required"

  Scenario: Multi-resource decision request with obligations
    Given I send a request to create an obligation with:
      | namespace_id | name         | values      |
      | ns1          | geo-restrict | enforce     |
    Then the response should be successful
    And I send a request to create an obligation trigger with:
      | obligation_name | obligation_value | action | attribute_value                                         |
      | geo-restrict    | enforce          | read   | https://example.com/attr/classification/value/topsecret |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "alice" and referenced as "alice"
    When I send a multi-resource decision request for entity chain "alice" for "read" action on resources:
      | resource                                                      |
      | https://example.com/attr/classification/value/topsecret       |
      | https://example.com/attr/classification/value/secret          |
      | https://example.com/attr/classification/value/confidential    |
    Then the response should be successful
    And I should get 3 decision responses
    And the decision response for resource "https://example.com/attr/classification/value/topsecret" should contain obligation "https://example.com/obl/geo-restrict/value/enforce"
    And the decision response for resource "https://example.com/attr/classification/value/secret" should not contain any obligations
    And the decision response for resource "https://example.com/attr/classification/value/confidential" should not contain any obligations

  Scenario: Multiple chained entities in entity chain with obligations
    Given I send a request to create an obligation with:
      | namespace_id | name      | values        |
      | ns1          | chain-log | track-session |
    Then the response should be successful
    And I send a request to create an obligation trigger with:
      | obligation_name | obligation_value | action | attribute_value                                    |
      | chain-log       | track-session    | read   | https://example.com/attr/classification/value/secret |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "alice" and referenced as "alice"
    And there is a "client_id" environment entity with value "app-client" and referenced as "app"
    And there is a "user_name" subject entity with value "bob" and referenced as "bob"
    When I send a decision request for entity chain "alice,app,bob" for "read" action on resource "https://example.com/attr/classification/value/secret"
    Then the response should be successful
    And I should get a "PERMIT" decision response
    And the decision response should contain obligation "https://example.com/obl/chain-log/value/track-session"

  Scenario: ABAC entitlements with obligations - matrix test across entities, actions, and resources
    Given I send a request to create an obligation with:
      | namespace_id | name          | values                        |
      | ns1          | data-handling | encrypt-transit,encrypt-rest  |
    Then the response should be successful
    And I send a request to create an obligation trigger with:
      | obligation_name | obligation_value | action    | attribute_value                                         |
      | data-handling   | encrypt-transit  | transmit  | https://example.com/attr/classification/value/topsecret |
    And I send a request to create an obligation trigger with:
      | obligation_name | obligation_value | action | attribute_value                                         |
      | data-handling   | encrypt-rest     | read   | https://example.com/attr/classification/value/topsecret |
    Then the response should be successful
    # Create subject condition set and mappings for ABAC
    And a condition group referenced as "cg_ts_clearance" with an "or" operator with conditions:
      | selector_value          | operator | values    |
      | .attributes.clearance[] | in       | TS        |
    And a subject set referenced as "ss_ts_clearance" containing the condition groups "cg_ts_clearance"
    And I send a request to create a subject condition set referenced as "scs_clearance_topsecret" containing subject sets "ss_ts_clearance"
    And I send a request to create a subject mapping with:
      | reference_id                | attribute_value                                         | condition_set_name      | standard actions  | custom actions |
      | sm_classification_topsecret | https://example.com/attr/classification/value/topsecret | scs_clearance_topsecret | read,transmit     |                |
    And a user exists with username "alice-ts" and email "alice-ts@example.com" and the following attributes:
      | name      | value  |
      | clearance | ["TS"] |
    Given there is a "user_name" subject entity with value "alice-ts" and referenced as "alice-ts"
    When I send a multi-resource decision request for entity chain "alice-ts" for "read" action on resources:
      | resource                                                      |
      | https://example.com/attr/classification/value/topsecret       |
    Then the response should be successful
    And I should get 1 decision responses
    And I should get a "PERMIT" decision response
    And the decision response should contain obligation "https://example.com/obl/data-handling/value/encrypt-rest"
    When I send a multi-resource decision request for entity chain "alice-ts" for "transmit" action on resources:
      | resource                                                      |
      | https://example.com/attr/classification/value/topsecret       |
    Then the response should be successful
    And I should get 1 decision responses
    And I should get a "PERMIT" decision response
    And the decision response should contain obligation "https://example.com/obl/data-handling/value/encrypt-transit"

  Scenario: Multiple obligations on single resource decision
    Given I send a request to create an obligation with:
      | namespace_id | name      | values   |
      | ns1          | watermark | visible  |
      | ns1          | audit     | required |
      | ns1          | retention | 90-days  |
    Then the response should be successful
    And I send a request to create an obligation trigger with:
      | obligation_name | obligation_value | action | attribute_value                                         |
      | watermark       | visible          | read   | https://example.com/attr/classification/value/topsecret |
    And I send a request to create an obligation trigger with:
      | obligation_name | obligation_value | action | attribute_value                                         |
      | audit           | required         | read   | https://example.com/attr/classification/value/topsecret |
    And I send a request to create an obligation trigger with:
      | obligation_name | obligation_value | action | attribute_value                                         |
      | retention       | 90-days          | read   | https://example.com/attr/classification/value/topsecret |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "alice" and referenced as "alice"
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/classification/value/topsecret"
    Then the response should be successful
    And I should get a "PERMIT" decision response
    And the decision response should contain obligations:
      | obligation                                                   |
      | https://example.com/obl/watermark/value/visible       |
      | https://example.com/obl/audit/value/required          |
      | https://example.com/obl/retention/value/90-days       |
