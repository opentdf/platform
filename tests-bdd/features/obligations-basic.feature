@obligations @smoke-obligations
Feature: Obligations Decisioning Basic Smoke Test
  Basic smoke test for obligations decisioning to verify the feature works e2e

  Scenario: Create obligation definition with value and verify in decision response
    Given a user exists with username "alice" and email "alice@example.com" and the following attributes:
      | name      | value  |
      | clearance | ["TS"] |
    And a empty local platform
    And I submit a request to create a namespace with name "example.com" and reference id "ns1"
    And I send a request to create an attribute with:
      | namespace_id | name           | rule      | values      |
      | ns1          | classification | hierarchy | topsecret   |
    Then the response should be successful
    # Create subject mappings to allow alice to read topsecret
    And a condition group referenced as "cg_ts_clearance" with an "or" operator with conditions:
      | selector_value          | operator | values |
      | .attributes.clearance[] | in       | TS     |
    And a subject set referenced as "ss_ts_clearance" containing the condition groups "cg_ts_clearance"
    And I send a request to create a subject condition set referenced as "scs_clearance_topsecret" containing subject sets "ss_ts_clearance"
    And I send a request to create a subject mapping with:
      | reference_id                | attribute_value                                         | condition_set_name      | standard actions | custom actions |
      | sm_classification_topsecret | https://example.com/attr/classification/value/topsecret | scs_clearance_topsecret | read             |                |
    # Create obligation
    Given I send a request to create an obligation with:
      | namespace_id | name      | values  |
      | ns1          | watermark | visible |
    Then the response should be successful
    And the obligation "watermark" should exist with values "visible"
    And I send a request to create an obligation trigger with:
      | obligation_name | obligation_value | action | attribute_value                                         |
      | watermark       | visible          | read   | https://example.com/attr/classification/value/topsecret |
    Then the response should be successful
    Given there is a "user_name" subject entity with value "alice" and referenced as "alice"
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/classification/value/topsecret"
    Then the response should be successful
    Then I should get a "PERMIT" decision response
    And the decision response should contain obligation "https://example.com/obl/watermark/value/visible"
