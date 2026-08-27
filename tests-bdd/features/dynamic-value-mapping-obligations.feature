@dynamic-value-mappings @obligations
Feature: Obligations on dynamically entitled existing values
  Validates that an existing attribute value can retain an obligation trigger
  while entitlement to that value is provided by a Dynamic Value Mapping on
  its definition.

  Background:
    Given a user exists with username "alice" and email "alice@example.com" and the following attributes:
      | name       | value           |
      | department | ["engineering"] |
    And a user exists with username "bob" and email "bob@example.com" and the following attributes:
      | name       | value       |
      | department | ["finance"] |
    And a local platform with platform template "cukes/resources/platform.dynamic_value_mappings.template" and keycloak template "cukes/resources/keycloak_base.template"
    And I submit a request to create a namespace with name "example.com" and reference id "ns1"
    And I send a request to create an attribute with:
      | namespace_id | name | rule  | values              |
      | ns1          | team | anyOf | engineering,finance |
    Then the response should be successful
    And I send a request to create an obligation with:
      | namespace_id | name | values    |
      | ns1          | drm  | watermark |
    Then the response should be successful
    And I send a request to create an obligation trigger with:
      | obligation_name | obligation_value | action | attribute_value                                       |
      | drm             | watermark        | read   | https://example.com/attr/team/value/engineering       |
    Then the response should be successful
    And I send a request to create a dynamic value mapping with:
      | attribute_definition_fqn      | selector                 | operator | standard actions | reference_id |
      | https://example.com/attr/team | .attributes.department[] | IN       | read             | dvm_team     |
    Then the response should be successful
    And there is a "user_name" subject entity with value "alice" and referenced as "alice"
    And there is a "user_name" subject entity with value "bob" and referenced as "bob"

  Scenario: Fulfillable obligation permits dynamically entitled access and is returned
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/team/value/engineering" with fulfillable obligations "https://example.com/obl/drm/value/watermark"
    Then the response should be successful
    And I should get a "PERMIT" decision response
    And the decision response should contain obligation "https://example.com/obl/drm/value/watermark"

  Scenario: Unfulfilled obligation denies dynamically entitled access and is returned
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/team/value/engineering" with no fulfillable obligations
    Then the response should be successful
    And I should get a "DENY" decision response
    And the decision response should contain obligation "https://example.com/obl/drm/value/watermark"

  Scenario: Obligation is omitted when the dynamic value mapping does not entitle the entity
    When I send a decision request for entity chain "bob" for "read" action on resource "https://example.com/attr/team/value/engineering" with no fulfillable obligations
    Then the response should be successful
    And I should get a "DENY" decision response
    And the decision response should not contain obligation "https://example.com/obl/drm/value/watermark"
