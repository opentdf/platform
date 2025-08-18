@example
Feature: Example Default Platform Feature
  Some examples to demonstrate testing the platform using default keycloak
  and platform provisioning

  Background:
    Given a empty local platform
    And I submit a request to create a namespace with name "example.com" and reference id "ns1"
    

  Scenario: Create Attribute With Initial Values
    When I send a request to create an attribute with:
      | namespace_id                           | name      | rule     | values                  |
      | ns1                                    | age-group | anyOf    | 18-24,25-34,35-44,45-54 |
    Then the response should be successful

