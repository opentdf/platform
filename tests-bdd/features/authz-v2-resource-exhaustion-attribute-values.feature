@authorization @authz-v2 @resource-exhaustion
Feature: v2 GetDecision tolerates an attribute with many values (opentdf/platform#3821)
  An attribute definition with 1000+ values, each carrying a subject mapping, makes the v2 PDP's
  global ListAllSubjectMappings load exceed the 4MB connect limit. Size-adaptive paging must shrink
  the page until it fits so a decision over many of those value FQNs still succeeds.

  Background:
    Given a user exists with username "alice" and email "alice@example.com" and the following attributes:
      | name       | value   |
      | department | ["eng"] |
    And an empty local platform
    And I submit a request to create a namespace with name "example.com" and reference id "ns1"
    And I send a request to create an attribute referenced as "attr_many" in namespace "ns1" named "manyvalues" with rule "anyOf" and 1000 generated values
    Then the response should be successful
    # ~200 padding values (~8KB) hydrated into each of the 1000 subject mappings puts the aggregate
    # ListAllSubjectMappings load near 9MB, well past the 4MB limit.
    And a large subject condition set referenced as "scs_pad" matching selector ".attributes.department[]" value "eng" padded with 200 external values
    Then the response should be successful
    And I send a request to create a subject mapping for every value of attribute "attr_many" using condition set "scs_pad" with action "read"
    Then the response should be successful
    And there is a "user_name" subject entity with value "alice" and referenced as "alice"

  Scenario: GetDecision over many value FQNs succeeds when subject mappings exceed the 4MB message limit
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/manyvalues/value/v0000,https://example.com/attr/manyvalues/value/v0001,https://example.com/attr/manyvalues/value/v0002,https://example.com/attr/manyvalues/value/v0003,https://example.com/attr/manyvalues/value/v0004,https://example.com/attr/manyvalues/value/v0005,https://example.com/attr/manyvalues/value/v0006,https://example.com/attr/manyvalues/value/v0007,https://example.com/attr/manyvalues/value/v0008,https://example.com/attr/manyvalues/value/v0009,https://example.com/attr/manyvalues/value/v0010"
    Then the response should be successful
    And I should get a "PERMIT" decision response
