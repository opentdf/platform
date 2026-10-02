@authorization @authz-v2 @resource-exhaustion
Feature: v2 GetDecision over an attribute definition with many values (opentdf/platform#3821)
  A decision request naming FQNs from an attribute definition with 1000+ values, each carrying a
  subject mapping, fails on the v1 authorization API: its internal GetAttributeValuesByFqns call
  returns the whole definition — every sibling value with its subject mappings — and exceeds the
  4MB message limit with resource_exhausted. The v2 authorization API never makes that call, so the
  same request must succeed. This is the regression test behind the "upgrade to v2" guidance.

  Background:
    Given a user exists with username "alice" and email "alice@example.com" and the following attributes:
      | name       | value   |
      | department | ["eng"] |
    And an empty local platform
    And I submit a request to create a namespace with name "example.com" and reference id "ns1"
    # 1000 values matches the medium-scale data set the issue was reported against.
    And I send a request to create an attribute referenced as "attr_needtoknow" in namespace "ns1" named "needtoknow" with rule "anyOf" and 1000 generated values
    Then the response should be successful
    And I send a request to create an attribute with:
      | namespace_id | name           | rule  | values    |
      | ns1          | color          | anyOf | blue      |
      | ns1          | shape          | anyOf | circle    |
    Then the response should be successful
    And a condition group referenced as "cg_department_eng" with an "or" operator with conditions:
      | selector_value           | operator | values |
      | .attributes.department[] | in       | eng    |
    And a subject set referenced as "ss_department_eng" containing the condition groups "cg_department_eng"
    And I send a request to create a subject condition set referenced as "scs_department_eng" containing subject sets "ss_department_eng"
    Then the response should be successful
    # Every one of the 1000 values gets its own subject mapping, as in the reported data set. This is
    # what inflates the v1 GetAttributeValuesByFqns response past the message limit.
    And I send a request to create a subject mapping for every value of attribute "attr_needtoknow" using condition set "scs_department_eng" with actions "read"
    Then the response should be successful
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                             | condition_set_name | standard actions | custom actions |
      | sm_color     | https://example.com/attr/color/value/blue   | scs_department_eng | read             |                |
      | sm_shape     | https://example.com/attr/shape/value/circle | scs_department_eng | read             |                |
    Then the response should be successful
    And there is a "user_name" subject entity with value "alice" and referenced as "alice"

  # 11 FQNs — 9 from the many-valued definition plus two ordinary ones — is the request shape
  # that returned 500 resource_exhausted from v1 GetDecisions at this scale.
  Scenario: Decision over 11 FQNs including a many-valued definition succeeds
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/needtoknow/value/v0000,https://example.com/attr/needtoknow/value/v0001,https://example.com/attr/needtoknow/value/v0002,https://example.com/attr/needtoknow/value/v0003,https://example.com/attr/needtoknow/value/v0004,https://example.com/attr/needtoknow/value/v0005,https://example.com/attr/needtoknow/value/v0006,https://example.com/attr/needtoknow/value/v0007,https://example.com/attr/needtoknow/value/v0008,https://example.com/attr/color/value/blue,https://example.com/attr/shape/value/circle"
    Then the response should be successful
    And I should get a "PERMIT" decision response
