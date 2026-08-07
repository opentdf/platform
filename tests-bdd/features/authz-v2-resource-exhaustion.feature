@authorization @authz-v2 @resource-exhaustion
Feature: v2 GetDecision tolerates large subject-mapping sets (opentdf/platform#3821)
  The v2 PDP loads every subject mapping (each embedding its condition set) to make a
  decision; once the aggregate exceeds the 4MB connect limit it fails with
  resource_exhausted. A few mappings sharing one large condition set reproduce it.

  Background:
    Given a user exists with username "alice" and email "alice@example.com" and the following attributes:
      | name       | value   |
      | department | ["eng"] |
    And an empty local platform
    And I submit a request to create a namespace with name "example.com" and reference id "ns1"
    And I send a request to create an attribute with:
      | namespace_id | name       | rule  | values                          |
      | ns1          | needtoknow | anyOf | v0,v1,v2,v3,v4,v5,v6,v7          |
    Then the response should be successful
    # ~25k padding values ~= 1MB per condition set; shared across 8 subject mappings the
    # global ListAllSubjectMappings load embeds it 8 times (~8MB), well past the 4MB limit.
    And a large subject condition set referenced as "scs_big" matching selector ".attributes.department[]" value "eng" padded with 25000 external values
    Then the response should be successful
    And I send a request to create a subject mapping with:
      | reference_id | attribute_value                              | condition_set_name | standard actions | custom actions |
      | sm_v0        | https://example.com/attr/needtoknow/value/v0 | scs_big            | read             |                |
      | sm_v1        | https://example.com/attr/needtoknow/value/v1 | scs_big            | read             |                |
      | sm_v2        | https://example.com/attr/needtoknow/value/v2 | scs_big            | read             |                |
      | sm_v3        | https://example.com/attr/needtoknow/value/v3 | scs_big            | read             |                |
      | sm_v4        | https://example.com/attr/needtoknow/value/v4 | scs_big            | read             |                |
      | sm_v5        | https://example.com/attr/needtoknow/value/v5 | scs_big            | read             |                |
      | sm_v6        | https://example.com/attr/needtoknow/value/v6 | scs_big            | read             |                |
      | sm_v7        | https://example.com/attr/needtoknow/value/v7 | scs_big            | read             |                |
    Then the response should be successful
    And there is a "user_name" subject entity with value "alice" and referenced as "alice"

  Scenario: GetDecision returns a decision when subject mappings exceed the 4MB message limit
    When I send a decision request for entity chain "alice" for "read" action on resource "https://example.com/attr/needtoknow/value/v0"
    Then the response should be successful
    And I should get a "PERMIT" decision response
