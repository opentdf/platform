@authorization @authz-v2 @performance @scale
Feature: v2 multi-resource decisions at large policy scale
  GetDecisionMultiResource must remain responsive when the policy database contains the
  subject-mapping and resource-mapping cardinality from the reported regression. Fixture setup is
  not timed. The measured operation is a synchronized group of requests to the public v2
  authorization endpoint.

  Scenario Outline: Concurrent multi-resource decisions complete within 500 milliseconds with 6011 subject mappings at concurrency <concurrency>
    Given a user exists with username "scale-user" and email "scale-user@example.com" and the following attributes:
      | name       | value           |
      | department | ["engineering"] |
    And an empty local platform
    And I submit a request to create a namespace with name "scale.example" and reference id "scale_ns"
    And I send a request to create an attribute referenced as "scale_attr" in namespace "scale_ns" named "access-level" with rule "anyOf" and 6011 generated values in batches of 25
    Then the response should be successful
    And a condition group referenced as "scale_condition" with an "or" operator with conditions:
      | selector_value           | operator | values      |
      | .attributes.department[] | in       | engineering |
    And a subject set referenced as "scale_subject_set" containing the condition groups "scale_condition"
    And I send a request to create a subject condition set referenced as "scale_condition_set" in namespace "scale_ns" containing subject sets "scale_subject_set"
    Then the response should be successful
    And the policy database contains 6011 subject mappings for attribute "scale_attr" using condition set "scale_condition_set" in namespace "scale_ns" with action "read" and 6000 resource mappings
    And there is a "user_name" subject entity with value "scale-user" and referenced as "scale-user"
    When I send <concurrency> concurrent multi-resource decision requests for entity chain "scale-user" for "read" action on resources each within "500ms":
      | resource                                                        |
      | https://scale.example/attr/access-level/value/v0000             |
      | https://scale.example/attr/access-level/value/v3005             |
      | https://scale.example/attr/access-level/value/v6010             |
    Then the response should be successful
    And I should get 3 decision responses
    And the multi-resource decision should be "PERMIT"
    And the decision response for resource "https://scale.example/attr/access-level/value/v0000" should be "PERMIT"
    And the decision response for resource "https://scale.example/attr/access-level/value/v3005" should be "PERMIT"
    And the decision response for resource "https://scale.example/attr/access-level/value/v6010" should be "PERMIT"

    @concurrency-1
    Examples: One request
      | concurrency |
      | 1           |

    @concurrency-10
    Examples: Ten concurrent requests
      | concurrency |
      | 10          |

    @concurrency-25
    Examples: Twenty-five concurrent requests
      | concurrency |
      | 25          |

    @concurrency-50
    Examples: Fifty concurrent requests
      | concurrency |
      | 50          |
