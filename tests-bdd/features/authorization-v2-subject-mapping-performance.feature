@authorization @authz-v2 @performance @scale
Feature: v2 multi-resource decisions at large policy scale
  GetDecisionMultiResource must remain responsive when the policy database contains the
  subject-mapping and resource-mapping cardinality from the reported regression. Fixture setup is
  not timed. The measured operation is a synchronized group of requests to the public v2
  authorization endpoint. Every case runs at every concurrency level. A fixed seed
  shuffles case and resource order reproducibly. The extra value has no subject mapping.
  Subject mappings use the default unnamespaced policy path; attribute and resource mappings
  retain their namespace. This avoids repeatedly validating the entire attribute during setup.
  Latency is reported without a performance gate until a baseline is established.
  Incorrect decisions, request errors, and request timeouts fail the scenario.

  Scenario Outline: Varied multi-resource decisions at concurrency <concurrency>
    Given a user exists with username "scale-user" and email "scale-user@example.com" and the following attributes:
      | name       | value           |
      | department | ["engineering"] |
    And a user exists with username "other-user" and email "other-user@example.com" and the following attributes:
      | name       | value     |
      | department | ["sales"] |
    And an empty local platform
    And I submit a request to create a namespace with name "scale.example" and reference id "scale_ns"
    And I send a request to create an attribute referenced as "scale_attr" in namespace "scale_ns" named "access-level" with rule "anyOf" and 6012 generated values in batches of 25
    Then the response should be successful
    And a condition group referenced as "scale_condition" with an "or" operator with conditions:
      | selector_value           | operator | values      |
      | .attributes.department[] | in       | engineering |
    And a subject set referenced as "scale_subject_set" containing the condition groups "scale_condition"
    And I send a request to create a subject condition set referenced as "scale_condition_set" containing subject sets "scale_subject_set"
    Then the response should be successful
    And I create 6011 subject mappings for attribute "scale_attr" using condition set "scale_condition_set" with action "read"
    And I create 6000 resource mappings for attribute "scale_attr" in namespace "scale_ns"
    And there is a "user_name" subject entity with value "scale-user" and referenced as "scale-user"
    And there is a "user_name" subject entity with value "other-user" and referenced as "other-user"
    When I exercise the authorization cases with <concurrency> concurrent requests each, seed 4625, and request timeout "30s" for attribute "scale_attr":
      | case          | entity     | action | values           | expected            |
      | allowed_read  | scale-user | read   | v0000,v3005,v6010 | PERMIT,PERMIT,PERMIT |
      | denied_action | scale-user | write  | v0000,v3005,v6010 | DENY,DENY,DENY       |
      | denied_user   | other-user | read   | v0000,v3005,v6010 | DENY,DENY,DENY       |
      | mixed_values  | scale-user | read   | v0000,v6011,v6010 | PERMIT,DENY,PERMIT   |

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
