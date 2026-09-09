@authorization @authz-v2 @performance @scale
Feature: Mixed authorization traffic at large policy scale
  Concurrent workers continuously select requests from a pool of entitlement cases.
  The pool varies users, actions, anyOf/allOf/hierarchy rules, combined attributes,
  and multiple resources. Every resource includes a value from the large attribute
  so the measured requests exercise the large-policy lookup path.
  The seed selects the same request mix at every concurrency level. Each selection
  is independent; the summary reports how often each case was selected, including zero.
  Setup is excluded. Latency is report-only; incorrect decisions, errors, and client
  timeouts fail. The fixture's server write timeout exceeds the client deadline.

  Scenario Outline: Random entitlement requests at concurrency <concurrency>
    Given a user exists with username "engineer" and email "engineer@example.com" and the following attributes:
      | name       | value            |
      | population | ["load"]         |
      | department | ["engineering"]  |
      | projects   | ["alpha","beta"] |
      | clearance  | ["high"]         |
    And a user exists with username "analyst" and email "analyst@example.com" and the following attributes:
      | name       | value     |
      | population | ["load"]  |
      | department | ["sales"] |
      | projects   | ["alpha"] |
      | clearance  | ["low"]   |
    And a user exists with username "visitor" and email "visitor@example.com" and the following attributes:
      | name       | value    |
      | population | ["load"] |
      | department | ["none"] |
      | projects   | ["none"] |
      | clearance  | ["none"] |
    And an empty local platform with HTTP write timeout "35s"
    And I submit a request to create a namespace with name "scale.example" and reference id "scale_ns"
    And I send a request to create an attribute referenced as "scale_attr" in namespace "scale_ns" named "access-level" with rule "anyOf" and 6012 generated values in batches of 25
    Then the response should be successful
    And a condition group referenced as "scale_condition" with an "or" operator with conditions:
      | selector_value           | operator | values |
      | .attributes.population[] | in       | load   |
    And a subject set referenced as "scale_subject_set" containing the condition groups "scale_condition"
    And I send a request to create a subject condition set referenced as "scale_condition_set" containing subject sets "scale_subject_set"
    Then the response should be successful
    And I create 6011 subject mappings for attribute "scale_attr" using condition set "scale_condition_set" with action "read,write"
    And I create 6000 resource mappings for attribute "scale_attr" in namespace "scale_ns"
    And the following scale attributes exist in namespace "scale_ns":
      | attribute  | rule      | values                   |
      | department | anyOf     | engineering,sales        |
      | project    | allOf     | alpha,beta               |
      | clearance  | hierarchy | critical,high,medium,low |
    And the following scale grants exist:
      | attribute value        | selector                 | matches     | actions    |
      | department/engineering | .attributes.department[] | engineering | read       |
      | department/sales       | .attributes.department[] | sales       | read       |
      | project/alpha          | .attributes.projects[]   | alpha       | read,write |
      | project/beta           | .attributes.projects[]   | beta        | read,write |
      | clearance/high         | .attributes.clearance[]  | high        | read       |
      | clearance/low          | .attributes.clearance[]  | low         | read       |
    And the following scale resources are defined:
      | resource     | attributes                                                                                           |
      | engineering  | scale_attr/v0000,department/engineering                                                              |
      | sales        | scale_attr/v3005,department/sales                                                                    |
      | either-team  | scale_attr/v6010,department/engineering,department/sales                                             |
      | alpha        | scale_attr/v0000,project/alpha                                                                       |
      | projects     | scale_attr/v3005,project/alpha,project/beta                                                          |
      | medium       | scale_attr/v6010,clearance/medium                                                                    |
      | low          | scale_attr/v0000,clearance/low                                                                       |
      | critical     | scale_attr/v3005,clearance/critical                                                                  |
      | team-project | scale_attr/v6010,department/engineering,project/alpha,project/beta                                   |
      | all-rules    | scale_attr/v0000,department/engineering,department/sales,project/alpha,project/beta,clearance/medium |
      | unmapped     | scale_attr/v6011                                                                                     |
    And there is a "user_name" subject entity with value "engineer" and referenced as "engineer"
    And there is a "user_name" subject entity with value "analyst" and referenced as "analyst"
    And there is a "user_name" subject entity with value "visitor" and referenced as "visitor"
    When I send 200 randomly selected authorization requests with concurrency <concurrency>, seed 4625, and request timeout "30s":
      | case                      | user     | action | resources                  | expected           |
      | anyOf matching team       | engineer | read   | engineering                | PERMIT             |
      | anyOf other team          | engineer | read   | sales                      | DENY               |
      | anyOf one matching value  | analyst  | read   | either-team                | PERMIT             |
      | anyOf no matching value   | visitor  | read   | either-team                | DENY               |
      | allOf all values granted  | engineer | read   | projects                   | PERMIT             |
      | allOf missing one grant   | analyst  | read   | projects                   | DENY               |
      | allOf single value        | analyst  | read   | alpha                      | PERMIT             |
      | allOf no grants           | visitor  | read   | projects                   | DENY               |
      | hierarchy higher grant    | engineer | read   | medium,low                 | PERMIT,PERMIT      |
      | hierarchy lower grant     | analyst  | read   | medium                     | DENY               |
      | hierarchy exact grant     | analyst  | read   | low                        | PERMIT             |
      | hierarchy above clearance | engineer | read   | critical                   | DENY               |
      | hierarchy no grant        | visitor  | read   | low                        | DENY               |
      | write granted             | engineer | write  | projects                   | PERMIT             |
      | write partial grants      | analyst  | write  | alpha,projects             | PERMIT,DENY        |
      | write not granted         | engineer | write  | engineering                | DENY               |
      | combined attributes pass  | engineer | read   | team-project,all-rules     | PERMIT,PERMIT      |
      | combined attributes fail  | analyst  | read   | team-project,all-rules     | DENY,DENY          |
      | combined action denied    | engineer | write  | team-project               | DENY               |
      | mixed resource decisions  | engineer | read   | engineering,sales,projects | PERMIT,DENY,PERMIT |
      | different user decisions  | analyst  | read   | engineering,sales,projects | DENY,PERMIT,DENY   |
      | no attribute grants       | visitor  | read   | engineering,sales,projects | DENY,DENY,DENY     |
      | no mapping for value      | engineer | read   | unmapped                   | DENY               |
      | mixed mapped and unmapped | engineer | read   | engineering,unmapped       | PERMIT,DENY        |

    @concurrency-1
    Examples: One worker
      | concurrency |
      | 1           |

    @concurrency-10
    Examples: Ten workers
      | concurrency |
      | 10          |

    @concurrency-25
    Examples: Twenty-five workers
      | concurrency |
      | 25          |

    @concurrency-50
    Examples: Fifty workers
      | concurrency |
      | 50          |
