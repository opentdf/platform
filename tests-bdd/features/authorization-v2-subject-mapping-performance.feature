@authorization @authz-v2 @performance @scale
Feature: Mixed authorization traffic at large policy scale
  Policy has 6,000 allOf project values, four hierarchy levels, seven anyOf regions,
  6,011 distinct subject mappings, and 6,000 resource mappings with multiple aliases.
  Each mapping matches its own user entitlement OR an approved client ID.
  Five users hold 3, 10, 50, 500, and zero projects spread across the full policy.
  Resources combine projects, classification, and regions. Of 1,000 generated
  documents, 55% have one project, 40% have 2-20, and 5% have 21-30.
  Documents exceeding 20 total FQNs are excluded from load. Another 100 documents
  provide permitted examples, and one unmapped value checks fail-closed behavior.
  Workers randomly select a user/action/decision case and then a resource variant.
  Requests vary read, write, denied delete, and one or three resources.
  The seed reproduces both selections at every concurrency level. Setup is excluded.
  Latency is report-only; incorrect decisions, errors, and 30-second timeouts fail.
  Run the same workload with subject mappings, direct entitlements, and dynamic mappings.
  Caching is disabled in all paths. The direct path uses the claims ERS and carries
  grants on the entity rather than matching its Keycloak attributes.
  The dynamic path keeps the same large policy as background load, but requests
  unprovisioned project values under a separate allOf definition. Its IN resolver
  matches the user's project list for read/write. Classification and regions
  continue to use subject mappings; the seed and expected decisions are unchanged.

  Scenario Outline: Random <entitlements> requests across concurrency levels
    Given representative scale users hold subsets of 6000 project values with seed 4625
    And an empty local platform with platform template "<template>" and HTTP write timeout "35s"
    And I submit a request to create a namespace with name "scale.example" and reference id "scale_ns"
    And I send a request to create an attribute referenced as "projects" in namespace "scale_ns" named "project" with rule "allOf" and 6001 generated values in batches of 25
    Then the response should be successful
    And I create 6000 subject mappings for attribute "projects" matching selector ".attributes.projects[]" with action "read,write"
    And I create 6000 resource mappings for attribute "projects" in namespace "scale_ns"
    And the following scale attributes exist in namespace "scale_ns":
      | attribute      | rule      | values                                                         |
      | classification | hierarchy | critical,high,medium,low                                        |
      | region         | anyOf     | region-a,region-b,region-c,region-d,region-e,region-f,region-g     |
    And the following scale grants exist:
      | attribute value         | selector                | matches   | actions    |
      | classification/critical | .attributes.clearance[] | critical  | read,write |
      | classification/high     | .attributes.clearance[] | high      | read,write |
      | classification/medium   | .attributes.clearance[] | medium    | read,write |
      | classification/low      | .attributes.clearance[] | low       | read,write |
      | region/region-a         | .attributes.regions[]   | region-a  | read,write |
      | region/region-b         | .attributes.regions[]   | region-b  | read,write |
      | region/region-c         | .attributes.regions[]   | region-c  | read,write |
      | region/region-d         | .attributes.regions[]   | region-d  | read,write |
      | region/region-e         | .attributes.regions[]   | region-e  | read,write |
      | region/region-f         | .attributes.regions[]   | region-f  | read,write |
      | region/region-g         | .attributes.regions[]   | region-g  | read,write |
    And scale users use "<entitlements>" entitlements for attribute "projects"
    When I send 200 generated authorization requests at these concurrency levels with seed 4625, request timeout "30s", attribute "projects", and 1000 documents:
      | concurrency |
      | 1           |
      | 10          |
      | 25          |
      | 50          |

    Examples:
      | entitlements          | template                                                 |
      | subject-mapping       | cukes/resources/platform.template                        |
      | direct-entitlement    | cukes/resources/platform.direct_entitlements.template    |
      | dynamic-value-mapping | cukes/resources/platform.dynamic_value_mappings.template |
