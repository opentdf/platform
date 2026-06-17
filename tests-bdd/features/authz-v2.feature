@authz-v2 @stateless
Feature: Authz v2 default policy authorization

  Background:
    # The platform template leaves policy.csv empty so the platform loads the
    # embedded default v2 policy from service/internal/auth/authz/casbin/policy.csv,
    # then appends only the BDD-specific KAS key roles via policy.extension.
    Given a local platform with platform template "cukes/resources/platform.authz_v2.template" and keycloak template "cukes/resources/keycloak_authz_v2.template"

  Rule: KAS registry key access

    # KAS GetKey resolves kas_uri for v2 authz. Granular ListKeys authorization is
    # intentionally deferred, so URI-scoped KAS roles are denied ListKeys.
    Scenario: opentdf-admin can read KAS keys by default
      Given I use the platform as "opentdf-admin"
      And I create KAS keys:
        | kas_uri                      | key_id    |
        | https://kas-admin.example.com | admin-kid |
      When I send a request to get KAS key "admin-kid"
      Then the response should be successful
      When I send a request to list KAS keys for URI "https://kas-admin.example.com"
      Then the response should be successful

    Scenario: opentdf-standard cannot read KAS keys by default
      Given I use the platform as "opentdf-admin"
      And I create KAS keys:
        | kas_uri                         | key_id       |
        | https://kas-standard.example.com | standard-kid |
      Given I use the platform as "opentdf-standard"
      When I send a request to get KAS key "standard-kid"
      Then the response should be permission denied
      When I send a request to list KAS keys for URI "https://kas-standard.example.com"
      Then the response should be permission denied

    Scenario: URI-specific KAS roles cannot read each other's keys
      Given I use the platform as "opentdf-admin"
      And I create KAS keys:
        | kas_uri                   | key_id    |
        | https://kas-a.example.com | kas-a-kid |
        | https://kas-b.example.com | kas-b-kid |
      Given I use the platform as "kas-a"
      When I send a request to get KAS key "kas-a-kid"
      Then the response should be successful
      When I send a request to list KAS keys for URI "https://kas-a.example.com"
      Then the response should be permission denied
      When I send a request to get KAS key "kas-b-kid"
      Then the response should be permission denied
      When I send a request to list KAS keys for URI "https://kas-b.example.com"
      Then the response should be permission denied
      Given I use the platform as "kas-b"
      When I send a request to get KAS key "kas-b-kid"
      Then the response should be successful
      When I send a request to list KAS keys for URI "https://kas-b.example.com"
      Then the response should be permission denied
      When I send a request to get KAS key "kas-a-kid"
      Then the response should be permission denied
      When I send a request to list KAS keys for URI "https://kas-a.example.com"
      Then the response should be permission denied

    Scenario: URI-specific KAS roles authorize ID-based GetKey using resolved KAS URI
      Given I use the platform as "opentdf-admin"
      And I create KAS keys:
        | kas_uri                      | key_id       |
        | https://kas-a-id.example.com | kas-a-id-kid |
        | https://kas-b-id.example.com | kas-b-id-kid |
      Given I use the platform as "kas-a"
      When I send a request to get KAS key "kas-a-id-kid" by stored ID
      Then the response should be successful
      When I send a request to get KAS key "kas-b-id-kid" by stored ID
      Then the response should be permission denied
      Given I use the platform as "kas-b"
      When I send a request to get KAS key "kas-b-id-kid" by stored ID
      Then the response should be successful
      When I send a request to get KAS key "kas-a-id-kid" by stored ID
      Then the response should be permission denied

    # Security: URL values containing '&' and '=' must not be mis-parsed as
    # extra dimensions. A kas-a scoped role must not gain access to a different
    # KAS key whose URI injects a trailing "kas_uri=https://kas-a.example.com".
    Scenario: KAS URI with injected dimension characters is rejected
      Given I use the platform as "opentdf-admin"
      And I create KAS keys:
        | kas_uri                                                             | key_id           |
        | https://kas-b.example.com?foo=bar&kas_uri=https://kas-a.example.com | inject-query-kid |
        | https://kas-b.example.com/a?x=y&kas_uri=https://kas-a.example.com   | inject-path-kid  |
      Given I use the platform as "kas-a"
      When I send a request to get KAS key "inject-query-kid"
      Then the response should be permission denied
      When I send a request to get KAS key "inject-path-kid"
      Then the response should be permission denied
