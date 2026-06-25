@authz-v2 @stateless
Feature: Authz v2 default policy authorization

  Background:
    # The platform template leaves policy.csv empty so the platform loads the
    # embedded default v2 policy from service/internal/auth/authz/casbin/policy.csv,
    # then appends only the BDD-specific KAS key roles via policy.extension.
    Given a local platform with platform template "cukes/resources/platform.authz_v2.template" and keycloak template "cukes/resources/keycloak_authz_v2.template"

  Rule: KAS registry key access

    Scenario: URI-specific KAS role can list unfiltered only while all keys match its KAS URI
      Given I use the platform as "opentdf-admin"
      And I create KAS keys:
        | kas_uri                              | key_id                 |
        | https://kas-a-unfiltered.example.com | kas-a-unfiltered-kid   |
      Given I use the platform as "kas-a"
      When I send a request to list KAS keys
      Then the response should be successful
      And the listed KAS keys should contain only "kas-a-unfiltered-kid"
      Given I use the platform as "opentdf-admin"
      And I create KAS keys:
        | kas_uri                              | key_id                 |
        | https://kas-b-unfiltered.example.com | kas-b-unfiltered-kid   |
      Given I use the platform as "kas-a"
      When I send a request to list KAS keys
      Then the response should be permission denied

    # KAS GetKey resolves kas_uri for v2 authz.
    Scenario: opentdf-admin can get KAS keys by default
      Given I use the platform as "opentdf-admin"
      And I create KAS keys:
        | kas_uri                      | key_id    |
        | https://kas-admin.example.com | admin-kid |
      When I send a request to get KAS key "admin-kid"
      Then the response should be successful

    Scenario: URI-specific KAS roles cannot get each other's keys
      Given I use the platform as "opentdf-admin"
      And I create KAS keys:
        | kas_uri                   | key_id    |
        | https://kas-a.example.com | kas-a-kid |
        | https://kas-b.example.com | kas-b-kid |
      Given I use the platform as "kas-a"
      When I send a request to get KAS key "kas-a-kid"
      Then the response should be successful
      When I send a request to get KAS key "kas-b-kid"
      Then the response should be permission denied
      Given I use the platform as "kas-b"
      When I send a request to get KAS key "kas-b-kid"
      Then the response should be successful
      When I send a request to get KAS key "kas-a-kid"
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

    Scenario: opentdf-standard can list all KAS keys by default
      Given I use the platform as "opentdf-admin"
      And I create KAS keys:
        | kas_uri                        | key_id          |
        | https://kas-list-a.example.com | kas-list-a-kid  |
        | https://kas-list-b.example.com | kas-list-b-kid  |
      Given I use the platform as "opentdf-standard"
      When I send a request to list KAS keys
      Then the response should be successful
      And the listed KAS keys should contain "kas-list-a-kid,kas-list-b-kid"

    Scenario: URI-specific KAS role can list only its KAS URI
      Given I use the platform as "opentdf-admin"
      And I create KAS keys:
        | kas_uri                        | key_id         |
        | https://kas-a-list.example.com | kas-a-list-kid |
        | https://kas-b-list.example.com | kas-b-list-kid |
      Given I use the platform as "kas-a"
      When I send a request to list KAS keys for KAS URI "https://kas-a-list.example.com"
      Then the response should be successful
      And the listed KAS keys should contain only "kas-a-list-kid"
      When I send a request to list KAS keys for KAS URI "https://kas-b-list.example.com"
      Then the response should be permission denied

    Scenario: URI-specific KAS role authorizes ID-based ListKeys using resolved KAS URI
      Given I use the platform as "opentdf-admin"
      And I create KAS keys:
        | kas_uri                           | key_id            |
        | https://kas-a-list-id.example.com | kas-a-list-id-kid |
        | https://kas-b-list-id.example.com | kas-b-list-id-kid |
      Given I use the platform as "kas-a"
      When I send a request to list KAS keys for KAS key "kas-a-list-id-kid" by stored KAS ID
      Then the response should be successful
      And the listed KAS keys should contain only "kas-a-list-id-kid"
      When I send a request to list KAS keys for KAS key "kas-b-list-id-kid" by stored KAS ID
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
