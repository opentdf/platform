@authz-v2 @stateless
Feature: Authz v2 default policy authorization

  Background:
    # The platform template leaves policy.csv empty so the platform loads the
    # embedded default v2 policy from service/internal/auth/authz/casbin/policy.csv,
    # then appends only the BDD-specific KAS key roles via policy.extension.
    Given a local platform with platform template "cukes/resources/platform.authz_v2.template" and keycloak template "cukes/resources/keycloak_authz_v2.template"

  Rule: KAS registry key access

    # TODO: Register authz resolvers for /policy.kasregistry.KeyAccessServerRegistryService/GetKey
    # and /policy.kasregistry.KeyAccessServerRegistryService/ListKeys that resolve kas_uri.
    # The kas-a/kas-b cases are expected to fail until those RPCs authorize with
    # kas_uri=https://kas-a.example.com or kas_uri=https://kas-b.example.com instead of dims=*.
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
      Then the response should be successful
      When I send a request to get KAS key "kas-b-kid"
      Then the response should be permission denied
      When I send a request to list KAS keys for URI "https://kas-b.example.com"
      Then the response should be permission denied
      Given I use the platform as "kas-b"
      When I send a request to get KAS key "kas-b-kid"
      Then the response should be successful
      When I send a request to list KAS keys for URI "https://kas-b.example.com"
      Then the response should be successful
      When I send a request to get KAS key "kas-a-kid"
      Then the response should be permission denied
      When I send a request to list KAS keys for URI "https://kas-a.example.com"
      Then the response should be permission denied
