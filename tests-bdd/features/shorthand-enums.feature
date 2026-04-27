@shorthand-enums
Feature: Shorthand Enum Names E2E
  Verify that the platform accepts shorthand enum names (e.g., "IN", "AND",
  "ANY_OF") in raw HTTP JSON requests. These tests bypass the SDK and send
  raw ConnectRPC JSON to prove the normalization middleware works end-to-end.

  Background:
    Given an empty local platform
    And I submit a request to create a namespace with name "shorthandenums.io" and reference id "ns1"

  Scenario: Create subject condition set with shorthand operator and boolean enums
    When I create a subject condition set via HTTP with shorthand enums

  Scenario: Create attribute with shorthand rule type enum
    When I create an attribute via HTTP with shorthand rule type

  Scenario: Create subject condition set with mixed shorthand and canonical enum names
    When I create a subject condition set via HTTP with mixed enum formats
