@encrypt-decrypt @stateless
Feature: Encrypt and decrypt with ABAC
  Demonstrates OpenTDF's attribute-based access control (ABAC) using the
  default demo policy loaded by `a default local platform`:

    demo.com/attr/department        rule: ANY_OF
      engineering, finance, hr

    demo.com/attr/classification    rule: HIERARCHY  (public < internal < confidential < secret)

  Each scenario encrypts a TDF bound to one or more attribute values,
  then has a user attempt to decrypt it. Decryption succeeds when the
  user's Keycloak claims satisfy every attribute on the TDF per its rule;
  otherwise the platform returns access-denied.

  Background:
    Given a user exists with username "alice" and email "alice@demo.com" and the following attributes:
      | name           | value              |
      | department     | ["engineering"]    |
      | classification | ["confidential"]   |
    And a user exists with username "bob" and email "bob@demo.com" and the following attributes:
      | name           | value       |
      | department     | ["finance"] |
      | classification | ["public"]  |
    And a default local platform
    And a user token for "alice" stored as "alice_tok"
    And a user token for "bob" stored as "bob_tok"

  Scenario: ANY_OF allow — engineering user decrypts engineering-bound TDF
    When I encrypt plaintext "hello engineering" with attributes "https://demo.com/attr/department/value/engineering" stored as "tdf1"
    And using token "alice_tok", decrypt "tdf1" stored as "plain1"
    Then the decryption stored as "plain1" should succeed with plaintext "hello engineering"

  Scenario: ANY_OF deny — finance user cannot decrypt engineering-bound TDF
    When I encrypt plaintext "hello engineering" with attributes "https://demo.com/attr/department/value/engineering" stored as "tdf2"
    And using token "bob_tok", decrypt "tdf2" stored as "plain2"
    Then the decryption stored as "plain2" should be denied

  Scenario: HIERARCHY allow — confidential clearance decrypts internal TDF
    When I encrypt plaintext "internal memo" with attributes "https://demo.com/attr/classification/value/internal" stored as "tdf3"
    And using token "alice_tok", decrypt "tdf3" stored as "plain3"
    Then the decryption stored as "plain3" should succeed with plaintext "internal memo"

  Scenario: HIERARCHY deny — public clearance cannot decrypt confidential TDF
    When I encrypt plaintext "confidential memo" with attributes "https://demo.com/attr/classification/value/confidential" stored as "tdf4"
    And using token "bob_tok", decrypt "tdf4" stored as "plain4"
    Then the decryption stored as "plain4" should be denied

  Scenario: Combined attributes — user qualifies for both department and classification
    When I encrypt plaintext "eng+internal" with attributes "https://demo.com/attr/department/value/engineering,https://demo.com/attr/classification/value/internal" stored as "tdf5"
    And using token "alice_tok", decrypt "tdf5" stored as "plain5"
    Then the decryption stored as "plain5" should succeed with plaintext "eng+internal"
