@deactivated-attribute-values
Feature: Deactivated attribute values deny decrypt
  A deactivated attribute value — or a value whose definition is deactivated —
  must fail closed: it can neither entitle an entity nor be satisfied on a
  resource, so a TDF already bound to it stops being decryptable the moment the
  deactivation lands.

  These scenarios run against a platform with allow_direct_entitlements
  enabled, which makes authorization v2 decide against the full entitlement
  policy instead of a targeted per-FQN fetch. Deactivated values are present in
  that full policy load, which is how they remained decryptable.

  The demo policy loaded by the default platform is used:

    demo.com/attr/department        rule: ANY_OF
      engineering, finance, hr

    demo.com/attr/classification    rule: HIERARCHY  (public < internal < confidential < secret)

  Each scenario deactivates a value, so the feature is deliberately not
  @stateless — every scenario gets its own platform and policy database.

  Background:
    Given a user exists with username "alice" and email "alice@demo.com" and the following attributes:
      | name           | value            |
      | department     | ["engineering"]  |
      | classification | ["confidential"] |
    And a default local platform with platform template "cukes/resources/platform.deactivation.template"
    And a user token for "alice" stored as "alice_tok"

  Scenario: ANY_OF — deactivating the value on the TDF denies decrypt
    When I encrypt plaintext "hello engineering" with attributes "https://demo.com/attr/department/value/engineering" stored as "tdf_dept"
    And using token "alice_tok", decrypt "tdf_dept" stored as "plain_dept_before"
    Then the decryption stored as "plain_dept_before" should succeed with plaintext "hello engineering"
    When I deactivate the attribute value "https://demo.com/attr/department/value/engineering"
    And using token "alice_tok", decrypt "tdf_dept" stored as "plain_dept_after"
    Then the decryption stored as "plain_dept_after" should be denied

  Scenario: HIERARCHY — deactivating the value on the TDF denies decrypt
    When I encrypt plaintext "internal memo" with attributes "https://demo.com/attr/classification/value/internal" stored as "tdf_class"
    And using token "alice_tok", decrypt "tdf_class" stored as "plain_class_before"
    Then the decryption stored as "plain_class_before" should succeed with plaintext "internal memo"
    When I deactivate the attribute value "https://demo.com/attr/classification/value/internal"
    And using token "alice_tok", decrypt "tdf_class" stored as "plain_class_after"
    Then the decryption stored as "plain_class_after" should be denied

  # Deactivating a definition does not cascade to its values in the database — each value keeps
  # active = true — so the deny must come from the definition's own state.
  Scenario: Deactivating the attribute definition denies decrypt of its values
    When I encrypt plaintext "hello engineering" with attributes "https://demo.com/attr/department/value/engineering" stored as "tdf_defn"
    And using token "alice_tok", decrypt "tdf_defn" stored as "plain_defn_before"
    Then the decryption stored as "plain_defn_before" should succeed with plaintext "hello engineering"
    When I deactivate the attribute definition "https://demo.com/attr/department"
    And using token "alice_tok", decrypt "tdf_defn" stored as "plain_defn_after"
    Then the decryption stored as "plain_defn_after" should be denied

  # alice reaches `public` only by hierarchy cascade from her entitled
  # `confidential`. Deactivating `confidential` must stop the cascade.
  Scenario: HIERARCHY — deactivating the entitled value stops the cascade to lower values
    When I encrypt plaintext "public notice" with attributes "https://demo.com/attr/classification/value/public" stored as "tdf_cascade"
    And using token "alice_tok", decrypt "tdf_cascade" stored as "plain_cascade_before"
    Then the decryption stored as "plain_cascade_before" should succeed with plaintext "public notice"
    When I deactivate the attribute value "https://demo.com/attr/classification/value/confidential"
    And using token "alice_tok", decrypt "tdf_cascade" stored as "plain_cascade_after"
    Then the decryption stored as "plain_cascade_after" should be denied
