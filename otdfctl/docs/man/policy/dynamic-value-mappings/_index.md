---
title: Dynamic value mappings
command:
  name: dynamic-value-mappings
  aliases:
    - dvm
    - dynamic-value-mapping
    - dynamicvaluemappings
---

Dynamic Value Mappings entitle dynamically-requested Attribute Values under an Attribute Definition
without pre-provisioning a Value and Subject Mapping for each discrete value.

A Dynamic Value Mapping raises entitlement authority from a concrete Attribute Value up to the
Attribute Definition. At decision time the mapping's resolver compares the requested resource value
segment against a selector resolved from the Entity Representation (such as from an idP/LDAP), so a
subject may be entitled to values that were never created in policy.

A Dynamic Value Mapping (DVM) relates:
    1. one Attribute Definition (see `attributes` command)
    2. one dynamic value resolver (a selector plus a comparison operator)
    3. one or more Actions (see `actions` command)
    4. an optional static pre-gate Subject Condition Set (see `subject-condition-sets` command)

Combination semantics: multiple dynamic value mappings on the same definition are OR-ed (any match
entitles). When a static pre-gate Subject Condition Set is present, both the gate and the resolver
must pass. A definition with a dynamic value mapping cannot also carry value-level subject mappings,
and HIERARCHY definitions are not supported.
