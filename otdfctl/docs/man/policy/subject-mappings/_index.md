---
title: Subject mappings
command:
  name: subject-mappings
  aliases:
    - subm
    - sm
    - submap
    - subject-mapping
---

Subject Mappings are the policy mechanism used to entitle Entities to take Actions on Attribute Values.

In a TDF flow, the resource data is associated to Attribute Values within the TDF manifest policy,
and a Subject Mapping links a given entity (user, principal) to entitled Action(s) on an Attribute Value.

A Subject Mapping (SM) relates:
    1. one Subject Condition Set (SCS, see `subject-condition-sets` command)
    2. one or more Actions (see `actions` command)
    3. one Attribute Value (see `attributes values` command)

Within ABAC entitlement decisioning, the principal/agent/user/subject is known via an Entity Representation
provided by the Entity Resolution Service and identity provider, and that Entity Representation is logically
resolved against the Subject Mapping's contained Subject Condition set such that if it is logically true,
the entity is considered entitled to the contained Actions on the contained Attribute Value.
