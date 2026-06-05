---
title: Subject condition sets
command:
  name: subject-condition-sets
  aliases:
    - subcs
    - scs
    - subject-condition-set
---

Subject Condition Sets (SCSs) are the logical resolvers of entitlement to attributes.

An SCS contains AND/OR groups of conditions with IN/NOT_IN/CONTAINS logic to be applied against
a Subject Entity Representation as either their OIDC Access Token claims or the platform's Entity
Resolution Service (ERS).

They are applied to Attribute Values via Subject Mappings to determine a Subject's entitlement to
any given attribute on TDF'd data.

For example structure and logical resolution, see `create` subcommand. For information about Subject
Mappings, see the `subject-mappings` command.
