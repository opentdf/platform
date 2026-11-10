---
title: Manage attribute values
command:
  name: values
  aliases:
    - val
    - value
---

Attribute values are the individual units tagged on TDFs containing Resource Data.

They are mapped to entitle person and non-person entities through Subject Mappings, to varied terms for tagging providers
through Resource Mappings, to individual keys and Key Access Servers through KAS Grants, and more.

They are fully-qualified through the FQN structure `https://<namespace>/attr/<definition name>/value/<value>`, and the presence
of one or more values on a piece of Resource Data (a TDF) determines an entity's access to the data through a combination
of entitlements and the attribute definition rule evaluation.

In other words, Attribute Values are the atomic units that drive access control relation of Data -> Entities and vice versa.

Values are contextualized by Attribute Definitions within Namespaces, and only have logical meaning as part of a Definition.

Giving data multiple Attribute Values across the same or multiple Definitions/Namespaces will require all of the definition rules to be satisfied
by an Entity's mapped Entitlements to result in key release, decryption, and resulting access to TDF'd data.

For more information on:

- values, see the `attributes values` subcommand
- attribute definitions, see the `attributes` subcommand
- namespaces, see the `attributes namespaces` subcommand
