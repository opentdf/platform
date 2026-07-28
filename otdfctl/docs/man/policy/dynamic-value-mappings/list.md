---
title: List dynamic value mappings
command:
  name: list
  aliases:
    - l
  flags:
    - name: namespace
      shorthand: n
      description: Namespace ID or FQN to filter results
    - name: attribute-definition-id
      description: Attribute Definition ID to filter results
    - name: limit
      shorthand: l
      description: Limit retrieved count
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
    - name: sort
      description: Sort list results by field
    - name: order
      description: Sort order direction. Accepted values are asc and desc
---

List Dynamic Value Mappings, optionally filtered by namespace or attribute definition.

For more information about dynamic value mappings, see the `dynamic-value-mappings` subcommand.

## Sort Options

Use `--sort <field>` with optional `--order <direction>`. Either flag may be omitted.

| Field | Description |
| --- | --- |
| created_at | Order by creation timestamp |
| updated_at | Order by last update timestamp |
