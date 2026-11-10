---
title: Update an attribute definition
command:
  name: update
  flags:
    - name: id
      shorthand: i
      description: ID of the attribute definition
      required: true
    - name: name
      shorthand: n
      description: Name of the attribute definition
    - name: rule
      shorthand: r
      description: Rule of the attribute definition
      enum:
        - ANY_OF
        - ALL_OF
        - HIERARCHY
    - name: values-order
      shorthand: o
      description: Order of the attribute values (IDs)
---

# Unsafe Update Warning

## Name Update

Renaming an Attribute Definition means any Values and any associated mappings underneath will now be tied to the new name.

Any existing TDFs containing attributes under the old definition name will be rendered inaccessible, and any TDFs tied to the new name
and already created may now become accessible.

## Rule Update

Altering a rule of an Attribute Definition changes the evaluation of entitlement to data. Existing TDFs of the same definition name
and values will now be accessible based on the updated rule. An `anyOf` rule becoming `hierarchy` or vice versa, for example, have
entirely different meanings and access evaluations.

## Values-Order Update

In the case of a `hierarchy` Attribute Definition Rule, the order of Values on the attribute has significant impact on data access.
Changing this order (complete, destructive replacement of the existing order) will impact access to data.

To remove Values from an Attribute Definition, delete them separately via the `values unsafe` commands. To add, utilize safe
`values create` commands.

Make sure you know what you are doing.

For more general information about attributes, see the `attributes` subcommand.

## Example

```shell
otdfctl policy attributes unsafe update --id 3c51a593-cbf8-419d-b7dc-b656d0bedfbb --name mynewname
```
