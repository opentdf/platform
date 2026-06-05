---
title: Create an attribute definition
command:
  name: create
  aliases:
    - new
    - add
    - c
  flags:
    - name: name
      shorthand: n
      description: Name of the attribute
      required: true
    - name: rule
      shorthand: r
      description: Rule of the attribute
      enum:
        - ANY_OF
        - ALL_OF
        - HIERARCHY
      required: true
    - name: value
      shorthand: v
      description: Value of the attribute (i.e. 'value1')
      required: true
    - name: namespace
      shorthand: s
      description: Namespace ID of the attribute
      required: true
    - name: allow-traversal
      description: Allow for platform to use the attribute definition when the value is missing during encryption
      default: false
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
      default: ''
---

Under a namespace, create an attribute with a rule. An attribute definition `name` is normalized to lower case
and may contain hyphens and underscores between other alphanumeric characters.

### Rules

#### ANY_OF

If an Attribute is defined with logical rule `ANY_OF`, an Entity who is mapped to `any` of the associated Values of the Attribute
on TDF'd Resource Data will be Entitled to take the actions in the mapping.

#### ALL_OF

If an Attribute is defined with logical rule `ALL_OF`, an Entity must be mapped to `all` of the associated Values of the Attribute
on TDF'd Resource Data to be Entitled to take the actions in the mapping.

### HIERARCHY

If an Attribute is defined with logical rule `HIERARCHY`, an Entity must be mapped to the same level Value or a level above in hierarchy
compared to a given Value on TDF'd Resource Data. Hierarchical values are considered highest at index 0 and lowest at the last index. Actions
propagate down through the hierarchy, so a mapping of a `read` action on the highest level Value on the Attribute will entitle the action
to each hierarchically lower value, and so on.

For more general information about attributes, see the `attributes` subcommand.

### Allow Traversal

Setting the `allow_traversal` flag on an attribute definition allows a TDF to be created with a missing attribute value.
During encryption while `autoconfigure` is true, if the attribute value is missing and the definition has `allow_traversal`
set our system will encrypt using the attribute definitions key, if a key has been mapped to the definition.

## Example

```shell
otdfctl policy attributes create --namespace 3d25d33e-2469-4990-a9ed-fdd13ce74436 --name myattribute --rule ANY_OF
```
