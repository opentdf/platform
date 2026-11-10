---
title: Create Registered Resource Value
command:
  name: create
  aliases:
    - c
    - add
    - new
  flags:
    - name: resource
      shorthand: r
      description: Identifier of the associated registered resource (ID or name)
      required: true
    - name: value
      shorthand: v
      description: Value of the registered resource (i.e. 'value1', must be unique within the Registered Resource)
      required: true
    - name: action-attribute-value
      shorthand: a
      description: "Optional action attribute values in the format: \"<action_id | action_name>;<attribute_value_id | attribute_value_fqn>\""
      default: ''
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
      default: ''
---

Add a value to a registered resource in the platform Policy.

A registered resource value `value` is normalized to lower case and may contain hyphens or dashes between other alphanumeric characters.

For more information, see the `registered-resources` subcommand.

## Examples

Create a registered resource value for the registered resource with ID '3c51a593-cbf8-419d-b7dc-b656d0bedfbb', value 'my_value', and action attribute values using action/attribute value IDs, action names, and attribute value FQNs:

```shell
otdfctl policy registered-resources values create --resource 3c51a593-cbf8-419d-b7dc-b656d0bedfbb --value my_value --action-attribute-value "74a3eade-ef6c-4422-b764-fe0471f5c6c1;405a35a7-2051-49a6-9645-3a667b4739f3" --action-attribute-value "create;https://example.com/attr/my_attribute/value/my_value"
```
