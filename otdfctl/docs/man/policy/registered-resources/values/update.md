---
title: Update a Registered Resource Value
command:
  name: update
  aliases:
    - u
  flags:
    - name: id
      shorthand: i
      description: ID of the registered resource value to update
    - name: value
      shorthand: v
      description: Optional updated value of the registered resource value (must be unique within the Registered Resource)
    - name: action-attribute-value
      shorthand: a
      description: "Optional action attribute values in the format: \"<action_id | action_name>;<attribute_value_id | attribute_value_fqn>\""
      default: ''
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
      default: ''
    - name: force
      description: Force update without interactive confirmation
---

Update any or all of the `value`, action attribute values, and metadata labels for a Registered Resource Value.

If PEPs rely on this value, a value update could break access.

Updating the action attribute values will remove and replace all existing action attribute values for this registered resource value.

Make sure you know what you are doing.

For more information about Registered Resource Values, see the manual for the `values` subcommand.

## Example

```shell
otdfctl policy registered-resources values update --id 3c51a593-cbf8-419d-b7dc-b656d0bedfbb --value new_value --action-attribute-value "74a3eade-ef6c-4422-b764-fe0471f5c6c1;405a35a7-2051-49a6-9645-3a667b4739f3" --action-attribute-value "create;https://example.com/attr/my_attribute/value/my_value"
```
