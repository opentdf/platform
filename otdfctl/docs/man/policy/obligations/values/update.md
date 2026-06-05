---
title: Update an obligation value
command:
  name: update
  aliases:
    - u
  flags:
    - name: id
      shorthand: i
      description: ID of the obligation value to update
      required: true
    - name: value
      shorthand: v
      description: Optional updated value of the obligation value (must be unique within the definition)
    - name: triggers
      shorthand: t
      description: Optional JSON array or file path of obligation trigger(s) to be created and stored on the obligation value. 
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
      default: ''
---

Update the `value` and/or metadata labels for an obligation value.

If PEPs rely on this value, a value update could break access.

Make sure you know what you are doing.

For more information about obligation values, see the manual for the `values` subcommand.

## Example

```shell
otdfctl policy obligations values update --id 3c51a593-cbf8-419d-b7dc-b656d0bedfbb --value new_value --label "hello=world"
```

### Trigger Example

>[!CAUTION]
>Updating a obligation value with triggers will replace all existing
>triggers, on the obligation value being updated, with the new list.

Update an obligation value and assign one unscoped trigger to the new value.

>[!NOTE]
>View the `create` command under obligation triggers to read
>more about `scoped` and `unscoped` triggers.

```shell
otdfctl policy obligations values update --id 3c51a593-cbf8-419d-b7dc-b656d0bedfbb --value new_value --label "hello=world" --triggers '[{"action": "read", "attribute_value": "https://test.org/attr/test/value/red"}]'
```

Update triggers on an obligation value via a json file.

```shell
otdfctl policy obligations values update --id 3c51a593-cbf8-419d-b7dc-b656d0bedfbb --value new_value --label "hello=world" --triggers "/path/to/file.json"
```
