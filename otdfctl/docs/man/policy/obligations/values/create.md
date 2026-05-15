---
title: Create an obligation value
command:
  name: create
  aliases:
    - c
    - add
    - new
  flags:
    - name: obligation
      shorthand: o
      description: Identifier of the associated obligation (ID or FQN)
      required: true
    - name: value
      shorthand: v
      description: Value of the obligation (i.e. 'value1', must be unique within the definition)
      required: true
    - name: triggers
      shorthand: t
      description: Optional JSON array or file path of obligation trigger(s) to be created and stored on the obligation value.
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
      default: ''
---

Add a value to an obligation in the platform Policy.

For more information about obligation values, see the `obligations` subcommand.

## Examples

Create an obligation value for the obligation with ID '3c51a593-cbf8-419d-b7dc-b656d0bedfbb', and value 'my_value':

```shell
otdfctl policy obligations values create --obligation 3c51a593-cbf8-419d-b7dc-b656d0bedfbb --value my_value
```

### Trigger examples

You can also create multiple obligation triggers while creating an obligation value.

Create an obligation value and create a non-scoped trigger that will map to the created value.

```shell
otdfctl policy obligations values create --obligation 3c51a593-cbf8-419d-b7dc-b656d0bedfbb --value my_value --triggers '[{"action": "read", "attribute_value": "https://test.org/attr/test/value/red"}]'
```

Create an obligation value and create a scoped trigger that will map to the created value

```shell
otdfctl policy obligations values create --obligation 3c51a593-cbf8-419d-b7dc-b656d0bedfbb --value my_value --triggers '[{"action": "read", "attribute_value": "https://test.org/attr/test/value/red", "context": {"pep": {"client_id": "a-pep" }}}]'
```

Create an obligation value and triggers, where the triggers come from a json file.

```shell
otdfctl policy obligations values create --obligation 3c51a593-cbf8-419d-b7dc-b656d0bedfbb --value my_value --triggers "/path/to/file.json"
```
