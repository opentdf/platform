---
title: List attribute definitions
command:
  name: list
  aliases:
    - l
  flags:
    - name: state
      shorthand: s
      description: Filter by state
      enum:
        - active
        - inactive
        - any
      default: active
    - name: limit
      shorthand: l
      description: Limit retrieved count
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
    - name: sort
      description: Sort list results with field:direction syntax. Either field or direction may be omitted
---

By default, the list will only provide `active` attributes if unspecified, but the filter can be controlled with the `--state` flag.

For more general information about attributes, see the `attributes` subcommand.

## Sort Options

Use `--sort <field>:<direction>`. Either side may be omitted, for example `name:` or `:asc`.

| Direction | Description | Default |
| --- | --- | --- |
| `asc` | Ascending order | No |
| `desc` | Descending order | Yes |

| Field | Description | Default |
| --- | --- | --- |
| `name` | Attribute name | No |
| `created_at` | Creation timestamp | Yes |
| `updated_at` | Last update timestamp | No |

Omit direction and let the server choose the default direction:

```shell
otdfctl policy attributes list --sort name:
```

Omit field and let the server choose the default field:

```shell
otdfctl policy attributes list --sort :asc
```

## Example

```shell
otdfctl policy attributes list
```

Sort attributes by name ascending:

```shell
otdfctl policy attributes list --sort name:asc
```
