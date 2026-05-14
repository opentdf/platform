---
title: List Registered Resources
command:
  name: list
  aliases:
    - l
  flags:
    - name: namespace
      shorthand: s
      description: Namespace ID or FQN to filter results
    - name: limit
      shorthand: l
      description: Limit retrieved count
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
    - name: sort
      description: Sort list results with field:direction syntax. Either field or direction may be omitted
---

For more information about Registered Resources, see the `registered-resources` subcommand.

## Sort Options

Use `--sort <field>:<direction>`. Either side may be omitted, for example `name:` or `:asc`.

| Direction | Description | Default |
| --- | --- | --- |
| `asc` | Ascending order | No |
| `desc` | Descending order | Yes |

| Field | Description | Default |
| --- | --- | --- |
| `name` | Registered resource name | No |
| `created_at` | Creation timestamp | Yes |
| `updated_at` | Last update timestamp | No |

Omit direction and let the server choose the default direction:

```shell
otdfctl policy registered-resources list --sort name:
```

Omit field and let the server choose the default field:

```shell
otdfctl policy registered-resources list --sort :asc
```

## Example

```shell
otdfctl policy registered-resources list
```

Sort registered resources by name ascending:

```shell
otdfctl policy registered-resources list --sort name:asc
```
