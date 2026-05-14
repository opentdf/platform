---
title: List attribute namespaces
command:
  name: list
  aliases:
    - ls
    - l
  flags:
    - name: state
      shorthand: s
      description: Filter by state [active, inactive, any]
    - name: limit
      shorthand: l
      description: Limit retrieved count
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
    - name: sort
      description: Sort list results with field:direction syntax. Either field or direction may be omitted
---

For more general information, see the `namespaces` subcommand.

## Sort Options

Use `--sort <field>:<direction>`. Either side may be omitted, for example `name:` or `:asc`.

| Direction | Description | Default |
| --- | --- | --- |
| `asc` | Ascending order | No |
| `desc` | Descending order | Yes |

| Field | Description | Default |
| --- | --- | --- |
| `name` | Namespace name | No |
| `fqn` | Namespace FQN | No |
| `created_at` | Creation timestamp | Yes |
| `updated_at` | Last update timestamp | No |

Omit direction and let the server choose the default direction:

```shell
otdfctl policy namespaces list --sort name:
```

Omit field and let the server choose the default field:

```shell
otdfctl policy namespaces list --sort :asc
```

## Example

```shell
otdfctl policy namespaces list
```

Sort namespaces by name ascending:

```shell
otdfctl policy namespaces list --sort name:asc
```
