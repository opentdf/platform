---
title: List obligation definitions
command:
  name: list
  aliases:
    - l
  flags:
    - name: limit
      shorthand: l
      description: Limit retrieved count
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
    - name: namespace
      shorthand: n
      description: Namespace ID or FQN by which to filter results
    - name: sort
      description: Sort list results by field
    - name: order
      description: Sort order direction. Accepted values are asc and desc
---

List obligations definitions (optionally by namespace).

For more information about obligations, see the `obligations` subcommand.

## Sort Options

Use `--sort <field>` with optional `--order <direction>`. Either flag may be omitted.

| Direction | Description | Default |
| --- | --- | --- |
| `asc` | Ascending order | No |
| `desc` | Descending order | Yes |

| Field | Description | Default |
| --- | --- | --- |
| `name` | Obligation name | No |
| `fqn` | Obligation FQN | No |
| `created_at` | Creation timestamp | Yes |
| `updated_at` | Last update timestamp | No |

Omit direction and let the server choose the default direction:

```shell
otdfctl policy obligations list --sort name
```

Omit field and let the server choose the default field:

```shell
otdfctl policy obligations list --order asc
```

## Example

```shell
otdfctl policy obligations list --limit 10 --offset 0
```

Sort obligations by name ascending:

```shell
otdfctl policy obligations list --sort name --order asc
```
