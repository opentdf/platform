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
    - name: search
      description: Search term to filter results
    - name: sort
      description: Sort list results by field
    - name: order
      description: Sort order direction. Accepted values are asc and desc
---

For more information about Registered Resources, see the `registered-resources` subcommand.

## Search Fields

The `--search` term is trimmed and matched as a substring against these values:

| Value | Description |
| --- | --- |
| Registered resource name | Resource name |

## Sort Options

Use `--sort <field>` with optional `--order <direction>`. Either flag may be omitted.

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
otdfctl policy registered-resources list --sort name
```

Omit field and let the server choose the default field:

```shell
otdfctl policy registered-resources list --order asc
```

## Example

```shell
otdfctl policy registered-resources list
```

Search registered resources by name:

```shell
otdfctl policy registered-resources list --search document
```

Sort registered resources by name ascending:

```shell
otdfctl policy registered-resources list --sort name --order asc
```
