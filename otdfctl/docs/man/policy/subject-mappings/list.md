---
title: List subject mappings
command:
  name: list
  aliases:
    - l
  flags:
    - name: namespace
      shorthand: n
      description: Namespace ID or FQN to filter results
    - name: limit
      shorthand: l
      description: Limit retrieved count
    - name: offset
      shorthand: o
      description: Offset (page) quantity from start of the list
    - name: sort
      description: Sort list results by field
    - name: order
      description: Sort order direction. Accepted values are asc and desc
---

For more information about subject mappings, see the `subject-mappings` subcommand.

## Sort Options

Use `--sort <field>` with optional `--order <direction>`. Either flag may be omitted.

| Direction | Description | Default |
| --- | --- | --- |
| `asc` | Ascending order | No |
| `desc` | Descending order | Yes |

| Field | Description | Default |
| --- | --- | --- |
| `created_at` | Creation timestamp | Yes |
| `updated_at` | Last update timestamp | No |

Omit direction and let the server choose the default direction:

```shell
otdfctl policy subject-mappings list --sort created_at
```

Omit field and let the server choose the default field:

```shell
otdfctl policy subject-mappings list --order asc
```

## Example

```shell
otdfctl policy subject-mappings list

otdfctl policy subject-mappings list --namespace "https://example.com"
```

Sort subject mappings by creation time ascending:

```shell
otdfctl policy subject-mappings list --sort created_at --order asc
```
