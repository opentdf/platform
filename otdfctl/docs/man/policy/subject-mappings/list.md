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
      description: Sort list results with field:direction syntax. Either field or direction may be omitted
---

For more information about subject mappings, see the `subject-mappings` subcommand.

## Sort Options

Use `--sort <field>:<direction>`. Either side may be omitted, for example `created_at:` or `:asc`.

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
otdfctl policy subject-mappings list --sort created_at:
```

Omit field and let the server choose the default field:

```shell
otdfctl policy subject-mappings list --sort :asc
```

## Example

```shell
otdfctl policy subject-mappings list

otdfctl policy subject-mappings list --namespace "https://example.com"
```

Sort subject mappings by creation time ascending:

```shell
otdfctl policy subject-mappings list --sort created_at:asc
```
