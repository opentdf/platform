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
    - name: search
      description: Search term to filter results
    - name: sort
      description: Sort list results by field
    - name: order
      description: Sort order direction. Accepted values are asc and desc
---

For more information about subject mappings, see the `subject-mappings` subcommand.

## Search Fields

The `--search` term is trimmed and matched as a substring against these values:

| Value | Description |
| --- | --- |
| Attribute value FQN | Fully qualified mapped attribute value, such as `https://example.com/attr/classification/value/public` |
| Metadata label values | Values under subject mapping metadata `labels` |

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

Search subject mappings by mapped attribute value FQN or metadata label value:

```shell
otdfctl policy subject-mappings list --search public
```

Sort subject mappings by creation time ascending:

```shell
otdfctl policy subject-mappings list --sort created_at --order asc
```
