---
title: List Subject Condition Set

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

For more information about subject condition sets, see the `subject-condition-sets` subcommand.

## Search Fields

The `--search` term is trimmed and matched as a substring against these values:

| Value | Description |
| --- | --- |
| Metadata label values | Values under subject condition set metadata `labels` |

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
otdfctl policy subject-condition-sets list --sort created_at
```

Omit field and let the server choose the default field:

```shell
otdfctl policy subject-condition-sets list --order asc
```

## Example

```shell
otdfctl policy subject-condition-sets list

otdfctl policy subject-condition-sets list --namespace https://example.com
```

Search subject condition sets by metadata label value:

```shell
otdfctl policy subject-condition-sets list --search engineering
```

Sort subject condition sets by creation time ascending:

```shell
otdfctl policy subject-condition-sets list --sort created_at --order asc
```
