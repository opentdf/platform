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
    - name: search
      description: Search term to filter results
    - name: sort
      description: Sort list results by field
    - name: order
      description: Sort order direction. Accepted values are asc and desc
---

For more general information, see the `namespaces` subcommand.

## Search Fields

The `--search` term is trimmed and matched as a substring against these values:

| Value | Description |
| --- | --- |
| Namespace FQN | Fully qualified namespace name, such as `https://example.com` |

## Sort Options

Use `--sort <field>` with optional `--order <direction>`. Either flag may be omitted.

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
otdfctl policy namespaces list --sort name
```

Omit field and let the server choose the default field:

```shell
otdfctl policy namespaces list --order asc
```

## Example

```shell
otdfctl policy namespaces list
```

Search namespaces by FQN:

```shell
otdfctl policy namespaces list --search example.com
```

Sort namespaces by name ascending:

```shell
otdfctl policy namespaces list --sort name --order asc
```
