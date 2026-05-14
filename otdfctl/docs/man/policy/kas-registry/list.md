---
title: List Key Access Server registrations
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
    - name: sort
      description: Sort list results with field:direction syntax. Either field or direction may be omitted
---

For more information about registration of Key Access Servers, see the manual for `kas-registry`.

## Sort Options

Use `--sort <field>:<direction>`. Either side may be omitted, for example `name:` or `:asc`.

| Direction | Description | Default |
| --- | --- | --- |
| `asc` | Ascending order | No |
| `desc` | Descending order | Yes |

| Field | Description | Default |
| --- | --- | --- |
| `name` | KAS registration name | No |
| `uri` | KAS URI | No |
| `created_at` | Creation timestamp | Yes |
| `updated_at` | Last update timestamp | No |

Omit direction and let the server choose the default direction:

```shell
otdfctl policy kas-registry list --sort name:
```

Omit field and let the server choose the default field:

```shell
otdfctl policy kas-registry list --sort :asc
```

## Example

```shell
otdfctl policy kas-registry list
```

Sort KAS registrations by URI descending:

```shell
otdfctl policy kas-registry list --sort uri:desc
```
