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
      description: Sort list results by field
    - name: order
      description: Sort order direction. Accepted values are asc and desc
---

For more information about registration of Key Access Servers, see the manual for `kas-registry`.

## Sort Options

Use `--sort <field>` with optional `--order <direction>`. Either flag may be omitted.

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
otdfctl policy kas-registry list --sort name
```

Omit field and let the server choose the default field:

```shell
otdfctl policy kas-registry list --order asc
```

## Example

```shell
otdfctl policy kas-registry list
```

Sort KAS registrations by URI descending:

```shell
otdfctl policy kas-registry list --sort uri --order desc
```
