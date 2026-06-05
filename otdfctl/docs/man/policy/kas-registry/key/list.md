---
title: List Keys
command:
  name: list
  aliases:
    - l
  flags:
    - name: limit
      shorthand: l
      description: Maximum number of keys to return
      required: true
    - name: offset
      shorthand: o
      description: Number of keys to skip before starting to return results
      required: true
    - name: algorithm
      shorthand: a
      description: Key Algorithm to filter for
    - name: kas
      description: Specify the Key Access Server (KAS) where the key (identified by `--key`) is registered. The KAS can be identified by its ID, URI, or Name.
    - name: legacy
      description: Filter keys by legacy status.
      required: false
    - name: sort
      description: Sort list results by field
    - name: order
      description: Sort order direction. Accepted values are asc and desc
---

This command lists keys registered within a specified Key Access Server (KAS). You must specify the KAS using its ID, URI, or Name.

The list can be filtered by key algorithm. Pagination is supported using `limit` and `offset` flags to manage the number of results returned.

## Sort Options

Use `--sort <field>` with optional `--order <direction>`. Either flag may be omitted.

| Direction | Description | Default |
| --- | --- | --- |
| `asc` | Ascending order | No |
| `desc` | Descending order | Yes |

| Field | Description | Default |
| --- | --- | --- |
| `key_id` | Key ID | No |
| `created_at` | Creation timestamp | Yes |
| `updated_at` | Last update timestamp | No |

Omit direction and let the server choose the default direction:

```shell
otdfctl policy kas-registry key list --kas "https://kas.example.com/kas" --sort key_id
```

Omit field and let the server choose the default field:

```shell
otdfctl policy kas-registry key list --kas "https://kas.example.com/kas" --order asc
```

## Examples

List the first 10 keys from a KAS specified by its URI:

```shell
otdfctl policy kas-registry key list --kas "https://kas.example.com/kas" --limit 10 --offset 0
```

List keys from a KAS named "Primary KAS", filtering for keys using the "RSA:2048" algorithm, and output in JSON format:

```shell
otdfctl policy kas-registry key list --kas "Primary KAS" --alg "RSA:2048" --limit 20 --offset 0 --json
```

List the next 5 keys (skipping the first 5) from a KAS identified by its ID:

```shell
otdfctl policy kas-registry key list --kas "kas-id-12345" --limit 5 --offset 5
```

List only legacy keys

```shell
otdfctl policy kas-registry key list --legacy true
```

Exclude legacy keys

```shell
otdfctl policy kas-registry key list --legacy false
```

Sort keys by key ID descending:

```shell
otdfctl policy kas-registry key list --kas "https://kas.example.com/kas" --sort key_id --order desc
```
