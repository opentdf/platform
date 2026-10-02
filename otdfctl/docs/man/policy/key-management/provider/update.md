---
title: Update a Provider Config
command:
  name: update
  aliases:
    - u
  flags:
    - name: id
      shorthand: i
      description: ID of the provider config to update
      required: true
    - name: name
      shorthand: n
      description: New name for the provider config
    - name: manager
      shorthand: m
      description: New key manager for the provider config
    - name: config
      shorthand: c
      description: New JSON configuration for the provider
    - name: label
      shorthand: l
      description: Metadata labels for the provider config
---

Updates an existing provider config with the specified parameters.

## Examples

```shell
otdfctl keymanagement provider update --id <id> --name <new-name> --config <new-json-config>
```

```shell
otdfctl keymanagement provider update --id '04ba179c-2f77-4e0d-90c5-fe4d1c9aa3f7' --name 'gcp' --config `{"region": "us-west-2"}`
```
