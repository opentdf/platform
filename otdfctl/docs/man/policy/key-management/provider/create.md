---
title: Create a Provider Config
command:
  name: create
  aliases:
    - c
  flags:
    - name: name
      shorthand: n
      description: Name of the provider config to create
      required: true
    - name: manager
      shorthand: m
      description: Key Manager for the provider config
      required: true
    - name: config
      shorthand: c
      description: JSON configuration for the provider
      required: true
    - name: label
      shorthand: l
      description: Metadata labels for the provider config
---

Creates a new provider config with the specified name and configuration.

## Examples

```shell
otdfctl keymanagement provider create --name <name> --config <json-config>
```

```shell
otdfctl keymanagement provider create --name aws --config `{"region": "us-west-2"}`
```
