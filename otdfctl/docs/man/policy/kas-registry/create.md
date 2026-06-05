---
title: Create a Key Access Server registration
command:
  name: create
  aliases:
    - c
    - add
    - new
  flags:
    - name: uri
      shorthand: u
      description: URI of the Key Access Server
      required: true
    - name: public-keys 
      shorthand: c
      description: "(Deprecated: Use otdfctl policy kas-registry keys) One or more public keys saved for the KAS"
    - name: public-key-remote
      shorthand: r
      description: "(Deprecated: Use otdfctl policy kas-registry keys) Remote URI where the public key can be retrieved for the KAS"
    - name: label
    - name: name
      shorthand: n
      description: Optional name of the registered KAS (must be unique within Policy)
    - name: label
      description: "Optional metadata 'labels' in the format: key=value"
      shorthand: l
      default: ''
---

## Examples

```shell
otdfctl policy kas-registry create --uri http://example.com/kas --name example-kas
```
