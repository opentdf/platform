---
title: Delete a Key Access Server registration
command:
  name: delete
  flags:
    - name: id
      shorthand: i
      description: ID of the Key Access Server registration
      required: true
    - name: force
      description: Force deletion without interactive confirmation (dangerous)
---

Removes knowledge of a KAS (registration) from a platform's policy.

If resource data has been TDFd utilizing key splits from the registered KAS, deletion from
the registry (and therefore any associated grants) may prevent decryption depending on the
type of grants and relevant key splits.

Make sure you know what you are doing.

For more information about registration of Key Access Servers, see the manual for `kas-registry`.

## Example 

```shell
otdfctl policy kas-registry delete --id 3c39618a-cd8c-48cf-a60c-e8a2f4be4dd5
```
