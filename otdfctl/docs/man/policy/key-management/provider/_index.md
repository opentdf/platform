---
title: Provider configuration for Key Management

command:
  name: provider
  aliases:
    - p
---

Commands used for managing a key providers configuration. You should register key providers when creating keys where the key is either:

1. Wrapped by a key stored outside of your KAS server. For example. if you created a key that is of `mode``provider`
2. The actual wrapped key is not stored within the platform database, but a reference to the key is. For example, if you created a key that is of `mode` `remote`.

**You should not** create provider configurations for keys of mode:

- `local`
- `public_key`
