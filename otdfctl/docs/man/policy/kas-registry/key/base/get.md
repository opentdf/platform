---
title: Get Base Key
command:
  name: get
  aliases:
    - g
---

Command for retrieving information about the currently configured platform base key. This key is used for encryption operations when no attributes are present or when attributes lack associated keys.

The command will display details such as the key's identifier (KeyID or UUID) and the Key Access Server (KAS) it is registered with.

## Examples

Retrieve the platform base key information in the default (human-readable) format:
```
otdfctl policy kas-registry key base get
```
