---
title: Print the cached OIDC access token (if found)

command:
  name: print-access-token
  flags:
    - name: json
      description: Print the full token in JSON format
      default: false
---

> [!NOTE]
> Requires experimental profiles feature.
>
> | OS | Keychain | State |
> | --- | --- | --- |
> | MacOS | Keychain | Stable |
> | Windows | Credential Manager | Alpha |
> | Linux | Secret Service | Not yet supported |

Retrieves a new OIDC Access Token using the client credentials and prints to stdout if found.
