---
title: Open a browser and login

command:
  name: login
  flags:
    - name: client-id
      description: A clientId for a public (no-secret) IdP client supporting the auth code flow from any localhost port (e.g. cli-client)
      shorthand: i
      required: true
    - name: port
      description: A preferred port number to faciliate the auth flow process.
      shorthand: p
      required: false
---

> [!NOTE]
> Requires experimental profiles feature.
>
> | OS | Keychain | State |
> | --- | --- | --- |
> | MacOS | Keychain | Stable |
> | Windows | Credential Manager | Alpha |
> | Linux | Secret Service | Not yet supported |

Authenticate for use of the OpenTDF Platform through a browser (required).

Provide a specific public 'client-id' known to support the Auth Code PKCE flow and recognized
by the OpenTDF Platform (e.g. `cli-client`).

The OIDC Access Token will be stored in the OS-specific keychain by default (Linux not yet supported).
