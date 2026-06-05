---
title: Authenticate to the platform with the client-credentials flow

command:
  name: client-credentials
  args: 
    - client-id
  arbitrary_args:
    - client-secret
  flags:
    - name: scopes
      description: OIDC scopes to request (space-separated).
---

> [!NOTE]
> Requires experimental profiles feature.
>
> | OS | Keychain | State |
> | --- | --- | --- |
> | MacOS | Keychain | Stable |
> | Windows | Credential Manager | Alpha |
> | Linux | Secret Service | Not yet supported |

Allows the user to login in via Client Credentials flow. The client credentials will be stored safely
in the OS keyring for future use.

## Examples

Authenticate with client credentials (id and secret provided interactively)

```shell
otdfctl auth client-credentials
```

Authenticate with client credentials (secret provided interactively)

```shell
otdfctl auth client-credentials <client-id>
```

Authenticate with client credentials (secret provided as argument)

```shell
otdfctl auth client-credentials <client-id> <client-secret>
```

Authenticate with client credentials and explicit scopes

```shell
otdfctl auth client-credentials <client-id> <client-secret> --scopes "api:access:read api:access:write"
```
