---
title: Clear credentials from profile

command:
  name: logout
---


> [!NOTE]
> Requires experimental profiles feature.
>
> | OS | Keychain | State |
> | --- | --- | --- |
> | MacOS | Keychain | Stable |
> | Windows | Credential Manager | Alpha |
> | Linux | Secret Service | Not yet supported |

Removes any auth credentials (Client Credentials or an Access Token from a login)
from the current profile.
