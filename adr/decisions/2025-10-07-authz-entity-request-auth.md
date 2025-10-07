---
status: 'proposed'
date: '2025-10-07'
tags:
 - authorization
driver: '@jakedoublev'
consulted:
  - '@jrschumacher'
  - '@c-r33d'
---
# Allow Authz GetDecision/GetEntitlements requests to derive entity from request authorization token JWT

## Context and Problem Statement

Today, Authorization endpoints require entity specification on the request body, including one of a
`Token` option, a `RegisteredResourceFQN` option, or an `EntityChain` option.

In our SDKs, we prefer client-side interceptors to populate auth state within authenticated requests.

When adding SDK support for a TDF `.Obligations()` method, it was realized we would need to add auth logic inside
each SDK method itself (not their interceptors) to retrieve a valid access token and set it to a `GetDecision` request
body as a `Token` entity. We had not exposed the ability serverside to check the request authorization token _as_ the entity
in a decision/entitlements request, and would need to do more work clientside as a result.

## Decision Drivers

* Reduced SDK logic:
    - avoids roundtripping for an access token from the idP twice (once to auth the request, once to place in the body)
    - avoids complexity in the interceptors (check if we've already retrieved a token first, etc.)
* Improved DX/UX:
    - effectively GetMyEntitlements, GetMyDecision
* Security:
    - fewer access tokens retrieved by an SDK instance

## Considered Options

* **Option 1**: Get an Access Token outside the interceptor from the OAuth token source for request body entity _and_ another within the interceptor (two tokens retrieved)
* **Option 2**: Get an Access Token outside the interceptor from the OAuth token source for request body entity _and_ reuse within interceptor (one token retrieved)
* **Option 3**: Improve Authz endpoints to allow explicitly using the auth header token as the entity

## Decision Outcome

Chosen option: **Option 3**: Improve Authz endpoints to allow explicitly using the auth header token as the entity

### Consequences

* 🟩 **Good**, because better API UX/DX for use cases where a PEP auth == user auth
* 🟩 **Good**, because keeps token handling logic in SDKs centralized
* 🟩 **Good**, because simplified Obligations decision check flow
* 🟩 **Good**, because explicit flag on request avoids footguns in super-privileged PEPs
* 🟨 **Neutral**, because more complexity in a oneof proto, but there are 4 types of entities/entity sources
