# Auth Package

This package handles authentication (authn) and authorization (authz) for the OpenTDF platform.

## Package Structure

```
auth/
├── authn.go           # Authentication middleware and token validation
├── connect_gate.go    # Connect request gate that authenticates before body decoding
├── connect_v2.go      # connect-go v2 authentication, authorization, and IPC interceptors
├── config.go          # Configuration types
├── discovery.go       # OIDC discovery
└── authz/             # Authorization interfaces and implementations
    ├── authorizer.go  # Authorizer interface and factory
    ├── resolver.go    # Resolver registry and resource dimension context
    └── casbin/        # Casbin authorizers
        ├── v1/        # Legacy path + action authorization
        └── v2/        # RPC + dimensions authorization
```

## Connect Request Flow

The platform serves services registered with a connect-go v1 handler and services registered on a connect-go v2 server. Both authenticate from the request headers before the body is read.

External requests to connect-go v1 services pass through these stages:

1. The HTTP router stores the request's HTTP method in the context (`ContextWithHTTPMethod`).
2. `ConnectAuthNRequestGate` authenticates the request from its headers, including DPoP proof validation, before Connect reads, decompresses, or unmarshals the body. Unauthenticated requests are rejected without decoding the body.
3. `ConnectAuthNInterceptor` sets `DPoP-Nonce` response headers when nonces are required. It authenticates only when the gate did not run, such as for handlers built outside the platform server.
4. `ConnectAuthZInterceptor` authorizes the request. Unary authorization may read the decoded message through resource resolvers.

Requests rejected by the gate never reach the interceptor chain, so tracing interceptors record no span for them.

External requests to connect-go v2 services pass through these stages:

1. `ConnectAuthNInterceptorV2` authenticates the request from its headers. connect-go v2 runs server interceptors before it reads the body, so no gate is needed, and the interceptor reads the HTTP method from the call. It sets `DPoP-Nonce` and DPoP challenge headers on the response.
2. `ConnectAuthZInterceptorV2` authorizes the request. For a unary procedure with a resource resolver it receives the request message first, runs the resolver, and passes the same message to the handler. Every other request is authorized before the body is read.

Rejections from the v2 interceptors pass through the tracing interceptor, so they are recorded, and gRPC clients receive the DPoP challenge headers.

The in-process (IPC) server uses neither gate nor external authentication; `IPCUnaryServerInterceptor` and `IPCServerInterceptorV2` handle its requests.

## Authz v1

Authz v1 is the legacy Casbin model. Its policy rows have four fields:

```csv
p, subject, resource, action, effect
```

The enforcement request is `(subject, resource, action)`. For Connect/gRPC requests, `resource` is the RPC procedure path normalized for v1 policy compatibility: gRPC-style resources omit the leading slash, while HTTP paths keep it. The `action` field matches the policy action column, typically `read`, `write`, `delete`, `unsafe`, or `*`.

## Authz v2

Authz v2 is the Casbin RPC + dimensions model. It authorizes `(subject, rpc, dimensions)`:

- `subject`: extracted from JWT roles, client ID, and username. Roles and clients are typed as `role:<name>` and `client:<id>`.
- `rpc`: full Connect/gRPC procedure path such as `/policy.kasregistry.KeyAccessServerRegistryService/GetKey`.
- `dimensions`: a serialized `ResolverContext` resource such as `kas_uri=https://kas-a.example.com`, or `*` when no dimensions are available.

The interceptor calls a service-registered resolver only when the selected authorizer supports resource authorization. If no resolver is registered for the RPC, v2 evaluates the request with wildcard dimensions (`*`). Policies that require a concrete dimension then deny; policies using wildcard dimensions may still allow.

Services register resolvers through their scoped `ScopedResolverRegistry` during service startup. A resolver may return one or more resources, and every non-empty resource must be allowed for the request to pass.

### Moving From Authz v1 to v2 Policy

When moving policy from v1 to v2:

- Change policy rows from `p, subject, resource, action, effect` to `p, subject, rpc, dimensions, effect`.
- Use the full Connect/gRPC RPC path in the `rpc` column, including the leading slash, for example `/policy.kasregistry.KeyAccessServerRegistryService/GetKey`.
- Remove the separate action column. In v2, the RPC method represents the operation.
- Use `*` for dimensions when the policy is only subject/RPC scoped.
- Use concrete dimensions only for RPCs with registered resolvers. Today, `GetKey` and `ListKeys` can use `kas_uri=<value>`.

For example, a v1 read rule:

```csv
p, role:standard, kasregistry.*, read, allow
```

becomes a v2 RPC-scoped rule:

```csv
p, role:standard, /policy.kasregistry.KeyAccessServerRegistryService/Get*, *, allow
```

and a v2 dimension-scoped `GetKey` rule:

```csv
p, role:kas-reader, /policy.kasregistry.KeyAccessServerRegistryService/GetKey, kas_uri=https://kas.example.com, allow
```

### Current v2 Dimension Coverage

The table lists production resolver coverage in this workspace. The v2 authorizer supports arbitrary dimension keys supplied by resolvers, but only the RPCs below currently have registered production resolvers.

| RPC | Available dimensions |
| --- | --- |
| `/policy.kasregistry.KeyAccessServerRegistryService/GetKey` | `kas_uri` |
| `/policy.kasregistry.KeyAccessServerRegistryService/ListKeys` | `kas_uri` |
| All other RPCs | none (`*`) |

### Streaming and Bidi RPCs

The Connect authN and authz interceptors cover unary, streaming, and bidi RPCs. A
streaming RPC is authenticated and authorized once, at stream establishment, before the
handler runs.

Because no request message is available at establishment, resource-dimension resolvers
cannot run for streams. Streaming authorization is therefore **procedure-level only**: the
enforcement request always uses wildcard dimensions (`*`). As a result, a dimension-scoped
v2 policy row (one that requires a concrete dimension such as `kas_uri=...`) never matches
a stream, so dimension-scoped policy **fails closed** for streaming RPCs. To authorize a
stream, grant it with a wildcard-dimension rule. This mirrors the raw-HTTP `MuxHandler`
path, which is likewise procedure-level.

### KAS URI Policy Encoding

When writing `kas_uri` dimension values in v2 Casbin policy, encode only the characters that conflict with dimension parsing:

- `%` -> `%25`
- `&` -> `%26`
- literal `*` -> `%2A` (Only if you want to match exactly on `*`)

Other URI characters such as `:`, `/`, `?`, `=`, and `+` can stay readable. For example, a KAS URI with query parameters should encode the query separator `&` in policy:

```csv
p, role:kas-reader, /policy.kasregistry.KeyAccessServerRegistryService/GetKey, kas_uri=https://kas.example.com?foo=bar%26baz=qux, allow
```

> [!NOTE]
> This escaping only covers authz v2 dimension parsing. Policy rows are still Casbin CSV, so if a URI contains a literal comma, quote the policy field using valid CSV/Casbin syntax. Quotes and newlines should not appear unescaped in valid KAS URIs.

The embedded v2 [default policy](https://github.com/opentdf/platform/blob/8702ac1760ba0952f3e6876dd733d7a20c9438cc/service/internal/auth/authz/casbin/v2/policy.csv) grants:

- `role:admin` full access.
- `role:standard` read access to policy `Get*`, `List*`, and `Match*` RPCs, access to KAS, health, discovery, and authorization services.
- `role:unknown` access to `/kas.AccessService/Rewrap`.

## Security Guidelines

### Never Log Sensitive Authentication Data

**DO NOT log the following:**

1. **JWT Tokens** - Never log full tokens, even at DEBUG level
   - Tokens can be replayed if logs are compromised
   - Tokens may contain PII in claims
   - Large tokens can be used for DoS attacks (disk/memory exhaustion)
   - Unsanitized token content can enable log injection attacks

2. **Credentials** - Never log passwords, API keys, or secrets

3. **Full UserInfo responses** - May contain PII

**Safe to log:**
- Claim names (e.g., which claim was missing)
- Extracted role/group names (after validation)
- Subject identifiers (if not sensitive in your context)
- Error types and messages (without embedding tokens)

### Example: What NOT to do

```go
// BAD - logs full token (security risk)
e.logger.Debug("processing token", slog.Any("token", token))

// BAD - token in error message
e.logger.Error("auth failed", slog.String("token", tokenString))
```

### Example: Safe logging

```go
// GOOD - no sensitive data
e.logger.Debug("extracting roles from token")

// GOOD - only logs claim name, not value
e.logger.Warn("claim not found", slog.String("claim", claimName))

// GOOD - logs extracted, bounded data
e.logger.Debug("roles extracted", slog.Int("count", len(roles)))
```

### Log Injection Prevention

Even when logging "safe" data extracted from tokens, be aware that:
- Claims can contain newlines (fake log entries)
- Claims can contain ANSI escape codes
- Claims can be arbitrarily large

Consider truncating or sanitizing any user-controlled data before logging.
