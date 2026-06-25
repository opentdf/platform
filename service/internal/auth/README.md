# Auth Package

This package handles authentication (authn) and authorization (authz) for the OpenTDF platform.

## Package Structure

```
auth/
├── authn.go           # Authentication middleware and token validation
├── config.go          # Configuration types
├── discovery.go       # OIDC discovery
└── authz/             # Authorization interfaces and implementations
    ├── authorizer.go  # Authorizer interface and factory
    ├── resolver.go    # Resolver registry and resource dimension context
    └── casbin/        # Casbin authorizers
        ├── v1/        # Legacy path + action authorization
        └── v2/        # RPC + dimensions authorization
```

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

Services register resolvers through their scoped `AuthzResolverRegistry` during service startup. A resolver may return one or more resources, and every non-empty resource must be allowed for the request to pass.

### Current v2 Dimension Coverage

The table lists production resolver coverage in this workspace. The v2 authorizer supports arbitrary dimension keys supplied by resolvers, but only the RPC below currently has a registered production resolver.

| RPC | Available dimensions |
| --- | --- |
| `/policy.kasregistry.KeyAccessServerRegistryService/GetKey` | `kas_uri` |
| All other RPCs | none (`*`) |

### KAS URI Policy Encoding

When writing `kas_uri` dimension values in v2 Casbin policy, encode only the characters that conflict with dimension parsing:

- `%` -> `%25`
- `&` -> `%26`
- literal `*` -> `%2A` (Only if you want to match exactly on `*`)

Other URI characters such as `:`, `/`, `?`, `=`, and `+` can stay readable. For example, a KAS URI with query parameters should encode the query separator `&` in policy:

```csv
p, role:kas-reader, /policy.kasregistry.KeyAccessServerRegistryService/GetKey, kas_uri=https://kas.example.com?foo=bar%26baz=qux, allow
```

The embedded v2 default policy grants:

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
