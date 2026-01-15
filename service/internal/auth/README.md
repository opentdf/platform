# Auth Package

This package handles authentication (authn) and authorization (authz) for the OpenTDF platform.

## Package Structure

```
auth/
├── authn.go           # Authentication middleware and token validation
├── casbin.go          # V1 Casbin enforcer (legacy, path-based authz)
├── config.go          # Configuration types
├── discovery.go       # OIDC discovery
└── authz/             # V2 authorization system
    ├── authorizer.go  # Authorizer interface and factory
    ├── resolver.go    # AuthzResolver for fine-grained resource authorization
    └── casbin/        # V2 Casbin implementation with multi-claim support
```

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

## V1 vs V2 Authorization

- **V1** (`casbin.go`): Legacy path-based authorization using `(subject, resource, action)`
- **V2** (`authz/casbin/`): RPC + dimensions authorization using `(subject, rpc, dimensions)` with support for fine-grained resource authorization via `AuthzResolver`

V1 is being maintained for backward compatibility. New features should use V2.
