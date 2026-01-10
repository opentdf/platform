# Resource-Level Authorization Specification

**Status:** WIP / Draft
**Authors:** Platform Team
**Created:** 2024-12-30
**Last Updated:** 2025-01-02

## Problem Statement

The current authorization system uses **path-based RBAC** via Casbin, where policies match on gRPC method paths and HTTP routes. This provides coarse-grained access control (e.g., "admins can access all policy endpoints") but lacks the ability to enforce **resource-level permissions** (e.g., "user A can only modify attributes in namespace X").

### Current State (v1)

```
Model: (subject, resource, action)
       where resource = gRPC path pattern (e.g., "policy.attributes.AttributesService/*")
       and subject = roles extracted from JWT claims
```

### Desired State (v2)

```
Model: (subject, rpc, dimensions)
       where:
         - rpc = full gRPC method path (e.g., "/policy.attributes.AttributesService/UpdateAttribute")
         - dimensions = service-specific key-value pairs (e.g., {"namespace": "hr", "attribute": "classification"})
       The RPC method itself implies the action (Get* = read, Update* = write, etc.)
```

## Goals

1. **Namespace-scoped authorization** - Restrict users to resources within specific namespaces
2. **Governance & auditability** - Authorization decisions are logged with full context for compliance
3. **Developer experience** - Service maintainers have clear patterns for implementing authorization
4. **Extensibility** - Architecture supports future instance-level authorization
5. **Backwards compatibility** - Existing path-based policies continue to work

## Non-Goals (v1)

1. Instance-level authorization (user A can edit attribute X but not Y) - future consideration
2. Real-time policy updates without restart
3. External PDP integration (OPA, Cedar, etc.) - future consideration

---

## Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Request Flow                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Client Request                                                              │
│       │                                                                      │
│       ▼                                                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     ConnectRPC Interceptor                           │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │ 1. Extract JWT claims → subject (roles, username)           │    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │ 2. Call service resolver → AuthzContext{dimensions: {...}}  │    │    │
│  │  │    (IoC / "Hollywood Principle" - framework calls service)  │    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │ 3. Enforce → Casbin(sub, type, action, serialized_dims)     │    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│       │                                                                      │
│       ▼ (if allowed)                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                        Service Handler                               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Owner | Responsibility |
|-----------|-------|----------------|
| AuthzContext | Platform | Contract struct between resolvers and enforcer |
| Interceptor | Platform | Orchestrates the authorization flow |
| Resolver Interface | Platform | Defines the hook contract |
| Resolver Implementation | Service | Enriches context with resource relationships |
| Casbin Model | Platform | Defines policy matching dimensions |
| Casbin Policies | Deployer | Configures actual access rules |

---

## Implementation Concepts

### 1. ResolverContext (Platform-Owned Contract)

```go
// service/internal/auth/authz/resolver.go

// ResolverResource represents a single resource's authorization dimensions.
// Each key-value pair is a dimension (e.g., "namespace" -> "hr").
type ResolverResource map[string]string

// ResolverContext holds the resolved authorization context for a request.
// Multiple resources are supported for operations like "move from A to B"
// where authorization is required for both source and destination.
type ResolverContext struct {
    Resources []*ResolverResource
}

// Key methods:
// - NewResolverContext() - creates empty context
// - NewResource() *ResolverResource - adds and returns a new resource
// - AddDimension(key, value string) - adds dimension to a resource
```

### 2. Resolver Interface (Platform-Owned)

```go
// service/internal/auth/authz/resolver.go

// ResolverFunc is the function signature for service-provided resolvers.
// Services implement this to extract authorization dimensions from requests.
//
// Parameters:
//   - ctx: Request context (includes auth info, can be used for DB calls)
//   - req: The connect request (use type assertion to get typed proto)
//
// Returns:
//   - ResolverContext with populated dimensions
//   - Error if resolution fails (results in 403)
type ResolverFunc func(ctx context.Context, req connect.AnyRequest) (ResolverContext, error)

// ResolverRegistry holds resolver functions keyed by service method.
// Thread-safe for concurrent read/write access.
type ResolverRegistry struct {
    resolvers map[string]ResolverFunc // full method path -> resolver
}

// ScopedResolverRegistry provides a namespace-scoped view of the registry.
// Validates method ownership against ServiceDesc to prevent cross-service registration.
type ScopedResolverRegistry struct {
    parent      *ResolverRegistry
    serviceDesc grpc.ServiceDesc
}
```

### 3. Service Resolver Implementation (Service-Owned)

Service maintainers implement resolvers as methods on their service struct. Each method
handles one RPC and extracts dimensions from the request (with DB lookups as needed).

**Implementation pattern (from service/policy/attributes/attributes.go):**

```go
// updateAttributeAuthzResolver resolves namespace from attribute lookup.
func (s *AttributesService) updateAttributeAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
    resolverCtx := authz.NewResolverContext()
    msg, ok := req.Any().(*attributes.UpdateAttributeRequest)
    if !ok {
        return resolverCtx, fmt.Errorf("unexpected request type: %T", req.Any())
    }

    // DB lookup to resolve attribute -> namespace relationship
    attr, err := s.dbClient.GetAttribute(ctx, msg.GetId())
    if err != nil {
        return resolverCtx, fmt.Errorf("failed to resolve attribute for authz: %w", err)
    }

    // Populate dimensions
    res := resolverCtx.NewResource()
    res.AddDimension("namespace", attr.GetNamespace().GetName())
    res.AddDimension("attribute", attr.GetName())

    return resolverCtx, nil
}
```

**Different services use different dimensions:**

| Service | Typical Dimensions |
|---------|-------------------|
| Policy (attributes, namespaces) | `namespace`, `attribute` |
| KAS | `kas_id` |
| Authorization | (service-specific) |

### 4. Service Registration (Service-Owned)

Services register their resolvers during service startup via `RegistrationParams.AuthzResolverRegistry`:

```go
// In service registration (service/policy/attributes/attributes.go)
RegisterFunc: func(srp serviceregistry.RegistrationParams) {
    // ... service setup ...

    // Register authz resolvers per-method
    if srp.AuthzResolverRegistry != nil {
        srp.AuthzResolverRegistry.MustRegister("CreateAttribute", as.createAttributeAuthzResolver)
        srp.AuthzResolverRegistry.MustRegister("GetAttribute", as.getAttributeAuthzResolver)
        srp.AuthzResolverRegistry.MustRegister("GetAttributeValuesByFqns", as.getAttributeValuesByFqnsAuthzResolver)
        srp.AuthzResolverRegistry.MustRegister("ListAttributes", as.listAttributesAuthzResolver)
        srp.AuthzResolverRegistry.MustRegister("UpdateAttribute", as.updateAttributeAuthzResolver)
        srp.AuthzResolverRegistry.MustRegister("DeactivateAttribute", as.deactivateAttributeAuthzResolver)
    }
}
```

The `ScopedResolverRegistry` validates that method names match the service's `ServiceDesc`.

### 5. Casbin Model (Platform-Owned)

The v2 Casbin model uses 3 fields: `(subject, rpc, dimensions)`. The RPC method path
itself implies the action, simplifying the model compared to v1's 4-field format.

```conf
# service/internal/auth/authz/casbin/model.conf

[request_definition]
# sub: subject (roles from JWT, or username)
# rpc: full gRPC method path (e.g., /policy.attributes.AttributesService/UpdateAttribute)
# dims: serialized key=value pairs, sorted by key (e.g., "namespace=hr&attribute=x")
r = sub, rpc, dims

[policy_definition]
# Same structure as request, with eft (effect) for allow/deny
p = sub, rpc, dims, eft

[role_definition]
g = _, _

[policy_effect]
# Allow if any policy explicitly allows AND no policy explicitly denies
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
# g(r.sub, p.sub): role/group membership check
# keyMatch(r.rpc, p.rpc): RPC path matching with wildcards
# dimensionMatch(r.dims, p.dims): custom function for dimension matching
m = g(r.sub, p.sub) && keyMatch(r.rpc, p.rpc) && dimensionMatch(r.dims, p.dims)
```

#### Dimension Matching

The platform provides a custom Casbin matcher function `dimensionMatch` that compares request dimensions (`map[string]string`) against policy dimensions (string format).

**Policy dimension format:**
- `*` - matches any dimensions (global wildcard)
- `key=value` - matches single dimension
- `key=value&key2=value2` - matches multiple dimensions (AND logic)
- `key=*` - matches any value for that key

**Matching rules:**
- All policy dimensions must be satisfied (AND logic)
- Policy can omit dimensions (partial match OK)
- OR logic is achieved via multiple policy lines

The matcher is registered with Casbin via `enforcer.AddFunction("dimensionMatch", ...)` during initialization.

### 6. Interceptor Flow (Platform-Owned)

The `ResourceAuthzInterceptor` orchestrates the authorization flow as a ConnectRPC interceptor:

```
1. Extract subject from JWT claims (e.g., "role:hr-admin")

2. Call service resolver to get AuthzContext
   └─ No resolver registered? Use empty dimensions (matches wildcard policies)
   └─ Resolution failure? Return 403 PermissionDenied

3. Enforce policy via Casbin:
   enforcer.Enforce(subject, resourceType, action, dimensions)

4. Log authorization decision (subject, resource, action, dimensions, allow/deny)

5. If allowed, proceed to handler; otherwise return 403
```

**Key behaviors:**
- No resolver registered = empty dimensions (matches wildcard policies)
- Resolver error = authorization failure (403)
- Falls back to path-based authorization for unannotated methods (backwards compat)

### 7. Example Policies (Deployer-Owned)

Policies use the new 4-position format: `(subject, resource_type, action, dimensions)`.
Dimensions use `&` as the AND delimiter (e.g., `namespace=hr&attr_id=123`).

```csv
# ====================================================================
# Policy Service - Namespace-scoped roles
# ====================================================================

# Finance admin: full access to finance namespace
p, role:finance-admin, policy.*, *, namespace=finance.com, allow

# HR admin: full access to hr namespace
p, role:hr-admin, policy.*, *, namespace=hr.io, allow

# Cross-namespace read-only auditor
p, role:auditor, policy.*, read, *, allow

# Standard role: read all namespaces, no write
p, role:standard, policy.*, read, *, allow

# Contractors cannot delete anything
p, role:contractor, policy.*, delete, *, deny

# ====================================================================
# KAS Service - KAS instance scoped roles
# ====================================================================

# KAS-1 admin: can manage KAS instance 1
p, role:kas1-admin, kas.*, *, kas_id=kas-1, allow

# KAS operator: read access to all KAS instances
p, role:kas-operator, kas.*, read, *, allow

# KAS rewrap permission for specific instance
p, role:kas1-rewrapper, kas.key, rewrap, kas_id=kas-1, allow

# ====================================================================
# Global roles (cross-service)
# ====================================================================

# Global admin: full access to everything
p, role:admin, *, *, *, allow

# ====================================================================
# Fine-grained policies (AND logic with &)
# ====================================================================

# Specific user: must match BOTH namespace AND attribute
p, user:alice@example.com, policy.attribute, write, namespace=hr&attribute=classification, allow

# Wildcard on specific dimension key
p, role:ns-reader, policy.namespace, read, namespace=*, allow

# ====================================================================
# OR logic via multiple policies
# ====================================================================

# User can access hr namespace OR finance namespace (two separate policies)
p, role:hr-or-finance, policy.attribute, read, namespace=hr, allow
p, role:hr-or-finance, policy.attribute, read, namespace=finance, allow
```

#### Policy Format Reference

| Format | Meaning |
|--------|---------|
| `*` | Match any value (global wildcard) |
| `namespace=hr` | Match only when namespace dimension is "hr" |
| `namespace=*` | Match any namespace value (but namespace must be present) |
| `namespace=hr&attribute=classification` | Match both dimensions (AND logic) |
| `policy.*` | Match any policy resource type (resource type wildcard) |
| Multiple policies with same subject | OR logic across policies |

---

## Maintainer Responsibilities

### Platform Maintainer

| Responsibility | Artifacts |
|----------------|-----------|
| Define ResolverContext contract | `service/internal/auth/authz/resolver.go` |
| Implement interceptor | `service/internal/auth/authn.go` (authorization flow) |
| Define authorizer interface | `service/internal/auth/authz/authorizer.go` |
| Maintain Casbin model | `service/internal/auth/authz/casbin/model.conf` |
| Documentation | Architecture docs, migration guides |

### Service Maintainer

| Responsibility | Artifacts |
|----------------|-----------|
| Implement resolver functions | Methods on service struct (e.g., `*AttributesService`) |
| Register resolvers at startup | In service `RegisterFunc` via `AuthzResolverRegistry.MustRegister()` |
| Unit test resolver logic | Service test file |

### Deployer / Operator

| Responsibility | Artifacts |
|----------------|-----------|
| Define Casbin policies | Config file or policy adapter |
| Map IdP roles to platform roles | Casbin `g` groupings |
| Monitor authorization denials | Logs, metrics |

---

## Governance & Auditability

### Runtime Audit Logging

All authorization decisions are logged with the serialized dimensions:

```json
{
  "level": "info",
  "msg": "authorization decision",
  "subject": "role:hr-admin",
  "resource_type": "policy.attribute",
  "action": "write",
  "dimensions": "attribute=classification;namespace=hr",
  "decision": "allow",
  "timestamp": "2024-12-30T12:00:00Z",
  "trace_id": "abc123",
  "method": "/policy.attributes.AttributesService/UpdateAttribute"
}
```

---

## Concerns & Mitigations

| Concern | Mitigation |
|---------|------------|
| **Performance**: DB lookups in resolver add latency | Caching layer in resolver; batch lookups where possible |
| **Complexity**: Service maintainers must implement resolvers | Provide base resolver implementations; clear patterns |
| **Consistency**: Resolvers could diverge in behavior | Platform-owned contract; integration tests |
| **Migration**: Existing policies use path-based model | Phased rollout; maintain backwards compatibility |
| **Testing**: Hard to test authorization in isolation | Mock resolver interface; provide test utilities |

---

## Decision Log

### Decided

| # | Decision | Rationale | Date |
|---|----------|-----------|------|
| D1 | Resolver follows IoC pattern (platform calls service) | Centralizes enforcement while allowing service-specific enrichment logic | 2024-12-30 |
| D2 | Dynamic dimensions via `map[string]string` | Different services have different resource hierarchies (policy uses namespace, KAS uses kas_id). Fixed fields would impose platform concepts on all services. | 2024-12-30 |
| D3 | Start with namespace-level granularity | Covers primary use case; instance-level can be added later | 2024-12-30 |
| D4 | Pass dimensions map directly to Casbin matcher | Avoids request-side serialization; custom matcher receives `map[string]string` directly and parses policy string; simpler code with lower complexity | 2025-01-02 |
| D5 | Use `&` as dimension AND delimiter in policies | Semantically correct (& means AND), visually distinct, enables future extensibility for `\|` OR logic within single policy line | 2025-01-02 |
| D6 | Resolver registration per-service namespace | Service maintainers register resolvers for each RPC in their service; `ScopedAuthzResolverRegistry` ensures services can only register for their own methods (validated against `ServiceDesc`) | 2025-01-02 |
| D7 | Empty resolver response treated as no dimensions | If no resolver is registered or resolver returns empty dimensions, Casbin evaluates with empty map. Policies expecting specific dimensions (non-wildcard) will deny; wildcard policies will allow. | 2025-01-02 |
| D8 | Multiple resources supported in single AuthzContext | `AuthzResolverContext.Resources` is a slice of `*AuthzResolverResource`, supporting operations like "move from A to B" that require authorization on multiple resources | 2025-01-02 |

### Open Questions

| # | Question | Options | Leaning | Notes |
|---|----------|---------|---------|-------|
| Q1 | How to handle List operations with post-filtering? | A) Check namespace in resolver, service filters results<br>B) Return all namespaces user can access<br>C) No authz on list, filter in service | TBD | Service maintainer responsibility. Risk: inconsistent implementations across services. |
| Q2 | How to test resolver implementations? | A) Provide mock DB client<br>B) Provide test harness<br>C) Integration tests only | TBD | DX concern |
| Q3 | Caching strategy for resolved namespaces? | A) Resolver owns caching<br>B) Platform provides cache to resolver<br>C) No caching initially | TBD | Platform has `CacheManager` available. Also consider DB client caching since successful authz will repeat the same query in the handler. |

### Future Considerations

| Topic | Notes |
|-------|-------|
| Proto annotations for schema definition | Could define annotations in proto files to enable governance tooling and documentation generation. Deferred. |
| Policy UI integration | Future work to provide UI for policy management |
| Governance tooling | Future work for permission matrix generation |

### Rejected Alternatives

| Alternative | Reason for Rejection |
|-------------|---------------------|
| Service-side explicit authz calls (no interceptor) | No centralized governance; easy to forget; inconsistent |
| Pure ABAC with CEL expressions | Too complex for v1; can revisit if needed |
| External PDP (OPA, Cedar) | Adds operational complexity; Casbin sufficient for v1 |
| Fixed-field AuthzContext (namespace, resource_id) | Different services have different resource hierarchies. "Namespace" is a policy concept but not KAS or authz service concept. Fixed fields impose platform-centric thinking on all services. |
| Positional Casbin model with fixed dimensions | Doesn't accommodate service-specific dimensions; would require model changes for each new dimension type |
| Semicolon (`;`) as dimension delimiter | Neutral semantically but less visually distinct; `&` implies AND logic correctly |
| Pipe (`\|`) as dimension delimiter | Semantically implies OR, which would be confusing since dimensions within a policy are AND conditions |
| Full request-side serialization | Unnecessary complexity; passing map directly to custom matcher is simpler |

---

## Migration Path

### Phase 1: Infrastructure (Platform)

1. Implement AuthzContext and resolver interface
2. Extend interceptor to support resource authorization
3. Update Casbin model to support new dimensions
4. Add fallback to path-based auth for methods without resolvers

### Phase 2: Pilot Service (Platform + Service)

1. Implement AttributeResolver for `policy.attributes` service
2. Write integration tests
3. Deploy to staging with permissive policies
4. Validate audit logging

### Phase 3: Rollout (Service Teams)

1. Document patterns and provide examples
2. Services implement resolvers as needed

### Phase 4: Enforcement (Deployers)

1. Define namespace-scoped policies
2. Migrate from path-based to resource-based policies
3. Monitor for authorization failures
4. Iterate on policy granularity

---

## Implementation Progress

### Phase 1: Infrastructure (Platform) - IN PROGRESS

**Completed:**

- [x] Authorizer interface with pluggable backends (`service/internal/auth/authz/authorizer.go`)
- [x] ResolverRegistry and ResolverContext types (`service/internal/auth/authz/resolver.go`)
- [x] Casbin model v2 with `dimensionMatch` custom function (`authz/casbin/model.conf`)
- [x] CasbinAuthorizer supporting v1 (path-based) and v2 (RPC+dimensions) modes
- [x] Default v2 policy with role-based access (`authz/casbin/policy.csv`)
- [x] Config version flag (defaults to "v1" for backwards compatibility)
- [x] Authentication integration with Authorizer and ResolverRegistry
- [x] Unit tests for dimension matching and policy evaluation
- [x] Attributes service resolvers (CreateAttribute, GetAttribute, GetAttributeValuesByFqns, ListAttributes, UpdateAttribute, DeactivateAttribute)

**Remaining:**

- [ ] Additional service resolvers (KAS, namespaces, etc.)
- [ ] Integration tests for resolver + authorizer flow

### Key Files

| File | Purpose |
|------|---------|
| `internal/auth/authz/authorizer.go` | Authorizer interface and factory |
| `internal/auth/authz/resolver.go` | ResolverRegistry and ResolverContext types |
| `internal/auth/authz/policy.go` | PolicyConfig type |
| `internal/auth/authz/casbin/casbin.go` | CasbinAuthorizer with v1/v2 support |
| `internal/auth/authz/casbin/model.conf` | Casbin model for v2 authorization |
| `internal/auth/authz/casbin/policy.csv` | Default v2 policy (embedded) |
| `policy/attributes/attributes.go` | Example resolver implementations (lines 544-688) |

## Open Work

- [ ] Finalize answers to open questions (Q1-Q3)
- [ ] Design caching strategy for resolver lookups
- [ ] Define integration test patterns
- [ ] Performance benchmarks with resolver overhead

---

## References

- [Casbin Documentation](https://casbin.org/docs/overview)
- [XACML Architecture](https://en.wikipedia.org/wiki/XACML) (PDP/PEP/PIP pattern)
- [Google Zanzibar](https://research.google/pubs/pub48190/) (relationship-based access control)
- Current implementation: `service/internal/auth/`
