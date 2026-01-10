# Authorization Resolver Registry - Component Reference

**Purpose**: Track authorization resolver components and service registrations for drift detection.

**Last Updated**: 2026-01-02

---

## Component Inventory

### Core Types

| Type | Location | Purpose |
|------|----------|---------|
| `AuthzResolverResource` | `service/internal/auth/authz_resolver.go:15` | `map[string]string` - Single resource's authorization dimensions (key=dimension name, value=dimension value) |
| `AuthzResolverContext` | `service/internal/auth/authz_resolver.go:20-22` | Container for multiple resources; supports multi-resource operations (e.g., move from A to B) |
| `AuthzResolverFunc` | `service/internal/auth/authz_resolver.go:40` | Function signature: `func(ctx context.Context, req connect.AnyRequest) (AuthzResolverContext, error)` |
| `AuthzResolverRegistry` | `service/internal/auth/authz_resolver.go:45-48` | Global thread-safe registry; keyed by full method path |
| `ScopedAuthzResolverRegistry` | `service/internal/auth/authz_resolver.go:88-91` | Namespace-scoped view; validates method ownership against ServiceDesc |

### Factory Functions

| Function | Location | Returns |
|----------|----------|---------|
| `NewAuthzResolverRegistry()` | `service/internal/auth/authz_resolver.go:50-54` | `*AuthzResolverRegistry` |
| `NewAuthzResolverContext()` | `service/internal/auth/authz_resolver.go:126-128` | `AuthzResolverContext` (empty) |

### Registry Methods

| Method | Receiver | Purpose |
|--------|----------|---------|
| `register(fullMethodPath, resolver)` | `*AuthzResolverRegistry` | Internal - adds resolver for full method path |
| `Get(method)` | `*AuthzResolverRegistry` | Returns resolver and existence flag for method |
| `ScopedForService(serviceDesc)` | `*AuthzResolverRegistry` | Creates scoped registry for service; panics if serviceDesc is nil |
| `Register(methodName, resolver)` | `*ScopedAuthzResolverRegistry` | Validates method exists in ServiceDesc, builds full path, delegates to parent |
| `MustRegister(methodName, resolver)` | `*ScopedAuthzResolverRegistry` | Like Register but panics on error |
| `ServiceName()` | `*ScopedAuthzResolverRegistry` | Returns scoped service name |

### Context Methods

| Method | Receiver | Purpose |
|--------|----------|---------|
| `NewResource()` | `*AuthzResolverContext` | Appends new resource to Resources slice, returns pointer |
| `AddDimension(dimension, value)` | `*AuthzResolverResource` | Sets dimension key-value pair |

---

## Platform Integration Points

### Registry Creation

| Location | Line | Action |
|----------|------|--------|
| `service/pkg/server/start.go` | 275 | Creates global `AuthzResolverRegistry` |
| `service/pkg/server/start.go` | 286 | Passes registry to `startServicesParams` |

### Scoped Registry Creation

| Location | Line | Action |
|----------|------|--------|
| `service/pkg/server/services.go` | 211-216 | Creates `ScopedAuthzResolverRegistry` per service via `ScopedForService()` |
| `service/pkg/server/services.go` | 230 | Injects scoped registry into `RegistrationParams.AuthzResolverRegistry` |

### RegistrationParams Field

| Location | Line | Field |
|----------|------|-------|
| `service/pkg/serviceregistry/serviceregistry.go` | 69-83 | `AuthzResolverRegistry *auth.ScopedAuthzResolverRegistry` |

---

## Service Registrations

### Attributes Service

**File**: `service/policy/attributes/attributes.go`

**Registration Location**: Lines 74-80 in `RegisterFunc`

| Method | Resolver Function | Dimensions Resolved |
|--------|-------------------|---------------------|
| `CreateAttribute` | `createAttributeAuthzResolver` | `namespace` (via DB lookup from namespace_id) |
| `GetAttribute` | `getAttributeAuthzResolver` | `namespace`, `attribute` (via DB lookup) |
| `ListAttributes` | `listAttributesAuthzResolver` | `namespace` (optional, from request filter) |
| `UpdateAttribute` | `updateAttributeAuthzResolver` | `namespace`, `attribute` (via DB lookup) |
| `DeactivateAttribute` | `deactivateAttributeAuthzResolver` | `namespace`, `attribute` (via DB lookup) |

**Resolver Functions Location**: Lines 100-339

### Services Without Registrations

The following services do not currently register authz resolvers:

| Service | Namespace | File |
|---------|-----------|------|
| Namespaces | policy | `service/policy/namespaces/namespaces.go` |
| Subject Mappings | policy | `service/policy/subjectmapping/subject_mapping.go` |
| Resource Mappings | policy | `service/policy/resourcemapping/resource_mapping.go` |
| KAS Registry | policy | `service/policy/kasregistry/kas_registry.go` |
| Public Key | policy | `service/policy/publickey/public_key.go` |
| Unsafe | policy | `service/policy/unsafe/unsafe.go` |
| KAS | kas | `service/kas/kas.go` |
| Authorization | authorization | `service/authorization/authorization.go` |
| Authorization V2 | authorization | `service/authorization/v2/authorization.go` |
| Entity Resolution | entityresolution | `service/entityresolution/*.go` |
| Health | health | `service/health/health.go` |
| WellKnown | wellknown | `service/wellknownconfiguration/wellknown.go` |

---

## Dimension Schema

### Known Dimensions

| Dimension | Used By | Description |
|-----------|---------|-------------|
| `namespace` | Attributes | Policy namespace name (resolved from namespace_id or attribute lookup) |
| `attribute` | Attributes | Attribute definition name |

### Expected Future Dimensions

| Dimension | Service | Description |
|-----------|---------|-------------|
| `kas_id` | KAS | KAS instance identifier |
| `value` | Attributes | Attribute value name |

---

## Validation Rules

### Method Validation

`ScopedAuthzResolverRegistry.Register()` validates:
1. Method name exists in `ServiceDesc.Methods`
2. Builds full path as `/<ServiceName>/<MethodName>`

### Registration Patterns

Services MUST:
1. Check `srp.AuthzResolverRegistry != nil` before registering
2. Use `MustRegister()` during initialization (panics are acceptable at startup)
3. Implement resolver functions as service methods (access to DB client)

Services SHOULD:
1. Resolve dimensions to human-readable names (not UUIDs)
2. Return errors for failed DB lookups (results in 403)
3. Support optional dimensions by omitting from context

---

## Drift Detection Checklist

### Review

- [ ] All proto `ResourceAuthz` annotations have matching resolver registrations
- [ ] All registered resolvers match methods in ServiceDesc
- [ ] Dimension keys match proto annotation schemas
- [ ] No orphaned resolver functions (registered but method removed)

### When Adding New Methods

1. Add proto annotation with `ResourceAuthz`
2. Implement resolver function
3. Register in `RegisterFunc`
4. Update this document's Service Registrations section

### When Removing Methods

1. Remove resolver registration
2. Remove resolver function
3. Update this document's Service Registrations section
