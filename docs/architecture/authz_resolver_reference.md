# Authorization Resolver Registry - Component Reference

**Purpose**: Track authorization resolver components and service registrations for drift detection.

**Last Updated**: 2026-01-09

---

## Component Inventory

### Core Types

| Type | Location | Purpose |
|------|----------|---------|
| `ResolverResource` | `service/internal/auth/authz/resolver.go:15` | `map[string]string` - Single resource's authorization dimensions (key=dimension name, value=dimension value) |
| `ResolverContext` | `service/internal/auth/authz/resolver.go:20-22` | Container for multiple resources; supports multi-resource operations (e.g., move from A to B) |
| `ResolverFunc` | `service/internal/auth/authz/resolver.go:40` | Function signature: `func(ctx context.Context, req connect.AnyRequest) (ResolverContext, error)` |
| `ResolverRegistry` | `service/internal/auth/authz/resolver.go:45-48` | Global thread-safe registry; keyed by full method path |
| `ScopedResolverRegistry` | `service/internal/auth/authz/resolver.go:89-92` | Namespace-scoped view; validates method ownership against ServiceDesc |

### Factory Functions

| Function | Location | Returns |
|----------|----------|---------|
| `NewResolverRegistry()` | `service/internal/auth/authz/resolver.go:51-55` | `*ResolverRegistry` |
| `NewResolverContext()` | `service/internal/auth/authz/resolver.go:127-129` | `ResolverContext` (empty) |

### Registry Methods

| Method | Receiver | Purpose |
|--------|----------|---------|
| `register(fullMethodPath, resolver)` | `*ResolverRegistry` | Internal - adds resolver for full method path |
| `Get(method)` | `*ResolverRegistry` | Returns resolver and existence flag for method |
| `ScopedForService(serviceDesc)` | `*ResolverRegistry` | Creates scoped registry for service; panics if serviceDesc is nil |
| `Register(methodName, resolver)` | `*ScopedResolverRegistry` | Validates method exists in ServiceDesc, builds full path, delegates to parent |
| `MustRegister(methodName, resolver)` | `*ScopedResolverRegistry` | Like Register but panics on error |
| `ServiceName()` | `*ScopedResolverRegistry` | Returns scoped service name |

### Context Methods

| Method | Receiver | Purpose |
|--------|----------|---------|
| `NewResource()` | `*ResolverContext` | Appends new resource to Resources slice, returns pointer |
| `AddDimension(dimension, value)` | `*ResolverResource` | Sets dimension key-value pair |

---

## Platform Integration Points

### Registry Creation

| Location | Line | Action |
|----------|------|--------|
| `service/pkg/server/start.go` | 276 | Creates global `ResolverRegistry` via `authz.NewResolverRegistry()` |
| `service/pkg/server/start.go` | 287 | Passes registry to `startServicesParams` |

### Scoped Registry Creation

| Location | Line | Action |
|----------|------|--------|
| `service/pkg/server/services.go` | 213-215 | Creates `ScopedResolverRegistry` per service via `ScopedForService()` |
| `service/pkg/server/services.go` | 230 | Injects scoped registry into `RegistrationParams.AuthzResolverRegistry` |

### RegistrationParams Field

| Location | Line | Field |
|----------|------|-------|
| `service/pkg/serviceregistry/serviceregistry.go` | 69-83 | `AuthzResolverRegistry *authz.ScopedResolverRegistry` |

---

## Service Registrations

### Attributes Service

**File**: `service/policy/attributes/attributes.go`

**Registration Location**: Lines 74-81 in `RegisterFunc`

| Method | Resolver Function | Dimensions Resolved |
|--------|-------------------|---------------------|
| `CreateAttribute` | `createAttributeAuthzResolver` | `namespace` (via DB lookup from namespace_id) |
| `GetAttribute` | `getAttributeAuthzResolver` | `namespace`, `attribute` (via DB lookup) |
| `GetAttributeValuesByFqns` | `getAttributeValuesByFqnsAuthzResolver` | `namespace` (parsed from FQN URLs, multiple resources) |
| `ListAttributes` | `listAttributesAuthzResolver` | `namespace` (optional, from request filter) |
| `UpdateAttribute` | `updateAttributeAuthzResolver` | `namespace`, `attribute` (via DB lookup) |
| `DeactivateAttribute` | `deactivateAttributeAuthzResolver` | `namespace`, `attribute` (via DB lookup) |

**Resolver Functions Location**: Lines 554-688

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
| `namespace` | Attributes | Policy namespace name (resolved from namespace_id, attribute lookup, or FQN parsing) |
| `attribute` | Attributes | Attribute definition name |

### Expected Future Dimensions

| Dimension | Service | Description |
|-----------|---------|-------------|
| `kas_id` | KAS | KAS instance identifier |
| `value` | Attributes | Attribute value name |

---

## Validation Rules

### Method Validation

`ScopedResolverRegistry.Register()` validates:
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
