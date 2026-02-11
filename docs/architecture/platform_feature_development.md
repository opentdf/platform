# Platform Feature Development Guide

This document describes the architectural patterns for developing new platform-level features in the OpenTDF platform. It explains the Inversion of Control (IoC) pattern used for platform/service separation and provides guidance for implementing new capabilities.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [The RegistrationParams Pattern](#the-registrationparams-pattern)
3. [Scoped Registries Pattern](#scoped-registries-pattern)
4. [Adding New Platform Capabilities](#adding-new-platform-capabilities)
5. [Implemented Platform Capabilities](#implemented-platform-capabilities)
6. [Checklist for New Features](#checklist-for-new-features)
7. [Anti-Patterns to Avoid](#anti-patterns-to-avoid)
8. [Known Areas Needing Alignment](#known-areas-needing-alignment)

---

## Architecture Overview

The OpenTDF platform follows an **Inversion of Control (IoC)** architecture where:

- **Platform** owns infrastructure, lifecycle management, and cross-cutting concerns
- **Services** own domain-specific business logic and implementations
- **RegistrationParams** is the injection point where platform provides capabilities to services
- **Scoped registries** prevent cross-service interference and enforce boundaries

### Key Principles

1. **Platform calls service code** - Services register handlers that the platform invokes
2. **Services receive dependencies** - Services don't reach out for platform internals
3. **Scoped access** - Each service receives only the capabilities it needs, scoped to its namespace
4. **Single source of truth** - Platform maintains global registries; services register into them

### Component Relationships

```
Platform Layer (service/pkg/server/, service/internal/)
    |
    |-- Creates global registries and managers
    |-- Initializes database clients per-namespace
    |-- Creates scoped registries for each service
    |-- Starts services via RegistrationParams
    |
    v
RegistrationParams (Injection Point)
    |
    |-- Config (scoped to service namespace)
    |-- DBClient (scoped to service namespace)
    |-- SDK (for IPC between services)
    |-- Logger (scoped to service namespace)
    |-- AuthzResolverRegistry (scoped to service's methods)
    |-- NewCacheClient function
    |-- RegisterReadinessCheck function
    |-- WellKnownConfig function
    |
    v
Service Layer (service/policy/, service/kas/, service/authorization/, etc.)
    |
    |-- Implements domain logic
    |-- Registers handlers via RegisterFunc
    |-- Uses injected dependencies
```

---

## The RegistrationParams Pattern

`RegistrationParams` is defined in `service/pkg/serviceregistry/serviceregistry.go` and serves as the **sole injection point** for platform capabilities into services.

### Injection Patterns

The platform uses three distinct patterns for providing capabilities to services:

| Pattern | Service Action | When to Use |
|---------|----------------|-------------|
| **Declarative Flag** | Declare need → receive and *consume* resource | Single resource, fixed config (DB) |
| **Factory Function** | Receive function → *create* resource(s) | Multiple instances, varied config (cache) |
| **Scoped Registry** | Receive registry → *contribute* registrations | Register handlers into platform systems (authz) |

The key distinction:
- **Declarative/Factory**: Service is a *consumer* of resources
- **Scoped Registry**: Service is a *contributor* to a platform-owned system (platform uses the registrations at runtime)

#### Declarative Flag Pattern

**Location**: `service/pkg/serviceregistry/serviceregistry.go:92-100`

Services declare needs in `ServiceOptions.DB`:
```
DB: serviceregistry.DBRegister{Required: true, Migrations: Migrations}
```

Platform sees the flag, creates the resource, and provides it via `RegistrationParams.DBClient`.

| Flag Field | Type | Purpose |
|------------|------|---------|
| `DB.Required` | `bool` | Platform creates DB client if true |
| `DB.Migrations` | `*embed.FS` | Goose migrations to run |

**Advantages**: Simpler service code, platform-managed lifecycle, explicit dependencies at registration time.

**Use when**: Service needs exactly one instance with configuration known at startup.

#### Factory Function Pattern

Services receive a function and call it to create resources. Service controls when and how resources are created.

| Field | Type | Purpose |
|-------|------|---------|
| `NewCacheClient` | `func(cache.Options) (*cache.Cache, error)` | Create cache instance on-demand |

**Advantages**: Lazy initialization, multiple instances with different options, service controls timing.

**Use when**: Service may need multiple instances, different configurations, or conditional creation.

#### Scoped Registry Pattern

Services receive a scoped registry and call registration methods. Platform creates the registry and handles scoping.

| Field | Type | Purpose |
|-------|------|---------|
| `AuthzResolverRegistry` | `*auth.ScopedAuthzResolverRegistry` | Register authz resolvers per-method |

**Advantages**: Platform controls scope validation, prevents cross-service registration, centralized lookup.

**Use when**: Services need to register handlers/resolvers for their own methods.

### RegistrationParams Fields

**Location**: `service/pkg/serviceregistry/serviceregistry.go:32-84`

| Field | Type | Scope | Pattern |
|-------|------|-------|---------|
| `Config` | `config.ServiceConfig` | Service namespace | Direct injection |
| `Security` | `*config.SecurityConfig` | Platform-wide | Direct injection |
| `OTDF` | `*server.OpenTDFServer` | Platform-wide | Direct injection (deprecated) |
| `DBClient` | `*db.Client` | Service namespace | Declarative flag |
| `SDK` | `*sdk.SDK` | Platform-wide | Direct injection |
| `Logger` | `*logger.Logger` | Service namespace | Direct injection |
| `Tracer` | `trace.Tracer` | Platform-wide | Direct injection |
| `NewCacheClient` | `func(...)` | Service namespace | Factory function |
| `KeyManagerCtxFactories` | `[]trust.NamedKeyManagerCtxFactory` | Platform-wide | Direct injection |
| `WellKnownConfig` | `func(...)` | Platform-wide | Factory function |
| `RegisterReadinessCheck` | `func(...)` | Platform-wide | Factory function |
| `AuthzResolverRegistry` | `*auth.ScopedAuthzResolverRegistry` | Service methods | Scoped registry |

### Service Reception

Services receive `RegistrationParams` via their `RegisterFunc` implementation in `ServiceOptions`.

**Key locations**:
- Service registration: Each service's `NewRegistration()` function
- Platform injection: `service/pkg/server/services.go:218-231`

### Platform-Side Creation

**Location**: `service/pkg/server/services.go:218-231`

The platform iterates through registered namespaces and creates `RegistrationParams` for each service, populating:
1. Scoped fields (Config, DBClient, Logger) from namespace-specific sources
2. Platform-wide fields (SDK, Security, OTDF) from global instances
3. Function fields (WellKnownConfig, RegisterReadinessCheck) from platform services
4. Scoped registries (AuthzResolverRegistry) created per-service

---

## Scoped Registries Pattern

Scoped registries provide **namespace isolation** - services can only register items for their own methods/namespace, preventing cross-service interference.

### Pattern Structure

```
Global Registry (platform-owned)
    |
    |-- ScopedForService(serviceDesc) --> ScopedRegistry
    |
    v
Scoped Registry (service-receives)
    |
    |-- Validates method belongs to service
    |-- Delegates to global registry with full path
```

### Implementation Requirements

| Component | Owner | Responsibility |
|-----------|-------|----------------|
| Global Registry | Platform | Thread-safe storage (`sync.RWMutex`), `Get()` accessor |
| `ScopedForService()` | Platform | Creates scoped view, validates serviceDesc not nil |
| Scoped Registry | Platform | Validates method ownership, builds full path, delegates |
| Registration call | Service | Calls scoped `Register()` or `MustRegister()` in `RegisterFunc` |

### Validation Flow

1. Service calls `scopedRegistry.Register(methodName, handler)`
2. Scoped registry checks `methodName` exists in `serviceDesc.Methods`
3. If valid: builds full path `/<ServiceName>/<MethodName>` and delegates to parent
4. If invalid: returns error (or panics for `MustRegister`)

### Platform Integration Points

| Location | Action |
|----------|--------|
| `service/pkg/server/start.go:275` | Creates global registry |
| `service/pkg/server/services.go:211-216` | Creates scoped registry per service |
| `service/pkg/server/services.go:230` | Injects scoped registry into RegistrationParams |

---

## Adding New Platform Capabilities

Follow these steps to add a new platform-level capability.

### Choose the Right Pattern

| Question | If Yes → Pattern |
|----------|------------------|
| Does the service *consume* a single resource with fixed config? | Declarative Flag |
| Does the service *create* multiple instances or need varied config? | Factory Function |
| Does the service *contribute* handlers/registrations to a platform system? | Scoped Registry |

### For Scoped Registry Pattern

#### Required Files

| Step | File | Action |
|------|------|--------|
| 1 | `service/internal/<feature>/registry.go` | Define global registry with `sync.RWMutex` |
| 2 | `service/internal/<feature>/scoped_registry.go` | Define scoped registry with validation |
| 3 | `service/pkg/serviceregistry/serviceregistry.go` | Add scoped registry field to `RegistrationParams` |
| 4 | `service/pkg/server/start.go` | Create global registry instance |
| 5 | `service/pkg/server/services.go` | Add to `startServicesParams`, create scoped registry per-service |
| 6 | `service/internal/<feature>/interceptor.go` | (Optional) Create interceptor using global registry |

#### Global Registry Requirements

- Thread-safe storage using `sync.RWMutex`
- `Get(key)` method for retrieval
- Internal `register(key, item)` method (not exported)
- `ScopedForService(serviceDesc)` factory method

#### Scoped Registry Requirements

- Reference to parent global registry
- Reference to `*grpc.ServiceDesc` for validation
- `Register(methodName, item)` validates method exists in ServiceDesc
- `MustRegister(methodName, item)` panics on validation failure
- Builds full path as `/<ServiceName>/<MethodName>`

### For Declarative Flag Pattern

#### Required Changes

| Step | File | Action |
|------|------|--------|
| 1 | `service/pkg/serviceregistry/serviceregistry.go` | Add flag struct (like `DBRegister`) to `ServiceOptions` |
| 2 | `service/pkg/serviceregistry/serviceregistry.go` | Add field to `RegistrationParams` for the resource |
| 3 | `service/pkg/server/services.go` | Check flag, create resource, inject into params |

#### Flag Struct Requirements

- Boolean `Required` field to indicate service needs this resource
- Any configuration fields needed for resource creation
- Platform checks flag in service loop before creating resource

### Platform Integration Requirements (Both Patterns)

- Resources created in `start.go` or service loop in `services.go`
- Passed to `startServicesParams` struct if created in `start.go`
- Nil check before using or scoping
- Injected into `RegistrationParams`

---

## Implemented Platform Capabilities

### Authorization Resolver Registry

**Reference Document**: [AUTHZ_RESOLVER_REFERENCE.md](./AUTHZ_RESOLVER_REFERENCE.md)

| Component | Location |
|-----------|----------|
| Core types | `service/internal/auth/authz_resolver.go` |
| Global registry creation | `service/pkg/server/start.go:275` |
| Scoped registry creation | `service/pkg/server/services.go:211-216` |
| RegistrationParams field | `service/pkg/serviceregistry/serviceregistry.go:69-83` |

**Service Integrations**:

| Service | File | Status |
|---------|------|--------|
| Attributes | `service/policy/attributes/attributes.go:74-80` | 5 methods registered |
| Namespaces | `service/policy/namespaces/namespaces.go` | Not implemented |
| Values | `service/policy/attributes/attributes.go` | Not implemented |
| KAS | `service/kas/kas.go` | Not implemented |

See [authz_resolver_reference.md](./authz_resolver_reference.md) for complete component inventory and drift detection checklist.

---

## Checklist for New Features

Use this checklist when adding new platform capabilities:

### Design Phase

- [ ] Is this truly a platform-level capability (cross-cutting, infrastructure)?
- [ ] Which injection pattern fits? (See [Choose the Right Pattern](#choose-the-right-pattern))
  - Declarative Flag: Service *consumes* a single resource with fixed config
  - Factory Function: Service *creates* multiple instances or needs varied config
  - Scoped Registry: Service *contributes* handlers/registrations to platform
- [ ] What validation is needed (method ownership, namespace scoping)?
- [ ] What is the runtime behavior (interceptor, handler, background job)?

### Implementation Phase (Declarative Flag)

- [ ] Add flag struct to `ServiceOptions` in `serviceregistry.go`
- [ ] Add resource field to `RegistrationParams`
- [ ] Check flag and create resource in `services.go`
- [ ] Inject resource into `RegistrationParams`

### Implementation Phase (Factory Function)

- [ ] Create factory function type
- [ ] Add factory field to `RegistrationParams`
- [ ] Initialize factory in `start.go` or `services.go`
- [ ] Inject factory into `RegistrationParams`

### Implementation Phase (Scoped Registry)

- [ ] Create global registry in `service/internal/` with `sync.RWMutex`
- [ ] Create scoped registry with ServiceDesc validation
- [ ] Add scoped registry type to `RegistrationParams`
- [ ] Create global registry in `start.go`
- [ ] Create scoped registries per-service in `services.go`
- [ ] Implement interceptor/handler that uses global registry

### Testing Phase

- [ ] Unit test resource creation or registry operations
- [ ] Unit test scoped registry validation (if applicable)
- [ ] Integration test service usage
- [ ] Integration test runtime behavior

### Documentation Phase

- [ ] Document in CLAUDE.md if it affects development workflow
- [ ] Update this document with the new capability

---

## Anti-Patterns to Avoid

| Anti-Pattern | Problem | Correct Approach |
|--------------|---------|------------------|
| **Cross-service data access** | Service A directly accesses Service B's DB client or internal state | Use SDK for IPC between services |
| **Platform internal access** | Service accesses `srp.OTDF.HTTPServer` or other server internals | Use scoped configuration from `srp.Config` |
| **Unscoped registration** | Global registry allows any service to register for any method | Use scoped registries with ServiceDesc validation |
| **Bypassing RegistrationParams** | Global singletons or package-level state for dependencies | Receive all dependencies through RegistrationParams |
| **Direct namespace access** | Accessing other namespace's configuration or state | Only access `srp.Config` for own namespace |

### Detection Indicators

- Import of `service/internal/server` in service code (except via RegistrationParams)
- Package-level `var` declarations for DB clients, SDK, or config
- Hardcoded namespace names outside the service's own namespace
- Direct method path strings instead of using ServiceDesc

---

## Known Areas Needing Alignment

The following areas of the codebase do not fully follow the patterns described above.

| Area | Location | Issue | Status |
|------|----------|-------|--------|
| **OTDF Server Direct Access** | `service/kas/kas.go:97-98, 142-170` | KAS accesses `srp.OTDF.CryptoProvider`, `PublicHostname`, `HTTPServer.Addr`, `TLSConfig` | TODO at `services.go:226` |
| **DBClient Namespace Sharing** | `service/pkg/server/services.go:188-192` | Services in same namespace share DB client | Mitigated by domain-specific wrappers |
| **SDK Full Access** | Various services | SDK gives access to all service clients, no compile-time enforcement | Intentional for IPC |
| **Function Pointer Registrations** | `serviceregistry.go:63-67` | Health/WellKnown use function pointers not scoped registries | Acceptable for cross-cutting concerns |
| **Logger Namespace Sharing** | `services.go:164-179` | Services in same namespace share logger | Acceptable with `.With()` context |

### OTDF Server Access Details

KAS service accesses these platform internals that should be in RegistrationParams:
- `srp.OTDF.CryptoProvider`
- `srp.OTDF.PublicHostname`
- `srp.OTDF.HTTPServer.Addr`
- `srp.OTDF.HTTPServer.TLSConfig`

**Recommendation**: Add dedicated fields to RegistrationParams:
- `PublicHostname string`
- `TLSEnabled bool`
- Migrate to `KeyManagerCtxFactories` for crypto
