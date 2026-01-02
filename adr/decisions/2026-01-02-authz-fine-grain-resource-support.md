# Resource-Level Authorization Specification

**Status:** WIP / Draft
**Authors:** Platform Team
**Created:** 2024-12-30
**Last Updated:** 2025-01-02

## Problem Statement

The current authorization system uses **path-based RBAC** via Casbin, where policies match on gRPC method paths and HTTP routes. This provides coarse-grained access control (e.g., "admins can access all policy endpoints") but lacks the ability to enforce **resource-level permissions** (e.g., "user A can only modify attributes in namespace X").

### Current State

```
Model: (subject, resource, action)
       where resource = gRPC path pattern (e.g., "policy.attributes.AttributesService/*")
       and subject = roles extracted from JWT claims
```

### Desired State

```
Model: (subject, resource_type, action, dimensions)
       where:
         - resource_type = service-defined type (e.g., "policy.attribute", "kas.key")
         - action = operation (read, write, delete, rewrap, etc.)
         - dimensions = service-specific key-value pairs (e.g., {"namespace": "hr"}, {"kas_id": "kas-1"})
       The proto annotation defines which dimensions exist for each resource type,
       creating a schema that bridges proto → resolver → Casbin policy → UI.
```

## Goals

1. **Namespace-scoped authorization** - Restrict users to resources within specific namespaces
2. **Governance & auditability** - Platform maintainers can generate a complete permission matrix from proto definitions
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
│  │  │ 2. Read proto annotation → ResourceAuthz{type, action, dims}│    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │ 3. Call service resolver → AuthzContext{dimensions: {...}}  │    │    │
│  │  │    (IoC / "Hollywood Principle" - framework calls service)  │    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │ 4. Enforce → Casbin(sub, type, action, serialized_dims)     │    │    │
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
| Proto Annotations | Platform | Define authorization schema per RPC method |
| AuthzContext | Platform | Contract struct between resolvers and enforcer |
| Interceptor | Platform | Orchestrates the authorization flow |
| Resolver Interface | Platform | Defines the hook contract |
| Resolver Implementation | Service | Enriches context with resource relationships |
| Casbin Model | Platform | Defines policy matching dimensions |
| Casbin Policies | Deployer | Configures actual access rules |

---

## Implementation Concepts

### 1. Proto Annotations (Platform-Owned)

```protobuf
// service/authz/options.proto

syntax = "proto3";
package opentdf.authz;

import "google/protobuf/descriptor.proto";

extend google.protobuf.MethodOptions {
  ResourceAuthz resource_authz = 50000;
}

// AuthzResourceDimension defines a single authorization dimension that the resolver will provide.
// This creates the contract between proto definition, resolver, and Casbin policy.
message AuthzResourceDimension {
  // The key name used in AuthzContext and Casbin policy (e.g., "namespace", "kas_id")
  string key = 1;

  // Human-readable description for documentation/UI
  string description = 2;

  // If true, resolver MUST provide this dimension
  bool required = 3;
}

message ResourceAuthz {
  // The type of resource being accessed (e.g., "policy.attribute", "kas.key")
  // This is the primary resource type and is always required.
  string resource_type = 1;

  // The action being performed (read, write, delete, unsafe)
  string action = 2;

  // Dimensions that the resolver will provide for policy evaluation.
  // These define the schema for this resource type's authorization context.
  // The resolver returns map[string]string with keys matching these dimensions.
  repeated AuthzResourceDimension dimensions = 3;

  // If true, a resolver MUST be registered for this method
  // If false, falls back to path-based authorization
  bool resolver_required = 4;

  // Human-readable description for documentation generation
  string description = 5;
}
```

Usage in service protos:

```protobuf
// service/policy/attributes/attributes.proto

import "authz/options.proto";

service AttributesService {
  rpc UpdateAttribute(UpdateAttributeRequest) returns (UpdateAttributeResponse) {
    option (opentdf.authz.resource_authz) = {
      resource_type: "policy.attribute"
      action: "write"
      resolver_required: true
      description: "Update attribute metadata. Requires write access to the attribute's namespace."
      dimensions: [
        {key: "namespace", description: "The namespace containing this attribute", required: true},
        {key: "attribute", description: "The attribute being updated (by name)", required: true}
      ]
    };
  }

  rpc ListAttributes(ListAttributesRequest) returns (ListAttributesResponse) {
    option (opentdf.authz.resource_authz) = {
      resource_type: "policy.attribute"
      action: "read"
      resolver_required: false
      description: "List attributes. Filtered by namespace if specified."
      dimensions: [
        {key: "namespace", description: "Filter to this namespace", required: false}
      ]
    };
  }
}

// service/kas/kas.proto
service AccessService {
  rpc Rewrap(RewrapRequest) returns (RewrapResponse) {
    option (opentdf.authz.resource_authz) = {
      resource_type: "kas.key"
      action: "rewrap"
      resolver_required: true
      description: "Rewrap a key. Requires access to the KAS instance."
      dimensions: [
        {key: "kas_id", description: "The KAS instance handling this request", required: true}
      ]
    };
  }
}
```

### Schema Registry for UI/Governance

The proto annotations create a **schema registry** that bridges the contract between:
- **Proto definitions** (what services declare)
- **Resolvers** (what context is provided at runtime)
- **Casbin policies** (what deployers configure)
- **Policy UI** (what administrators see)

This enables:
1. **Governance reports**: "What dimensions exist for each resource type?"
2. **Policy UI**: "When creating a policy for `policy.attribute`, what dimensions can I specify?"
3. **Validation**: "Does this Casbin policy reference valid dimensions?"
4. **Documentation**: Auto-generate permission documentation from proto files

#### Schema Extraction

The platform extracts schemas at build time from proto annotations:

```json
{
  "generated_at": "2024-12-30T12:00:00Z",
  "resource_schemas": {
    "policy.attribute": {
      "dimensions": [
        {"key": "namespace", "description": "The namespace containing this attribute", "required": true},
        {"key": "attribute", "description": "The attribute being updated (by name)", "required": true}
      ],
      "actions": ["read", "write", "delete"],
      "methods": [
        {"name": "UpdateAttribute", "action": "write", "resolver_required": true},
        {"name": "GetAttribute", "action": "read", "resolver_required": true},
        {"name": "ListAttributes", "action": "read", "resolver_required": false}
      ]
    },
    "policy.namespace": {
      "dimensions": [
        {"key": "namespace", "description": "The namespace", "required": true}
      ],
      "actions": ["read", "write", "delete"]
    },
    "kas.key": {
      "dimensions": [
        {"key": "kas_id", "description": "The KAS instance handling this request", "required": true}
      ],
      "actions": ["rewrap", "read"]
    }
  }
}
```

#### Policy UI Integration

The schema enables the UI to:

1. **Show available dimensions** when creating/editing a policy:
   ```
   Resource Type: [policy.attribute ▼]
   Action: [write ▼]
   Dimensions:
     namespace: [_________] (required)
     attribute: [_________] (optional, use * for all)
   ```

2. **Validate policies** against the schema:
   - Warn if a policy references a dimension that doesn't exist for the resource type
   - Warn if a required dimension is not specified (defaults to wildcard)

3. **Generate human-readable descriptions**:
   ```
   Policy: "HR admins can write to HR namespace attributes"
   Rule: role:hr-admin → policy.attribute / write / namespace=hr
   ```

#### Proto → Policy → UI Data Flow

```
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│  Proto Annotat.  │──────│  Schema Registry │──────│    Policy UI     │
│                  │      │                  │      │                  │
│  ResourceAuthz { │ gen  │  resource_schemas│ read │  Create Policy   │
│    resource_type │─────▶│    dimensions[]  │─────▶│  [resource_type] │
│    dimensions[]  │      │    actions[]     │      │  [dimensions...] │
│  }               │      │                  │      │                  │
└──────────────────┘      └──────────────────┘      └──────────────────┘
         │                        │                        │
         │                        │                        │
         ▼                        ▼                        ▼
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│    Resolver      │      │    Validation    │      │  Casbin Policy   │
│                  │      │                  │      │                  │
│  Returns dims    │ valid│  Check dims      │ store│  p, role:x,      │
│  matching schema │◀─────│  against schema  │◀─────│  type, action,   │
│                  │      │                  │      │  dims, allow     │
└──────────────────┘      └──────────────────┘      └──────────────────┘
```

### 2. AuthzContext (Platform-Owned Contract)

```go
// service/internal/auth/authz_context.go

package auth

// AuthzContext is the contract between service resolvers and the authorization enforcer.
// Resolvers populate this struct; the enforcer passes it to Casbin.
//
// This uses a dynamic Dimensions map rather than fixed fields because different
// services have different resource hierarchies:
//   - Policy service: namespace, attribute, value
//   - KAS service: kas_id, key_id
//   - Authorization service: (may have its own concepts)
//
// The proto annotation defines which dimensions are expected for each resource type,
// creating a schema that bridges proto → resolver → Casbin policy → UI.
type AuthzContext struct {
    // ResourceType identifies the kind of resource (e.g., "policy.attribute", "kas.key").
    // This is always required and should match the resource_type in the proto annotation.
    ResourceType string

    // Action is the operation (read, write, delete, unsafe, rewrap, etc.).
    // Typically comes from the proto annotation.
    Action string

    // Dimensions contains service-specific authorization dimensions.
    // Keys should match the dimension keys declared in the proto annotation.
    // Values are the resolved dimension values (e.g., {"namespace": "hr", "attribute": "classification"}).
    // Use "*" for wildcard/any matching.
    Dimensions map[string]string
}

// NewAuthzContext creates an AuthzContext with initialized Dimensions map.
func NewAuthzContext(resourceType, action string) *AuthzContext {
    return &AuthzContext{
        ResourceType: resourceType,
        Action:       action,
        Dimensions:   make(map[string]string),
    }
}

// SetDimension sets a dimension value, using "*" if value is empty.
func (c *AuthzContext) SetDimension(key, value string) {
    if value == "" {
        value = "*"
    }
    c.Dimensions[key] = value
}

// GetDimension returns a dimension value, defaulting to "*" if not set.
func (c *AuthzContext) GetDimension(key string) string {
    if v, ok := c.Dimensions[key]; ok {
        return v
    }
    return "*"
}

// Validate ensures required fields are populated and checks against annotation schema.
func (c *AuthzContext) Validate(annotation *ResourceAuthz) error {
    if c.ResourceType == "" {
        return errors.New("resource_type is required")
    }
    if c.Action == "" {
        return errors.New("action is required")
    }
    if c.ResourceType != annotation.ResourceType {
        return fmt.Errorf("resource_type mismatch: context has %q, annotation expects %q",
            c.ResourceType, annotation.ResourceType)
    }

    // Check required dimensions from annotation are present
    for _, dim := range annotation.Dimensions {
        if dim.Required {
            if _, ok := c.Dimensions[dim.Key]; !ok {
                return fmt.Errorf("required dimension %q not provided", dim.Key)
            }
        }
    }
    return nil
}
```

### 3. Resolver Interface (Platform-Owned)

```go
// service/internal/auth/resolver.go

package auth

import (
    "context"
    "google.golang.org/protobuf/proto"
)

// ResourceResolver is implemented by services to provide authorization context.
// This follows the Inversion of Control pattern - the platform calls the service's
// resolver during the authorization flow.
type ResourceResolver interface {
    // Resolve extracts and enriches authorization context from a request.
    //
    // The resolver may:
    //   - Extract fields directly from the request (e.g., namespace_id)
    //   - Perform DB lookups to resolve relationships (e.g., attribute → namespace)
    //   - Return errors if the resource cannot be resolved (results in 403)
    //
    // Parameters:
    //   - ctx: Request context (includes auth info, tracing, etc.)
    //   - method: The gRPC method name (e.g., "/policy.attributes.AttributesService/UpdateAttribute")
    //   - req: The deserialized protobuf request message
    //   - annotation: The ResourceAuthz annotation from the proto definition
    //
    // Returns:
    //   - AuthzContext with resolved namespace, resource_id, etc.
    //   - Error if resolution fails (e.g., resource not found)
    Resolve(ctx context.Context, method string, req proto.Message, annotation *ResourceAuthz) (*AuthzContext, error)
}

// ResolverRegistry manages resolver registrations per service namespace.
type ResolverRegistry struct {
    resolvers map[string]ResourceResolver  // namespace -> resolver
}

func NewResolverRegistry() *ResolverRegistry {
    return &ResolverRegistry{
        resolvers: make(map[string]ResourceResolver),
    }
}

func (r *ResolverRegistry) Register(namespace string, resolver ResourceResolver) {
    r.resolvers[namespace] = resolver
}

func (r *ResolverRegistry) Get(namespace string) (ResourceResolver, bool) {
    resolver, ok := r.resolvers[namespace]
    return resolver, ok
}
```

### 4. Service Resolver Implementation (Service-Owned)

```go
// service/policy/attributes/authz_resolver.go

package attributes

import (
    "context"
    "fmt"

    "google.golang.org/protobuf/proto"
    "github.com/opentdf/platform/service/internal/auth"
    "github.com/opentdf/platform/service/policy/db"
    pb "github.com/opentdf/platform/protocol/go/policy/attributes"
)

// AttributeResolver implements auth.ResourceResolver for the attributes service.
type AttributeResolver struct {
    dbClient *db.PolicyDBClient
}

func NewAttributeResolver(dbClient *db.PolicyDBClient) *AttributeResolver {
    return &AttributeResolver{dbClient: dbClient}
}

func (r *AttributeResolver) Resolve(
    ctx context.Context,
    method string,
    req proto.Message,
    annotation *auth.ResourceAuthz,
) (*auth.AuthzContext, error) {

    authzCtx := auth.NewAuthzContext(annotation.ResourceType, annotation.Action)

    switch v := req.(type) {
    case *pb.UpdateAttributeRequest:
        // Enrichment: look up attribute to get its namespace
        attr, err := r.dbClient.GetAttribute(ctx, v.GetId())
        if err != nil {
            return nil, fmt.Errorf("failed to resolve attribute: %w", err)
        }
        authzCtx.SetDimension("namespace", attr.GetNamespace().GetName())
        authzCtx.SetDimension("attribute", attr.GetName())

    case *pb.CreateAttributeRequest:
        // Namespace comes from request, no lookup needed
        ns, err := r.dbClient.GetNamespace(ctx, v.GetNamespaceId())
        if err != nil {
            return nil, fmt.Errorf("failed to resolve namespace: %w", err)
        }
        authzCtx.SetDimension("namespace", ns.GetName())
        // attribute not set → defaults to "*"

    case *pb.ListAttributesRequest:
        // Optional namespace filter
        authzCtx.SetDimension("namespace", v.GetNamespace())  // empty → "*"
        // attribute not set → defaults to "*"

    case *pb.GetAttributeRequest:
        // Read by ID - resolve namespace
        attr, err := r.dbClient.GetAttribute(ctx, v.GetId())
        if err != nil {
            return nil, fmt.Errorf("failed to resolve attribute: %w", err)
        }
        authzCtx.SetDimension("namespace", attr.GetNamespace().GetName())
        authzCtx.SetDimension("attribute", attr.GetName())

    default:
        return nil, fmt.Errorf("no resolver implementation for %T", req)
    }

    return authzCtx, nil
}
```

```go
// service/kas/authz_resolver.go (example of different service with different dimensions)

package kas

// KASResolver implements auth.ResourceResolver for the KAS service.
type KASResolver struct {
    // KAS might not need DB lookups - dimensions come from request/config
}

func (r *KASResolver) Resolve(
    ctx context.Context,
    method string,
    req proto.Message,
    annotation *auth.ResourceAuthz,
) (*auth.AuthzContext, error) {

    authzCtx := auth.NewAuthzContext(annotation.ResourceType, annotation.Action)

    switch v := req.(type) {
    case *pb.RewrapRequest:
        // KAS uses kas_id dimension, not namespace
        authzCtx.SetDimension("kas_id", r.kasID)  // From config or request

    default:
        return nil, fmt.Errorf("no resolver implementation for %T", req)
    }

    return authzCtx, nil
}
```

### 5. Service Registration (Service-Owned)

```go
// service/policy/attributes/attributes.go

func NewRegistration() *serviceregistry.Service[attributesconnect.AttributesServiceHandler] {
    return &serviceregistry.Service[attributesconnect.AttributesServiceHandler]{
        ServiceOptions: serviceregistry.ServiceOptions[attributesconnect.AttributesServiceHandler]{
            Namespace:   "policy",
            ServiceDesc: &attributespb.AttributesService_ServiceDesc,
            RegisterFunc: func(srp serviceregistry.RegistrationParams) (...) {
                // Create resolver with DB access
                resolver := NewAttributeResolver(srp.DBClient.PolicyClient())

                // Register resolver with platform
                srp.AuthzResolverRegistry.Register("policy.attributes", resolver)

                // ... rest of registration
            },
        },
    }
}
```

### 6. Casbin Model (Platform-Owned)

The Casbin model must support dynamic dimensions since different services define different
authorization dimensions. We use a **serialized dimensions** approach where the AuthzContext
dimensions map is converted to a canonical string format for policy matching.

```conf
# service/internal/auth/casbin_model_v2.conf

[request_definition]
# sub: subject (role or user)
# resource_type: the resource type (e.g., "policy.attribute", "kas.key")
# action: the operation (read, write, delete, etc.)
# dimensions: serialized key=value pairs, sorted by key (e.g., "namespace=hr")
r = sub, resource_type, action, dimensions

[policy_definition]
# Same structure as request, with eft (effect) for allow/deny
p = sub, resource_type, action, dimensions, eft

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
# keyMatch supports wildcards: * matches any segment
# dimensionMatch is a custom function that handles dynamic dimension matching
m = g(r.sub, p.sub) && keyMatch(r.resource_type, p.resource_type) && keyMatch(r.action, p.action) && dimensionMatch(r.dimensions, p.dimensions)
```

#### Dimension Matching

The platform passes the request dimensions as `map[string]string` directly to a custom Casbin matcher.
Policy dimensions use `&` as the AND delimiter (e.g., `namespace=hr&attr_def=clearance`).

```go
// service/internal/auth/dimension_matcher.go

package auth

import (
    "strings"
)

// DimensionMatch is a custom Casbin matcher function.
// It compares request dimensions (map) against policy dimensions (string).
//
// Policy format:
//   - "*" matches any dimensions (wildcard)
//   - "key=value" matches single dimension
//   - "key=value&key2=value2" matches multiple dimensions (AND logic)
//   - "key=*" matches any value for that key
//
// Matching rules:
//   - All policy dimensions must be satisfied (AND logic)
//   - Policy can omit dimensions (partial match OK)
//   - OR logic is achieved via multiple policy lines
//
// Future extensibility: Could add "|" for OR within a single policy line.
func DimensionMatch(requestDims map[string]string, policyDims string) bool {
    // Wildcard matches everything
    if policyDims == "*" {
        return true
    }

    // Parse policy dimensions and check each (AND logic)
    for _, pair := range strings.Split(policyDims, "&") {
        pair = strings.TrimSpace(pair)
        if pair == "" {
            continue
        }

        kv := strings.SplitN(pair, "=", 2)
        if len(kv) != 2 {
            return false // Malformed policy dimension
        }
        key, policyVal := kv[0], kv[1]

        requestVal, exists := requestDims[key]
        if !exists {
            return false // Policy requires a dimension that request doesn't have
        }
        if policyVal != "*" && policyVal != requestVal {
            return false // Value mismatch
        }
    }
    return true
}
```

#### Registering Custom Function

```go
// In Casbin setup
enforcer.AddFunction("dimensionMatch", DimensionMatchWrapper)

func DimensionMatchWrapper(args ...interface{}) (interface{}, error) {
    // Request dimensions come as map[string]string directly (no serialization)
    reqDims, ok := args[0].(map[string]string)
    if !ok {
        return false, fmt.Errorf("request dimensions must be map[string]string")
    }
    // Policy dimensions are strings from CSV/config
    polDims := args[1].(string)
    return DimensionMatch(reqDims, polDims), nil
}
```

### 7. Interceptor Implementation (Platform-Owned)

The interceptor orchestrates the authorization flow, calling resolvers and enforcing policies:

```go
// service/internal/auth/resource_interceptor.go

package auth

import (
    "context"
    "fmt"

    "connectrpc.com/connect"
    "google.golang.org/protobuf/proto"
    "google.golang.org/protobuf/reflect/protoreflect"
)

// ResourceAuthzInterceptor enforces resource-level authorization.
type ResourceAuthzInterceptor struct {
    enforcer         *casbin.Enforcer
    resolverRegistry *ResolverRegistry
    annotationCache  map[string]*ResourceAuthz  // method -> annotation
}

func (i *ResourceAuthzInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
    return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
        method := req.Spec().Procedure  // e.g., "/policy.attributes.AttributesService/UpdateAttribute"

        // 1. Get proto annotation for this method
        annotation, ok := i.annotationCache[method]
        if !ok {
            // No annotation = fall back to path-based authorization (backwards compat)
            return i.fallbackPathAuth(ctx, req, next)
        }

        // 2. Extract subject from JWT claims
        subject := i.extractSubject(ctx)

        // 3. Call service resolver to get AuthzContext
        authzCtx, err := i.resolveContext(ctx, method, req, annotation)
        if err != nil {
            // Resolution failure = authorization failure
            return nil, connect.NewError(connect.CodePermissionDenied,
                fmt.Errorf("authorization context resolution failed: %w", err))
        }

        // 4. Validate AuthzContext against annotation schema
        if err := authzCtx.Validate(annotation); err != nil {
            return nil, connect.NewError(connect.CodeInternal,
                fmt.Errorf("invalid authorization context: %w", err))
        }

        // 5. Enforce policy with dimensions map directly (no serialization)
        allowed, err := i.enforcer.Enforce(
            subject,                  // e.g., "role:hr-admin"
            authzCtx.ResourceType,    // e.g., "policy.attribute"
            authzCtx.Action,          // e.g., "write"
            authzCtx.Dimensions,      // map[string]string{"namespace": "hr", "attribute": "classification"}
        )
        if err != nil {
            return nil, connect.NewError(connect.CodeInternal,
                fmt.Errorf("authorization enforcement failed: %w", err))
        }

        // 6. Log authorization decision
        i.logDecision(ctx, subject, authzCtx, allowed)

        if !allowed {
            return nil, connect.NewError(connect.CodePermissionDenied,
                fmt.Errorf("access denied to %s %s", authzCtx.Action, authzCtx.ResourceType))
        }

        // 7. Proceed to handler
        return next(ctx, req)
    }
}

func (i *ResourceAuthzInterceptor) resolveContext(
    ctx context.Context,
    method string,
    req connect.AnyRequest,
    annotation *ResourceAuthz,
) (*AuthzContext, error) {
    // Get namespace from resource_type (e.g., "policy" from "policy.attribute")
    namespace := extractNamespace(annotation.ResourceType)

    resolver, ok := i.resolverRegistry.Get(namespace)
    if !ok {
        if annotation.ResolverRequired {
            return nil, fmt.Errorf("resolver required but not registered for namespace %q", namespace)
        }
        // No resolver, create basic context from annotation
        return &AuthzContext{
            ResourceType: annotation.ResourceType,
            Action:       annotation.Action,
            Dimensions:   make(map[string]string),  // Empty = matches "*" policies
        }, nil
    }

    // Cast request to proto.Message
    protoReq, ok := req.Any().(proto.Message)
    if !ok {
        return nil, fmt.Errorf("request is not a proto.Message")
    }

    return resolver.Resolve(ctx, method, protoReq, annotation)
}

func (i *ResourceAuthzInterceptor) logDecision(
    ctx context.Context,
    subject string,
    authzCtx *AuthzContext,
    allowed bool,
) {
    decision := "deny"
    if allowed {
        decision = "allow"
    }

    log.Info().
        Str("subject", subject).
        Str("resource_type", authzCtx.ResourceType).
        Str("action", authzCtx.Action).
        Interface("dimensions", authzCtx.Dimensions).
        Str("decision", decision).
        Msg("authorization decision")
}
```

### 8. Example Policies (Deployer-Owned)

Policies use the new 4-position format: `(subject, resource_type, action, dimensions)`.
Dimensions use `&` as the AND delimiter (e.g., `namespace=hr&attr_id=123`).

```csv
# ====================================================================
# Policy Service - Namespace-scoped roles
# ====================================================================

# Finance admin: full access to finance namespace
p, role:finance-admin, policy.*, *, namespace=finance, allow

# HR admin: full access to hr namespace
p, role:hr-admin, policy.*, *, namespace=hr, allow

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
| Define proto annotation schema | `service/authz/options.proto` |
| Define AuthzContext contract | `service/internal/auth/authz_context.go` |
| Implement interceptor | `service/internal/auth/resource_interceptor.go` |
| Define resolver interface | `service/internal/auth/resolver.go` |
| Maintain Casbin model | `service/internal/auth/casbin_model_v2.conf` |
| Provide governance tooling | `cmd/authz-matrix-generator` |
| Documentation | Architecture docs, migration guides |

### Service Maintainer

| Responsibility | Artifacts |
|----------------|-----------|
| Add proto annotations to RPCs | `service/<ns>/<svc>.proto` |
| Implement resolver | `service/<ns>/authz_resolver.go` |
| Register resolver at startup | In service registration |
| Unit test resolver logic | `service/<ns>/authz_resolver_test.go` |

### Deployer / Operator

| Responsibility | Artifacts |
|----------------|-----------|
| Define Casbin policies | Config file or policy adapter |
| Map IdP roles to platform roles | Casbin `g` groupings |
| Monitor authorization denials | Logs, metrics |

---

## Governance & Auditability

### Permission Matrix Generation

The platform provides tooling to generate a complete permission matrix from proto annotations:

```bash
# Generate JSON matrix
go run ./cmd/authz-matrix-gen --format json > permissions.json

# Generate markdown documentation
go run ./cmd/authz-matrix-gen --format markdown > docs/PERMISSIONS.md
```

Output example:

```json
{
  "generated_at": "2024-12-30T12:00:00Z",
  "permissions": [
    {
      "service": "policy.attributes.AttributesService",
      "method": "UpdateAttribute",
      "resource_type": "policy.attribute",
      "action": "write",
      "resolver_required": true,
      "description": "Update attribute metadata. Requires write access to the attribute's namespace."
    }
  ]
}
```

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

For governance and compliance, the dimensions can also be logged as structured data:

```json
{
  "level": "info",
  "msg": "authorization decision",
  "subject": "role:hr-admin",
  "resource_type": "policy.attribute",
  "action": "write",
  "dimensions": {
    "namespace": "hr",
    "attribute": "classification"
  },
  "dimensions_serialized": "attribute=classification;namespace=hr",
  "decision": "allow",
  "policy_matched": "p, role:hr-admin, policy.*, *, namespace=hr, allow"
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
| D1 | Use proto annotations as source of truth | Enables governance tooling, documentation generation, and compile-time visibility | 2024-12-30 |
| D2 | Resolver follows IoC pattern (platform calls service) | Centralizes enforcement while allowing service-specific enrichment logic | 2024-12-30 |
| D3 | Dynamic dimensions via `map[string]string` | Different services have different resource hierarchies (policy uses namespace, KAS uses kas_id). Fixed fields would impose platform concepts on all services. | 2024-12-30 |
| D4 | Start with namespace-level granularity | Covers primary use case; instance-level can be added later | 2024-12-30 |
| D5 | Proto annotations define dimension schema | Creates explicit contract between resolvers and policies; enables UI for policy management; validates that resolvers provide expected dimensions | 2024-12-30 |
| D6 | Pass dimensions map directly to Casbin matcher | Avoids request-side serialization; custom matcher receives `map[string]string` directly and parses policy string; simpler code with lower complexity | 2025-01-02 |
| D7 | Use `&` as dimension AND delimiter in policies | Semantically correct (& means AND), visually distinct, enables future extensibility for `\|` OR logic within single policy line | 2025-01-02 |
| D8 | Rename `ResourceDimension` to `AuthzResourceDimension` | Clearer naming that explicitly indicates authorization context | 2025-01-02 |
| D9 | Resolver registration per-service namespace | Service maintainers register resolvers for each RPC in their service; `ScopedAuthzResolverRegistry` ensures services can only register for their own methods (validated against `ServiceDesc`) | 2025-01-02 |
| D10 | Empty resolver response treated as no dimensions | If no resolver is registered or resolver returns empty dimensions, Casbin evaluates with empty map. Policies expecting specific dimensions (non-wildcard) will deny; wildcard policies will allow. | 2025-01-02 |
| D11 | Multiple resources supported in single AuthzContext | `AuthzResolverContext.Resources` is a slice of `*AuthzResolverResource`, supporting operations like "move from A to B" that require authorization on multiple resources | 2025-01-02 |

### Open Questions

| # | Question | Options | Leaning | Notes |
|---|----------|---------|---------|-------|
| Q1 | How to handle List operations with post-filtering? | A) Check namespace in resolver, service filters results<br>B) Return all namespaces user can access<br>C) No authz on list, filter in service | TBD | Service maintainer responsibility. Risk: inconsistent implementations across services. |
| Q2 | How to test resolver implementations? | A) Provide mock DB client<br>B) Provide test harness<br>C) Integration tests only | TBD | DX concern |
| Q3 | Caching strategy for resolved namespaces? | A) Resolver owns caching<br>B) Platform provides cache to resolver<br>C) No caching initially | TBD | Platform has `CacheManager` available. Also consider DB client caching since successful authz will repeat the same query in the handler. |

### Future Considerations

| Topic | Notes |
|-------|-------|
| Proto annotations for schema definition | Define annotations in `service/authz/options.proto` to enable governance tooling, documentation generation, and policy UI. Versioning strategy TBD. |
| Policy UI integration | Use proto annotation schema to drive policy creation UI with dimension validation |
| Governance tooling | `authz-matrix-gen` command to generate permission matrix from annotations |

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

1. Add proto annotation definitions
2. Implement AuthzContext and resolver interface
3. Extend interceptor to support resource authorization
4. Update Casbin model to support new dimensions
5. Add fallback to path-based auth for unannotated methods

### Phase 2: Pilot Service (Platform + Service)

1. Add annotations to `policy.attributes` service
2. Implement AttributeResolver
3. Write integration tests
4. Deploy to staging with permissive policies
5. Validate audit logging

### Phase 3: Rollout (Service Teams)

1. Document patterns and provide examples
2. Services add annotations incrementally
3. Implement resolvers as needed
4. Platform provides governance report

### Phase 4: Enforcement (Deployers)

1. Define namespace-scoped policies
2. Migrate from path-based to resource-based policies
3. Monitor for authorization failures
4. Iterate on policy granularity

---

## Open Work

- [ ] Finalize answers to open questions (Q1-Q8)
- [ ] Design caching strategy for resolver lookups
- [ ] Define integration test patterns
- [ ] Create example resolver implementations
- [ ] Build governance tooling (authz-matrix-gen)
- [ ] Write migration guide for service maintainers
- [ ] Performance benchmarks with resolver overhead

---

## References

- [Casbin Documentation](https://casbin.org/docs/overview)
- [XACML Architecture](https://en.wikipedia.org/wiki/XACML) (PDP/PEP/PIP pattern)
- [Google Zanzibar](https://research.google/pubs/pub48190/) (relationship-based access control)
- Current implementation: `service/internal/auth/`
