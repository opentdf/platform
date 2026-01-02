package auth

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"connectrpc.com/connect"
	"google.golang.org/grpc"
)

// AuthzResolverResource represents a single resource's authorization dimensions.
// Each key-value pair is a dimension (e.g., "namespace" -> "hr").
type AuthzResolverResource map[string]string

// AuthzResolverContext holds the resolved authorization context for a request.
// Multiple resources are supported for operations like "move from A to B"
// where authorization is required for both source and destination.
type AuthzResolverContext struct {
	Resources []*AuthzResolverResource
}

// AuthzResolverFunc is the function signature for service-provided resolvers.
// Services implement this to extract authorization dimensions from requests.
//
// Parameters:
//   - ctx: Request context (includes auth info, can be used for DB calls)
//   - req: The connect request (use Deserialize helper to get typed proto)
//
// Returns:
//   - AuthzResolverContext with populated dimensions
//   - Error if resolution fails (results in 403)
//
// Service maintainers are responsible for:
//  1. Deserializing the request using the provided helper
//  2. Extracting relevant fields
//  3. Performing any required DB lookups
//  4. Populating dimensions in AuthzResolverContext
type AuthzResolverFunc func(ctx context.Context, req connect.AnyRequest) (AuthzResolverContext, error)

// AuthzResolverRegistry holds resolver functions keyed by service method.
// This is the global registry used by the interceptor.
// It is thread-safe for concurrent read/write access.
type AuthzResolverRegistry struct {
	mu        sync.RWMutex
	resolvers map[string]AuthzResolverFunc // full method path -> resolver
}

func NewAuthzResolverRegistry() *AuthzResolverRegistry {
	return &AuthzResolverRegistry{
		resolvers: make(map[string]AuthzResolverFunc),
	}
}

// register is internal - adds a resolver for a specific full method path.
// External callers should use ScopedAuthzResolverRegistry.
func (r *AuthzResolverRegistry) register(fullMethodPath string, resolver AuthzResolverFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resolvers[fullMethodPath] = resolver
}

// Get returns the resolver for a method, if registered.
func (r *AuthzResolverRegistry) Get(method string) (AuthzResolverFunc, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	resolver, ok := r.resolvers[method]
	return resolver, ok
}

// ScopedForService creates a namespace-scoped registry that only allows
// registering resolvers for the given service's methods.
// This prevents services from registering resolvers for other services.
// Panics if serviceDesc is nil.
func (r *AuthzResolverRegistry) ScopedForService(serviceDesc *grpc.ServiceDesc) *ScopedAuthzResolverRegistry {
	if serviceDesc == nil {
		panic("serviceDesc cannot be nil")
	}
	return &ScopedAuthzResolverRegistry{
		parent:      r,
		serviceDesc: serviceDesc,
	}
}

// ScopedAuthzResolverRegistry is a namespace-scoped view of the registry.
// It only allows registering resolvers for the service it was created for.
type ScopedAuthzResolverRegistry struct {
	parent      *AuthzResolverRegistry
	serviceDesc *grpc.ServiceDesc
}

// Register adds a resolver for a method in this service.
// Only the method name is required (e.g., "UpdateAttribute"), not the full path.
// The full path is derived from the ServiceDesc.
//
// Returns an error if the method doesn't exist in the ServiceDesc.
func (s *ScopedAuthzResolverRegistry) Register(methodName string, resolver AuthzResolverFunc) error {
	// Validate method exists in ServiceDesc
	methodExists := slices.ContainsFunc(s.serviceDesc.Methods, func(m grpc.MethodDesc) bool {
		return m.MethodName == methodName
	})
	if !methodExists {
		return fmt.Errorf("method %q not found in service %q", methodName, s.serviceDesc.ServiceName)
	}

	// Build full method path: /<ServiceName>/<MethodName>
	fullPath := "/" + s.serviceDesc.ServiceName + "/" + methodName
	s.parent.register(fullPath, resolver)
	return nil
}

// MustRegister is like Register but panics on error.
// Use during service initialization where errors should be fatal.
func (s *ScopedAuthzResolverRegistry) MustRegister(methodName string, resolver AuthzResolverFunc) {
	if err := s.Register(methodName, resolver); err != nil {
		panic(err)
	}
}

// ServiceName returns the service name this registry is scoped to.
func (s *ScopedAuthzResolverRegistry) ServiceName() string {
	return s.serviceDesc.ServiceName
}

func NewAuthzResolverContext() AuthzResolverContext {
	return AuthzResolverContext{}
}

func (a *AuthzResolverContext) NewResource() *AuthzResolverResource {
	resource := make(AuthzResolverResource)
	a.Resources = append(a.Resources, &resource)
	return &resource
}

func (a *AuthzResolverResource) AddDimension(dimension, value string) {
	(*a)[dimension] = value
}
