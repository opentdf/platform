package authz

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"connectrpc.com/connect"
	"google.golang.org/grpc"
)

// ResolverResource represents a single resource's authorization dimensions.
// Each key-value pair is a dimension (e.g., "namespace" -> "hr").
type ResolverResource map[string]string

// ResolverContext holds the resolved authorization context for a request.
// Multiple resources are supported for operations like "move from A to B"
// where authorization is required for both source and destination.
type ResolverContext struct {
	Resources []*ResolverResource
}

// ResolverFunc is the function signature for service-provided resolvers.
// Services implement this to extract authorization dimensions from requests.
//
// Parameters:
//   - ctx: Request context (includes auth info, can be used for DB calls)
//   - req: The connect request (use Deserialize helper to get typed proto)
//
// Returns:
//   - ResolverContext with populated dimensions
//   - Error if resolution fails (results in 403)
//
// Service maintainers are responsible for:
//  1. Deserializing the request using the provided helper
//  2. Extracting relevant fields
//  3. Performing any required DB lookups
//  4. Populating dimensions in ResolverContext
type ResolverFunc func(ctx context.Context, req connect.AnyRequest) (ResolverContext, error)

// ResolverRegistry holds resolver functions keyed by service method.
// This is the global registry used by the interceptor.
// It is thread-safe for concurrent read/write access.
type ResolverRegistry struct {
	mu        sync.RWMutex
	resolvers map[string]ResolverFunc // full method path -> resolver
}

// NewResolverRegistry creates a new resolver registry.
func NewResolverRegistry() *ResolverRegistry {
	return &ResolverRegistry{
		resolvers: make(map[string]ResolverFunc),
	}
}

// Get returns the resolver for a method, if registered.
func (r *ResolverRegistry) Get(method string) (ResolverFunc, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	resolver, ok := r.resolvers[method]
	return resolver, ok
}

// ScopedForService creates a namespace-scoped registry that only allows
// registering resolvers for the given service's methods.
// This prevents services from registering resolvers for other services.
// Panics if serviceDesc is nil.
func (r *ResolverRegistry) ScopedForService(serviceDesc *grpc.ServiceDesc) *ScopedResolverRegistry {
	if serviceDesc == nil {
		panic("serviceDesc cannot be nil")
	}
	return &ScopedResolverRegistry{
		parent:      r,
		serviceDesc: serviceDesc,
	}
}

// register is internal - adds a resolver for a specific full method path.
// External callers should use ScopedResolverRegistry.
func (r *ResolverRegistry) register(fullMethodPath string, resolver ResolverFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resolvers[fullMethodPath] = resolver
}

// ScopedResolverRegistry is a namespace-scoped view of the registry.
// It only allows registering resolvers for the service it was created for.
type ScopedResolverRegistry struct {
	parent      *ResolverRegistry
	serviceDesc *grpc.ServiceDesc
}

// Register adds a resolver for a method in this service.
// Only the method name is required (e.g., "UpdateAttribute"), not the full path.
// The full path is derived from the ServiceDesc.
//
// Returns an error if the method doesn't exist in the ServiceDesc.
func (s *ScopedResolverRegistry) Register(methodName string, resolver ResolverFunc) error {
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
func (s *ScopedResolverRegistry) MustRegister(methodName string, resolver ResolverFunc) {
	if err := s.Register(methodName, resolver); err != nil {
		panic(err)
	}
}

// ServiceName returns the service name this registry is scoped to.
func (s *ScopedResolverRegistry) ServiceName() string {
	return s.serviceDesc.ServiceName
}

// NewResolverContext creates a new empty resolver context.
func NewResolverContext() ResolverContext {
	return ResolverContext{}
}

// NewResource creates and adds a new resource to the context.
func (a *ResolverContext) NewResource() *ResolverResource {
	resource := make(ResolverResource)
	a.Resources = append(a.Resources, &resource)
	return &resource
}

// AddDimension adds a dimension to the resource.
func (a *ResolverResource) AddDimension(dimension, value string) {
	(*a)[dimension] = value
}
