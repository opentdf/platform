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

	// ResolvedData stores data fetched during resolution (e.g., attributes, namespaces)
	// to avoid duplicate DB queries in handlers. Keys are service-defined strings.
	// Handlers can retrieve this data via GetResolvedDataFromContext().
	ResolvedData map[string]any
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

// SetResolvedData stores data in the resolver context cache.
// Use this to cache fetched resources (e.g., attributes) for handler reuse.
// The key should be a descriptive string (e.g., "attribute", "namespace").
func (a *ResolverContext) SetResolvedData(key string, value any) {
	if a.ResolvedData == nil {
		a.ResolvedData = make(map[string]any)
	}
	a.ResolvedData[key] = value
}

// GetResolvedData retrieves cached data by key.
// Returns nil if key not found. Caller should type-assert the result.
func (a *ResolverContext) GetResolvedData(key string) any {
	if a.ResolvedData == nil {
		return nil
	}
	return a.ResolvedData[key]
}

// resolverContextKey is the context key for storing ResolverContext.
type resolverContextKey struct{}

// ContextWithResolverContext returns a new context with the ResolverContext attached.
// This is called by the auth interceptor after resolution to make cached data
// available to handlers.
func ContextWithResolverContext(ctx context.Context, rc *ResolverContext) context.Context {
	return context.WithValue(ctx, resolverContextKey{}, rc)
}

// ResolverContextFromContext retrieves the ResolverContext from the context.
// Returns nil if not present (e.g., no resolver registered for the method).
func ResolverContextFromContext(ctx context.Context) *ResolverContext {
	rc, _ := ctx.Value(resolverContextKey{}).(*ResolverContext)
	return rc
}

// GetResolvedDataFromContext is a convenience function to retrieve cached data
// from the ResolverContext in the given context.
// Returns nil if no ResolverContext or key not found.
func GetResolvedDataFromContext(ctx context.Context, key string) any {
	rc := ResolverContextFromContext(ctx)
	if rc == nil {
		return nil
	}
	return rc.GetResolvedData(key)
}
