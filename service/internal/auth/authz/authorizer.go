// Package authz provides the authorization interface and types for the OpenTDF platform.
// It defines the contract between the authentication middleware and authorization engines.
package authz

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Mode indicates which authorization strategy was used for a decision.
type Mode string

const (
	// ModeV1 indicates legacy path-based authorization (v1 model).
	ModeV1 Mode = "v1"
	// ModeV2 indicates RPC + dimensions authorization (v2 model).
	ModeV2 Mode = "v2"
)

// Request encapsulates all information needed for an authorization decision.
// This is the contract between the interceptor and any authorization engine.
type Request struct {
	// Subject information extracted from JWT
	Token    jwt.Token
	UserInfo []byte // Optional userInfo from IdP

	// RPC method path (e.g., "/policy.attributes.AttributesService/UpdateAttribute")
	// Used as the primary resource identifier in v2 model.
	RPC string

	// Action derived from RPC method (read, write, delete, unsafe).
	// Used in v1 model; informational in v2 model.
	Action string

	// ResourceContext contains resolved authorization dimensions (namespace, attribute, etc.).
	// If non-nil, indicates resource-level authorization should be attempted.
	// Populated by ResolverRegistry when a resolver is registered for the RPC.
	ResourceContext *ResolverContext
}

// Decision represents the result of an authorization check.
type Decision struct {
	// Allowed indicates whether the request is permitted.
	Allowed bool

	// Reason provides a human-readable explanation for audit logging.
	Reason string

	// Mode indicates which authorization model was used.
	Mode Mode

	// MatchedPolicy optionally contains the policy rule that matched (for debugging).
	MatchedPolicy string
}

// Authorizer is the interface for pluggable authorization engines.
// Implementations must be thread-safe.
//
// The OpenTDF platform supports multiple authorization versions:
//   - v1: Legacy path-based authorization using (subject, resource, action) tuple
//   - v2: RPC + dimensions authorization using (subject, rpc, dimensions) tuple
//
// When implementing a new authorization engine (e.g., OPA, Cedar), implement this interface
// and register it via the Factory.
type Authorizer interface {
	// Authorize performs an authorization check.
	//
	// The implementation should:
	// 1. Extract subjects (roles/username) from the token
	// 2. Apply the appropriate authorization model based on configuration
	// 3. For v2: Use ResourceContext dimensions if available
	// 4. Return an error only for system failures, not for denied access
	//
	// Thread-safety: This method may be called concurrently from multiple goroutines.
	Authorize(ctx context.Context, req *Request) (*Decision, error)

	// Version returns the authorization model version this authorizer implements.
	// Returns "v1" for legacy path-based, "v2" for RPC+dimensions, etc.
	Version() string

	// SupportsResourceAuthorization returns true if this authorizer
	// supports resource-level authorization with dimensions.
	// If false, ResourceContext will always be ignored.
	SupportsResourceAuthorization() bool
}

// Factory creates Authorizer instances based on configuration.
// This allows the platform to instantiate different authorization engines
// (Casbin, OPA, Cedar) based on configuration.
type Factory func(cfg Config) (Authorizer, error)

// Config provides configuration for authorization engine initialization.
type Config struct {
	// Version specifies which authorization model to use ("v1", "v2", etc.)
	Version string

	// Policy configuration (claims, CSV, adapter, etc.)
	PolicyConfig

	// Logger for authorization decisions
	Logger any

	// Options for engine-specific configuration
	Options []Option
}

// Option is a functional option for authorizer configuration.
type Option func(*optionConfig)

// optionConfig holds optional configuration for authorizers.
type optionConfig struct {
	// V1Enforcer is the legacy casbin enforcer for v1 authorization.
	// When provided, the casbin authorizer will delegate v1 auth to this enforcer
	// instead of creating its own.
	V1Enforcer V1Enforcer
}

// V1Enforcer is the interface for the legacy v1 casbin enforcer.
// This allows the casbin authorizer to delegate v1 authorization
// to the existing enforcer without circular dependencies.
type V1Enforcer interface {
	// Enforce checks if the given token and userInfo are allowed to perform the action on the resource.
	Enforce(token jwt.Token, userInfo []byte, resource, action string) bool

	// BuildSubjectFromTokenAndUserInfo extracts subjects (roles/username) from token and userInfo.
	BuildSubjectFromTokenAndUserInfo(token jwt.Token, userInfo []byte) []string
}

// WithV1Enforcer sets the v1 enforcer for backwards compatibility.
// This option is used when initializing a casbin authorizer that needs
// to support both v1 and v2 authorization modes.
func WithV1Enforcer(enforcer V1Enforcer) Option {
	return func(cfg *optionConfig) {
		cfg.V1Enforcer = enforcer
	}
}

// ApplyOptions applies the given options and returns the resulting config.
func ApplyOptions(opts ...Option) *optionConfig {
	cfg := &optionConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// factories is a registry of authorization engine factories.
var (
	factories   = make(map[string]Factory)
	factoriesMu sync.RWMutex
)

// RegisterFactory registers an authorization engine factory.
// This is called during init() by each authorizer implementation.
func RegisterFactory(name string, factory Factory) {
	factoriesMu.Lock()
	defer factoriesMu.Unlock()
	if _, exists := factories[name]; exists {
		panic(fmt.Sprintf("authorizer %q already registered", name))
	}
	factories[name] = factory
}

// GetFactory returns the factory for the given name, if registered.
func GetFactory(name string) (Factory, bool) {
	factoriesMu.RLock()
	defer factoriesMu.RUnlock()
	factory, exists := factories[name]
	return factory, exists
}

// New creates an Authorizer based on configuration.
// The engine is selected based on cfg.Version:
//   - "v1": CasbinAuthorizer with legacy path-based model
//   - "v2": CasbinAuthorizer with RPC+dimensions model
//
// Future versions may support OPA, Cedar, etc.
func New(cfg Config) (Authorizer, error) {
	// Default to v1 for backwards compatibility
	if cfg.Version == "" {
		cfg.Version = "v1"
	}

	// For now, all versions use Casbin; future versions may use different engines
	factory, exists := GetFactory("casbin")
	if !exists {
		return nil, errors.New("casbin authorizer not registered")
	}

	return factory(cfg)
}
