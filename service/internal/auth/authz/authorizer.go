// Package authz provides the authorization interface and types for the OpenTDF platform.
// It defines the contract between the authentication middleware and authorization engines.
package authz

import (
	"context"
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwt"
	platformauthz "github.com/opentdf/platform/service/pkg/authz"
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
	Token jwt.Token

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

	// Metadata contains supplemental information for audit logging.
	Metadata DecisionMetadata
}

// DecisionMetadata contains supplemental authorization decision metadata.
type DecisionMetadata struct {
	// GroupsClaim is the configured JWT claim used to extract authorization groups.
	GroupsClaim string
}

// EnforcementResult represents the v1 authorization enforcement result.
type EnforcementResult struct {
	// Allowed indicates whether the request is permitted.
	Allowed bool

	// GroupsClaim is the configured JWT claim used to extract authorization groups.
	GroupsClaim string
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
	// RoleProvider extracts role/group subjects for authorization.
	RoleProvider platformauthz.RoleProvider
}

// WithRoleProvider sets the role provider used for subject extraction.
func WithRoleProvider(provider platformauthz.RoleProvider) Option {
	return func(cfg *optionConfig) {
		cfg.RoleProvider = provider
	}
}

// applyOptions applies the given options and returns the resulting config.
func applyOptions(opts ...Option) *optionConfig {
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

// DefaultEngine is the default authorization engine when none is specified.
const DefaultEngine = "casbin"

// New creates an Authorizer based on configuration.
// The engine is selected based on cfg.PolicyConfig.Engine:
//   - "casbin" (default): Casbin policy engine
//   - "cedar": AWS Cedar policy engine (future)
//   - "opa": Open Policy Agent engine (future)
//
// For Casbin, the version determines the authorization model:
//   - "v1" (default): Legacy path-based model (subject, resource, action)
//   - "v2": RPC+dimensions model (subject, rpc, dimensions)
func New(cfg Config) (Authorizer, error) {
	// Default engine to casbin for backwards compatibility
	engine := cfg.Engine
	if engine == "" {
		engine = DefaultEngine
	}

	factory, exists := GetFactory(engine)
	if !exists {
		return nil, fmt.Errorf("authorization engine %q not registered", engine)
	}

	return factory(cfg)
}
