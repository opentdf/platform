package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// AuthorizationMode indicates which authorization strategy was used for a decision.
type AuthorizationMode string

const (
	// AuthzModeV1 indicates legacy path-based authorization (v1 model).
	AuthzModeV1 AuthorizationMode = "v1"
	// AuthzModeV2 indicates RPC + dimensions authorization (v2 model).
	AuthzModeV2 AuthorizationMode = "v2"
)

// AuthorizationRequest encapsulates all information needed for an authorization decision.
// This is the contract between the interceptor and any authorization engine.
type AuthorizationRequest struct {
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
	// Populated by AuthzResolverRegistry when a resolver is registered for the RPC.
	ResourceContext *AuthzResolverContext
}

// AuthorizationDecision represents the result of an authorization check.
type AuthorizationDecision struct {
	// Allowed indicates whether the request is permitted.
	Allowed bool

	// Reason provides a human-readable explanation for audit logging.
	Reason string

	// Mode indicates which authorization model was used.
	Mode AuthorizationMode

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
// and register it via the AuthorizerFactory.
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
	Authorize(ctx context.Context, req *AuthorizationRequest) (*AuthorizationDecision, error)

	// Version returns the authorization model version this authorizer implements.
	// Returns "v1" for legacy path-based, "v2" for RPC+dimensions, etc.
	Version() string

	// SupportsResourceAuthorization returns true if this authorizer
	// supports resource-level authorization with dimensions.
	// If false, ResourceContext will always be ignored.
	SupportsResourceAuthorization() bool
}

// AuthorizerFactory creates Authorizer instances based on configuration.
// This allows the platform to instantiate different authorization engines
// (Casbin, OPA, Cedar) based on configuration.
type AuthorizerFactory func(cfg AuthorizerConfig) (Authorizer, error)

// AuthorizerConfig provides configuration for authorization engine initialization.
type AuthorizerConfig struct {
	// Version specifies which authorization model to use ("v1", "v2", etc.)
	Version string

	// Policy configuration (claims, CSV, adapter, etc.)
	PolicyConfig

	// Logger for authorization decisions
	Logger interface{}
}

// authorizers is a registry of authorization engine factories.
var authorizers = make(map[string]AuthorizerFactory)

// RegisterAuthorizer registers an authorization engine factory.
// This is called during init() by each authorizer implementation.
func RegisterAuthorizer(name string, factory AuthorizerFactory) {
	if _, exists := authorizers[name]; exists {
		panic(fmt.Sprintf("authorizer %q already registered", name))
	}
	authorizers[name] = factory
}

// NewAuthorizer creates an Authorizer based on configuration.
// The engine is selected based on cfg.Version:
//   - "v1": CasbinAuthorizer with legacy path-based model
//   - "v2": CasbinAuthorizer with RPC+dimensions model
//
// Future versions may support OPA, Cedar, etc.
func NewAuthorizer(cfg AuthorizerConfig) (Authorizer, error) {
	// Default to v1 for backwards compatibility
	if cfg.Version == "" {
		cfg.Version = "v1"
	}

	// For now, all versions use Casbin; future versions may use different engines
	factory, exists := authorizers["casbin"]
	if !exists {
		return nil, errors.New("casbin authorizer not registered")
	}

	return factory(cfg)
}
