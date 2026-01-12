package authz

import "gorm.io/gorm"

// PolicyConfig contains the policy configuration for authorization.
// This mirrors auth.PolicyConfig to avoid circular imports while maintaining
// the same field structure for consistent configuration.
type PolicyConfig struct {
	// Engine specifies the authorization engine to use.
	// - "casbin" (default): Casbin policy engine
	// - "cedar": AWS Cedar policy engine (future)
	// - "opa": Open Policy Agent engine (future)
	Engine string

	// Version specifies the engine-specific authorization model version.
	// For Casbin:
	// - "v1" (default): Legacy path-based authorization (subject, resource, action)
	// - "v2": RPC + dimensions authorization (subject, rpc, dimensions)
	Version string

	// Username claim to use for user information
	UserNameClaim string

	// Claim to use for group/role information (dot notation supported, e.g., "realm_access.roles")
	GroupsClaim string

	// Claim to use to reference idP clientID
	ClientIDClaim string

	// Override the builtin policy with a custom policy (CSV format)
	Csv string

	// Extend the builtin policy with a custom policy
	Extension string

	// Casbin model configuration (for custom models)
	Model string

	// RoleMap maps IdP roles to internal platform roles
	// Deprecated: Use Casbin grouping statements g, <user/group>, <role>
	RoleMap map[string]string

	// Adapter is an optional custom policy adapter (e.g., SQL)
	// If nil, the default CSV string adapter is used.
	Adapter any

	// GormDB is the GORM database connection for SQL adapter (v2 only).
	// If provided, v2 authorization uses SQL adapter for policy storage.
	GormDB *gorm.DB

	// Schema for casbin_rule table (defaults to DB search_path).
	// Only used when GormDB is provided for v2 authorization.
	Schema string
}
