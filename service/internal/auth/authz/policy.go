package authz

// PolicyConfig contains the policy configuration for authorization.
// This is a subset of the fields from auth.PolicyConfig that are relevant
// for authorization engines.
type PolicyConfig struct {
	// Version specifies the authorization model version to use.
	// - "v1" (default): Legacy path-based authorization (subject, resource, action)
	// - "v2": RPC + dimensions authorization (subject, rpc, dimensions)
	Version string

	// Username claim to use for user information
	UserNameClaim string

	// Claims to use for group/role information (supports multiple claims)
	GroupsClaim []string

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
}
