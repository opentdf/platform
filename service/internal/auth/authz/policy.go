package authz

// PolicyConfig contains the policy configuration for authorization.
type PolicyConfig struct {
	Builtin string `mapstructure:"-" json:"-"`

	// Issuer is the configured token issuer for role provider requests.
	Issuer string `mapstructure:"-" json:"-"`

	// Engine specifies the authorization engine to use.
	// - "casbin" (default): Casbin policy engine
	// - "cedar": AWS Cedar policy engine (future)
	// - "opa": Open Policy Agent engine (future)
	Engine string `mapstructure:"engine" json:"engine" default:"casbin"`

	// Version specifies the engine-specific authorization model version.
	// For Casbin:
	// - "v1" (default): Legacy path-based authorization (subject, resource, action)
	// - "v2": RPC + dimensions authorization (subject, rpc, dimensions)
	// v2 enables fine-grained resource-level authorization using AuthzResolvers.
	Version string `mapstructure:"version" json:"version" default:"v1"`

	// Username claim to use for user information
	UserNameClaim string `mapstructure:"username_claim" json:"username_claim" default:"preferred_username"`

	// Claim to use for group/role information
	GroupsClaim string `mapstructure:"groups_claim" json:"groups_claim" default:"realm_access.roles"`

	// Role provider configuration (resolved via StartOptions)
	RolesProvider RolesProviderConfig `mapstructure:"roles_provider" json:"roles_provider"`

	// Claim to use to reference idP clientID
	ClientIDClaim string `mapstructure:"client_id_claim" json:"client_id_claim" default:"azp"`

	// Deprecated: Use GroupsClaim instead
	RoleClaim string `mapstructure:"claim" json:"claim" default:"realm_access.roles"`

	// Deprecated: Use Casbin grouping statements g, <user/group>, <role>
	RoleMap map[string]string `mapstructure:"map" json:"map"`

	// Override the builtin policy with a custom policy
	Csv string `mapstructure:"csv" json:"csv"`

	// Extend the builtin policy with a custom policy
	Extension string `mapstructure:"extension" json:"extension"`

	Model string `mapstructure:"model" json:"model"`

	// Adapter is intentionally any to allow future adapter config shapes beyond Casbin persist.Adapter.
	// Conversion and validation happen downstream.
	Adapter any `mapstructure:"-" json:"-"`
}

// RolesProviderConfig contains role-provider selection and provider-specific settings.
type RolesProviderConfig struct {
	Name   string         `mapstructure:"name" json:"name"`
	Config map[string]any `mapstructure:"config" json:"config"`
}
