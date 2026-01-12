package authz

import (
	"github.com/casbin/casbin/v2/persist"
	"gorm.io/gorm"
)

// EngineType identifies the authorization engine implementation.
type EngineType string

const (
	// EngineCasbin uses Casbin for policy enforcement.
	EngineCasbin EngineType = "casbin"
	// // EngineCedar uses AWS Cedar for policy enforcement (future).
	// EngineCedar EngineType = "cedar"
	// // EngineOPA uses Open Policy Agent for policy enforcement (future).
	// EngineOPA EngineType = "opa"
)

// BaseAdapterConfig contains configuration common to all authorization adapters.
// This provides a consistent interface for subject extraction across engines.
type BaseAdapterConfig struct {
	// UserNameClaim is the JWT claim containing the username.
	UserNameClaim string

	// GroupsClaim is the JWT claim containing roles/groups (dot notation supported).
	// Example: "realm_access.roles" for Keycloak.
	GroupsClaim string

	// ClientIDClaim is the JWT claim containing the client ID.
	ClientIDClaim string

	// Logger for authorization decisions (type: *logger.Logger)
	Logger any
}

// CasbinV1Config configures the legacy path-based Casbin authorizer.
// This model uses (subject, resource, action) tuples for authorization.
//
// Example policy:
//
//	p, role:admin, *, *, allow
//	p, role:standard, /attributes*, read, allow
type CasbinV1Config struct {
	BaseAdapterConfig

	// Csv is the policy CSV content (overrides builtin if set).
	Csv string

	// Extension appends additional rules to the policy.
	Extension string

	// Model is the Casbin model configuration.
	// If empty, uses the default RBAC model.
	Model string

	// RoleMap maps external IdP roles to internal platform roles.
	// Deprecated: Use Casbin grouping statements instead.
	RoleMap map[string]string

	// Adapter is a custom policy adapter (e.g., SQL).
	// If nil, uses string adapter with Csv content.
	Adapter persist.Adapter

	// Enforcer is an existing v1 enforcer to delegate to.
	// If provided, other policy fields are ignored.
	Enforcer V1Enforcer
}

// CasbinV2Config configures the RPC + dimensions Casbin authorizer.
// This model uses (subject, rpc, dimensions) tuples for authorization.
//
// Example policy:
//
//	p, role:admin, *, *, allow
//	p, role:standard, /policy.attributes.AttributesService/*, read, allow
//	p, role:ns-admin, /policy.attributes.AttributesService/*, *, ns:my-namespace, allow
type CasbinV2Config struct {
	BaseAdapterConfig

	// Csv is the policy CSV content (overrides builtin if set).
	Csv string

	// Extension appends additional rules to the policy.
	Extension string

	// Model is the Casbin model configuration.
	// If empty, uses the v2 model with dimension support.
	Model string

	// RoleMap maps external IdP roles to internal platform roles.
	// Deprecated: Use Casbin grouping statements instead.
	RoleMap map[string]string

	// Adapter is a custom policy adapter (e.g., SQL).
	// If nil, uses string adapter with Csv content.
	Adapter persist.Adapter

	// GormDB is the GORM database connection for SQL adapter.
	// If provided, uses SQL adapter for policy storage.
	// Takes precedence over Adapter if both are set.
	GormDB *gorm.DB

	// Schema for casbin_rule table (defaults to DB search_path).
	// Only used when GormDB is provided.
	Schema string
}

// CedarConfig configures the AWS Cedar authorization engine (future).
// Cedar provides a policy language with strong typing and formal verification.
type CedarConfig struct {
	BaseAdapterConfig

	// SchemaPath is the path to the Cedar schema file.
	SchemaPath string

	// PoliciesPath is the path to Cedar policy files.
	PoliciesPath string

	// EntitiesPath is the path to Cedar entities file.
	EntitiesPath string
}

// OPAConfig configures the Open Policy Agent authorization engine (future).
// OPA provides a general-purpose policy engine with Rego query language.
type OPAConfig struct {
	BaseAdapterConfig

	// BundlePath is the path to the OPA bundle.
	BundlePath string

	// Query is the Rego query for authorization decisions.
	Query string
}

// AdapterConfigFromExternal maps external configuration to the appropriate
// internal adapter configuration. This provides a clean boundary between
// customer-facing config (stable) and internal adapter config (can evolve).
//
// The external PolicyConfig is what customers configure in YAML/JSON.
// The internal adapter configs are what the authorization engines consume.
//
// Engine selection:
//   - "casbin" (default): Returns CasbinV1Config or CasbinV2Config based on Version
//   - "cedar": Returns CedarConfig (future)
//   - "opa": Returns OPAConfig (future)
func AdapterConfigFromExternal(cfg Config) any {
	base := BaseAdapterConfig{
		UserNameClaim: cfg.UserNameClaim,
		GroupsClaim:   cfg.GroupsClaim,
		ClientIDClaim: cfg.ClientIDClaim,
		Logger:        cfg.Logger,
	}

	opts := applyOptions(cfg.Options...)

	// Default engine to casbin for backwards compatibility
	engine := cfg.Engine
	if engine == "" {
		engine = string(EngineCasbin)
	}

	switch engine {
	case string(EngineCasbin):
		return casbinConfigFromExternal(cfg, base, opts)
	// Future engines:
	// case string(EngineCedar):
	//     return cedarConfigFromExternal(cfg, base)
	// case string(EngineOPA):
	//     return opaConfigFromExternal(cfg, base)
	default:
		// Unknown engine defaults to casbin v1 for backwards compatibility
		return casbinConfigFromExternal(cfg, base, opts)
	}
}

// casbinConfigFromExternal creates the appropriate Casbin config based on version.
func casbinConfigFromExternal(cfg Config, base BaseAdapterConfig, opts *optionConfig) any {
	switch cfg.Version {
	case "v2":
		return CasbinV2Config{
			BaseAdapterConfig: base,
			Csv:               cfg.Csv,
			Extension:         cfg.Extension,
			Model:             cfg.Model,
			RoleMap:           cfg.RoleMap,
			Adapter:           adapterFromAny(cfg.Adapter),
			GormDB:            cfg.GormDB,
			Schema:            cfg.Schema,
		}
	default: // v1 or empty
		return CasbinV1Config{
			BaseAdapterConfig: base,
			Csv:               cfg.Csv,
			Extension:         cfg.Extension,
			Model:             cfg.Model,
			RoleMap:           cfg.RoleMap,
			Adapter:           adapterFromAny(cfg.Adapter),
			Enforcer:          opts.V1Enforcer,
		}
	}
}

// adapterFromAny converts an any type to persist.Adapter.
// Returns nil if the value is nil or not an Adapter.
func adapterFromAny(v any) persist.Adapter {
	if v == nil {
		return nil
	}
	if adapter, ok := v.(persist.Adapter); ok {
		return adapter
	}
	return nil
}
