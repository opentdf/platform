package authz

import (
	"github.com/casbin/casbin/v2/persist"
	platformauthz "github.com/opentdf/platform/service/pkg/authz"
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

// CasbinV1Config configures the legacy path-based Casbin authorizer.
// This model uses (subject, resource, action) tuples for authorization.
//
// Example policy:
//
//	p, role:admin, *, *, allow
//	p, role:standard, /attributes*, read, allow
type CasbinV1Config struct {
	PolicyConfig

	// RoleProvider extracts role/group subjects.
	RoleProvider platformauthz.RoleProvider

	// Adapter is a custom policy adapter (e.g., SQL).
	// If nil, uses string adapter with Csv content.
	Adapter persist.Adapter
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
	PolicyConfig

	// RoleProvider extracts role/group subjects.
	RoleProvider platformauthz.RoleProvider

	// Adapter is a custom policy adapter (e.g., SQL).
	// If nil, uses string adapter with Csv content.
	Adapter persist.Adapter
}

// CedarConfig configures the AWS Cedar authorization engine (future).
// Cedar provides a policy language with strong typing and formal verification.
type CedarConfig struct {
	PolicyConfig

	// RoleProvider extracts role/group subjects.
	RoleProvider platformauthz.RoleProvider

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
	PolicyConfig

	// RoleProvider extracts role/group subjects.
	RoleProvider platformauthz.RoleProvider

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
	policyCfg := cfg.PolicyConfig

	opts := applyOptions(cfg.Options...)

	// Default engine to casbin for backwards compatibility
	engine := cfg.Engine
	if engine == "" {
		engine = string(EngineCasbin)
	}

	switch engine {
	case string(EngineCasbin):
		return casbinConfigFromExternal(cfg, policyCfg, opts.RoleProvider)
	// Future engines:
	// case string(EngineCedar):
	//     return cedarConfigFromExternal(cfg, base)
	// case string(EngineOPA):
	//     return opaConfigFromExternal(cfg, base)
	default:
		// Unknown engine defaults to casbin v1 for backwards compatibility
		return casbinConfigFromExternal(cfg, policyCfg, opts.RoleProvider)
	}
}

// casbinConfigFromExternal creates the appropriate Casbin config based on version.
func casbinConfigFromExternal(cfg Config, policyCfg PolicyConfig, roleProvider platformauthz.RoleProvider) any {
	switch cfg.Version {
	case "v2":
		return CasbinV2Config{
			PolicyConfig: policyCfg,
			RoleProvider: roleProvider,
			Adapter:      adapterFromAny(policyCfg.Adapter),
		}
	default: // v1 or empty
		return CasbinV1Config{
			PolicyConfig: policyCfg,
			RoleProvider: roleProvider,
			Adapter:      adapterFromAny(policyCfg.Adapter),
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
