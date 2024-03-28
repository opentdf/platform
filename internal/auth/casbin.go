package auth

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2"
	casbinModel "github.com/casbin/casbin/v2/model"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/pkg/util"
	"golang.org/x/exp/slog"
)

var rolePrefix = "role:"
var defaultRole = "unknown"

var defaultRoleClaim = "realm_access.roles"

var defaultRoleMap = map[string]string{
	"readonly":  "opentdf-readonly",
	"admin":     "opentdf-admin",
	"org-admin": "opentdf-org-admin",
}

var defaultPolicy = `
## Roles (prefixed with role:)
# org-admin - organization admin
# admin - admin
# readonly - readonly
# unknown - unknown role or no role

## Resources
# Resources beginning with / are HTTP routes. Generally, this does not matter, but when HTTP routes don't map well
# with the protos this may become important.

## Actions
# read - read the resource
# write - write to the resource
# delete - delete the resource
# unsafe - unsafe actions

# Role: Org-Admin
## gRPC routes
p,	role:org-admin,		policy.*,																*,			allow
p,	role:org-admin,		kasregistry.*,													*,			allow
p,	role:org-admin,		kas.AccessService/LegacyPublicKey,			*,			allow
p,	role:org-admin,		kas.AccessService/PublicKey,						*,			allow
## HTTP routes
p,	role:org-admin,		/health,																*,			allow
p,	role:org-admin,		/attributes*,														*,			allow
p,	role:org-admin,		/namespaces*,														*,			allow
p,	role:org-admin,		/subject-mappings*,											*,			allow
p,	role:org-admin,		/resource-mappings*,										*,			allow
p,	role:org-admin,		/key-access-servers*,										*,			allow
p,	role:org-admin,		/kas.AccessService/LegacyPublicKey,			*,			allow
# add unsafe actions to the org-admin role

# Role: Admin
## gRPC routes
p,	role:admin,		policy.*,																		*,			allow
p,	role:admin,		kasregistry.*,															*,			allow
p,	role:admin,		kas.AccessService/Info,					            *,			allow
p,	role:admin,		kas.AccessService/Rewrap, 			            *,			allow
p,	role:admin,		kas.AccessService/LegacyPublicKey,					*,			allow
p,	role:admin,		kas.AccessService/PublicKey,								*,			allow
## HTTP routes
p,	role:admin,		/health,																		*,			allow
p,	role:admin,		/attributes*,																*,			allow
p,	role:admin,		/namespaces*,																*,			allow
p,	role:admin,		/subject-mappings*,													*,			allow
p,	role:admin,		/resource-mappings*,												*,			allow
p,	role:admin,		/key-access-servers*,												*,			allow
p,	role:admin,		/kas.AccessService/LegacyPublicKey,					*,			allow

## Role: Readonly
## gRPC routes
p,	role:readonly,		policy.*,																read,			allow
p,	role:readonly,		kasregistry.*,													read,			allow
p,	role:readonly,		kas.AccessService/Info,		 		             *,			allow
p,	role:readonly,    kas.AccessService/Rewrap, 			           *,			allow
p,	role:readonly,    kas.AccessService/LegacyPublicKey,				 *,			allow
p,	role:readonly,    kas.AccessService/PublicKey,							 *,			allow
## HTTP routes
p,	role:readonly,		/health,																read,			allow
p,	role:readonly,		/attributes*,														read,			allow
p,	role:readonly,		/namespaces*,														read,			allow
p,	role:readonly,		/subject-mappings*,											read,			allow
p,	role:readonly,		/resource-mappings*,										read,			allow
p,	role:readonly,		/key-access-servers*,										read,			allow
p,	role:readonly,		/kas.AccessService/LegacyPublicKey,			read,			allow

# Public routes
## gRPC routes
p,	role:unknown,			kas.AccessService/LegacyPublicKey,			other,	allow
p,	role:unknown,			kas.AccessService/PublicKey,						other,	allow
## HTTP routes
p,	role:unknown,			/health,																read,		allow
p,	role:unknown,			/kas/v2/kas_public_key,									read,		allow
p,	role:unknown,			/kas/kas_public_key,										read,		allow
`

var defaultModel = `
[request_definition]
r = sub,	res,	act

[policy_definition]
p = sub,	res,	act,	eft

[role_definition]
g = _,	_

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.sub,	p.sub) && keyMatch(r.res,	p.res) && keyMatch(r.act,	p.act)
`

type Enforcer struct {
	*casbin.Enforcer
	Config CasbinConfig
	Policy string
}

type casbinSubject struct {
	Subject string
	Roles   []string
}

type CasbinConfig struct {
	PolicyConfig
	Db *sql.DB
}

// newCasbinEnforcer creates a new casbin enforcer
func NewCasbinEnforcer(c CasbinConfig) (*Enforcer, error) {
	// TODO implement the sqlx adapter
	// sqlx := sqlx.NewDb(d, "pgx")
	// ca, err := sqlxadapter.NewAdapter(sqlx, "auth_casbin")
	// if err != nil {
	// 	return nil, err
	// }
	mStr := defaultModel
	if c.Model != "" {
		mStr = c.Model
	}
	pStr := defaultPolicy
	if c.Csv != "" {
		pStr = c.Csv
	}

	m, err := casbinModel.NewModelFromString(mStr)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin model: %w", err)
	}
	a := stringadapter.NewAdapter(pStr)
	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin enforcer: %w", err)
	}

	return &Enforcer{
		Enforcer: e,
		Config:   c,
		Policy:   pStr,
	}, nil
}

// casbinEnforce is a helper function to enforce the policy with casbin
// TODO implement a common type so this can be used for both http and grpc
func (e Enforcer) Enforce(token jwt.Token, resource, action string) (bool, error) {
	var err error
	permDeniedError := fmt.Errorf("permission denied")

	// extract the role claim from the token
	s, err := e.buildSubjectFromToken(token)
	if err != nil {
		slog.Error("failed to build subject from token", slog.String("error", err.Error()))
		return false, permDeniedError
	}

	if len(s.Roles) == 0 {
		sub := rolePrefix + defaultRole
		slog.Info("enforcing policy", slog.Any("subject", sub), slog.String("resource", resource), slog.String("action", action))
		return e.Enforcer.Enforce(sub, resource, action)
	}

	allowed := false
	for _, role := range s.Roles {
		sub := rolePrefix + role
		slog.Info("enforcing policy", slog.String("subject", sub), slog.String("resource", resource), slog.String("action", action))
		allowed, err = e.Enforcer.Enforce(sub, resource, action)
		if err != nil {
			slog.Error("failed to enforce policy", slog.String("error", err.Error()))
			continue
		}
		if allowed {
			break
		}
	}
	if !allowed {
		return false, permDeniedError
	}

	return true, nil
}

func (e Enforcer) buildSubjectFromToken(t jwt.Token) (casbinSubject, error) {
	roles, err := e.extractRolesFromToken(t)
	if err != nil {
		return casbinSubject{}, err
	}

	return casbinSubject{
		Subject: t.Subject(),
		Roles:   roles,
	}, nil
}

func (e Enforcer) extractRolesFromToken(t jwt.Token) ([]string, error) {
	roles := []string{}

	roleClaim := defaultRoleClaim
	if e.Config.RoleClaim != "" {
		roleClaim = e.Config.RoleClaim
	}

	roleMap := defaultRoleMap
	if len(e.Config.RoleMap) > 0 {
		roleMap = e.Config.RoleMap
	}

	p := strings.Split(roleClaim, ".")
	if n, ok := t.Get(p[0]); ok {
		// use dotnotation if the claim is nested
		r := n
		if len(p) > 1 {
			r = util.Dotnotation(n.(map[string]interface{}), strings.Join(p[1:], "."))
			if r == nil {
				slog.Warn("role claim not found", slog.String("claim", roleClaim), slog.Any("roles", n))
				return nil, nil
			}
		}

		// TODO test the type because an array of strings will panic
		for _, v := range r.([]interface{}) {
			switch vv := v.(type) {
			case string:
				roles = append(roles, vv)
			default:
			}
		}
	} else {
		slog.Warn("role claim not found", slog.String("claim", roleClaim), slog.Any("token", t))
		return nil, nil
	}

	// filter roles based on the role map
	filtered := []string{}
	for _, r := range roles {
		for m, rr := range roleMap {
			slog.Debug("checking role", slog.String("role", r), slog.String("map", m))
			// if the role is in the map, add the mapped role to the filtered list
			if r == rr {
				filtered = append(filtered, m)
			}
		}
	}

	if len(filtered) == 0 {
		filtered = append(filtered, defaultRole)
	}

	return filtered, nil
}
