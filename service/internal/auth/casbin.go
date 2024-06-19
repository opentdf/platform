package auth

import (
	"fmt"
	"strings"

	"log/slog"

	"github.com/casbin/casbin/v2"
	casbinModel "github.com/casbin/casbin/v2/model"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/pkg/util"
)

var rolePrefix = "role:"
var defaultRole = "unknown"

var defaultRoleClaim = "realm_access.roles"

var defaultRoleMap = map[string]string{
	"standard":  "opentdf-standard",
	"admin":     "opentdf-admin",
	"org-admin": "opentdf-org-admin",
}

var defaultPolicy = `
## Roles (prefixed with role:)
# org-admin - organization admin
# admin - admin
# standard - standard
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
p,	role:org-admin,		kas.AccessService/Rewrap, 			            *,			allow
## HTTP routes
p,	role:org-admin,		/attributes*,														*,			allow
p,	role:org-admin,		/namespaces*,														*,			allow
p,	role:org-admin,		/subject-mappings*,											*,			allow
p,	role:org-admin,		/resource-mappings*,										*,			allow
p,	role:org-admin,		/key-access-servers*,										*,			allow
p,	role:org-admin, 	/kas/v2/rewrap,						  		*,      allow
p,	role:org-admin,		/unsafe*,										*,			allow

# Role: Admin
## gRPC routes
p,	role:admin,		policy.*,																		*,			allow
p,	role:admin,		kasregistry.*,															*,			allow
p,	role:admin,		kas.AccessService/Info,					            *,			allow
p,	role:admin,		kas.AccessService/Rewrap, 			            *,			allow
## HTTP routes
p,	role:admin,		/attributes*,																*,			allow
p,	role:admin,		/namespaces*,																*,			allow
p,	role:admin,		/subject-mappings*,													*,			allow
p,	role:admin,		/resource-mappings*,												*,			allow
p,	role:admin,		/key-access-servers*,												*,			allow
p,	role:admin,		/kas/v2/rewrap,						  				*,      allow

## Role: Standard
## gRPC routes
p,	role:standard,		policy.*,																read,			allow
p,	role:standard,		kasregistry.*,													read,			allow
p,	role:standard,		kas.AccessService/Info,		 		             *,			allow
p,	role:standard,    kas.AccessService/Rewrap, 			           *,			allow
## HTTP routes
p,	role:standard,		/attributes*,														read,			allow
p,	role:standard,		/namespaces*,														read,			allow
p,	role:standard,		/subject-mappings*,											read,			allow
p,	role:standard,		/resource-mappings*,										read,			allow
p,	role:standard,		/key-access-servers*,										read,			allow
p,	role:standard,		/kas/v2/rewrap,													write,		allow
p,	role:standard,		/entityresolution/resolve,							write,  	allow

# Public routes
## gRPC routes
## for ERS, right now we don't care about requester role, just that a valid jwt is provided when the OPA engine calls (enforced in the ERS itself, not casbin)
p,	role:unknown,			entityresolution.EntityResolutionService.ResolveEntities,										write,		allow
## HTTP routes
## for ERS, right now we don't care about requester role, just that a valid jwt is provided when the OPA engine calls (enforced in the ERS itself, not casbin)
p,	role:unknown,			/entityresolution/resolve,										write,		allow
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

	slog.Debug("creating casbin enforcer", slog.Any("config", c))

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
	s := e.buildSubjectFromToken(token)

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

func (e Enforcer) buildSubjectFromToken(t jwt.Token) casbinSubject {
	slog.Debug("building subject from token", slog.Any("token", t))
	roles := e.extractRolesFromToken(t)

	return casbinSubject{
		Subject: t.Subject(),
		Roles:   roles,
	}
}

func (e Enforcer) extractRolesFromToken(t jwt.Token) []string {
	slog.Debug("extracting roles from token", slog.Any("token", t))
	roles := []string{}

	roleClaim := defaultRoleClaim
	if e.Config.RoleClaim != "" {
		roleClaim = e.Config.RoleClaim
	}

	roleMap := defaultRoleMap
	if len(e.Config.RoleMap) > 0 {
		roleMap = e.Config.RoleMap
	}

	selectors := strings.Split(roleClaim, ".")
	claim, exists := t.Get(selectors[0])
	if !exists {
		slog.Warn("claim not found", slog.String("claim", roleClaim), slog.Any("token", t))
		return nil
	}
	slog.Debug("root claim found", slog.String("claim", roleClaim), slog.Any("claims", claim))
	// use dotnotation if the claim is nested
	if len(selectors) > 1 {
		claimMap, ok := claim.(map[string]interface{})
		if !ok {
			slog.Warn("claim is not of type map[string]interface{}", slog.String("claim", roleClaim), slog.Any("claims", claim))
			return nil
		}
		claim = util.Dotnotation(claimMap, strings.Join(selectors[1:], "."))
		if claim == nil {
			slog.Warn("claim not found", slog.String("claim", roleClaim), slog.Any("claims", claim))
			return nil
		}
	}

	// check the type of the role claim
	switch v := claim.(type) {
	case string:
		roles = append(roles, v)
	case []interface{}:
		for _, rr := range v {
			if r, ok := rr.(string); ok {
				roles = append(roles, r)
			}
		}
	default:
		slog.Warn("could not get claim type", slog.String("selector", roleClaim), slog.Any("claims", claim))
		return nil
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

	return filtered
}
