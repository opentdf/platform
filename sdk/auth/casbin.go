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

## Resources
# policy.attributes - attributes policy
# policy.namespaces - namespaces policy
# policy.subjectmappings - subjectmappings policy
# policy.resourcemappings - resourcemappings policy
# kasregistry - key access servers registry

## Actions
# read - read the resource
# write - write to the resource
# delete - delete the resource
# unsafe - unsafe actions

p, role:org-admin, ^(policy\.attributes|/attributes).*, .*, allow
p, role:org-admin, ^(policy\.namespaces).*, .*, allow
p, role:org-admin, ^(policy\.subjectmappings|/subject-mappings).*, .*, allow
p, role:org-admin, ^(policy\.resourcemappings|/resource-mappings).*, .*, allow
p, role:org-admin, ^(kasregistry|/key-access-servers).*, .*, allow
# add unsafe actions to the org-admin role

p, role:admin, ^(policy\.attributes|/attributes).*, .*, allow
p, role:admin, ^(policy\.namespaces).*, .*, allow
p, role:admin, ^(policy\.subjectmappings|/subject-mappings).*, .*, allow
p, role:admin, ^(policy\.resourcemappings|/resource-mappings).*, .*, allow
p, role:admin, ^(kasregistry|/key-access-servers).*, .*, allow

p, role:readonly, ^(policy\.attributes|/attributes).*, read, allow
p, role:readonly, ^(policy\.namespaces).*, read, allow
p, role:readonly, ^(policy\.subjectmappings|/subject-mappings).*, read, allow
p, role:readonly, ^(policy\.resourcemappings|/resource-mappings).*, read, allow
p, role:readonly, ^(kasregistry|/key-access-servers).*, read, allow

p, role:unknown, .*, .*, deny
`

var defaultModel = `
[request_definition]
r = sub, res, act

[policy_definition]
p = sub, res, act, eft

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.sub, p.sub) && regexMatch(r.res, p.res) && regexMatch(r.act, p.act)
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
		return nil, err
	}
	a := stringadapter.NewAdapter(pStr)
	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		return nil, err
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

	allowed := false
	for _, role := range s.Roles {
		sub := "role:" + role
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
				return nil, fmt.Errorf("role claim not found")
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
