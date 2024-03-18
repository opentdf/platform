package auth

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/pkg/util"
	"golang.org/x/exp/slog"
)

var defaultRole = "readonly"

var defaultRoleClaim = "realm_access.roles"

var defaultRoleMap = map[string]string{
	"readonly":  "opentdf-readonly",
	"admin":     "opentdf-admin",
	"org-admin": "opentdf-org-admin",
}

var defaultPolicy = `
# Built-in policy which defines two roles: role:readonly and role:admin,
# and additionally assigns the admin user to the role:admin role.
# There are two policy formats:
# 1. Applications, logs, and exec (which belong to a project):
# p, <user/group>, <resource>, <action>
# 2. All other resources:
# p, <user/group>, <resource>, <action>, <object>

p, role:org-admin, ^(policy\.attributes|/attributes).*, .*, allow
p, role:org-admin, ^(policy\.namespaces).*, .*, allow
p, role:org-admin, ^(policy\.subjectmappings|/subject-mappings).*, .*, allow
p, role:org-admin, ^(policy\.resourcemappings|/resource-mappings).*, .*, allow
p, role:org-admin, ^(kasregistry|/key-access-servers).*, .*, allow

p, role:readonly, ^(policy\.attributes|/attributes).*, read, allow
p, role:readonly, ^(policy\.namespaces).*, read, allow
p, role:readonly, ^(policy\.subjectmappings|/subject-mappings).*, read, allow
p, role:readonly, ^(policy\.resourcemappings|/resource-mappings).*, read, allow
p, role:readonly, ^(kasregistry|/key-access-servers).*, read, allow
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

type casbinSubject struct {
	Subject string
	Roles   []string
}

// newCasbinEnforcer creates a new casbin enforcer
func newCasbinEnforcer(d *sql.DB) (*casbin.Enforcer, error) {
	// TODO implement the sqlx adapter
	// sqlx := sqlx.NewDb(d, "pgx")
	// ca, err := sqlxadapter.NewAdapter(sqlx, "auth_casbin")
	// if err != nil {
	// 	return nil, err
	// }

	m, err := model.NewModelFromString(defaultModel)
	if err != nil {
		return nil, err
	}
	a := stringadapter.NewAdapter(defaultPolicy)
	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// casbinEnforce is a helper function to enforce the policy with casbin
// TODO implement a common type so this can be used for both http and grpc
func (a Authentication) casbinEnforce(_ context.Context, token jwt.Token, resource string, action string) error {
	var err error
	permDeniedError := fmt.Errorf("permission denied")

	// extract the role claim from the token
	s, err := buildSubjectFromToken(token)
	if err != nil {
		slog.Error("failed to build subject from token", slog.String("error", err.Error()))
		return permDeniedError
	}

	allowed := false
	for _, role := range s.Roles {
		sub := "role:" + role
		slog.Info("enforcing policy", slog.String("subject", sub), slog.String("resource", resource), slog.String("action", action))
		allowed, err = a.casbinEnforcer.Enforce(sub, resource, action)
		if err != nil {
			slog.Error("failed to enforce policy", slog.String("error", err.Error()))
			continue
		}
		if allowed {
			break
		}
	}
	if !allowed {
		return permDeniedError
	}

	return nil
}

func buildSubjectFromToken(token jwt.Token) (casbinSubject, error) {
	roles, err := extractRolesFromToken(token)
	if err != nil {
		return casbinSubject{}, err
	}

	return casbinSubject{
		Subject: token.Subject(),
		Roles:   roles,
	}, nil
}

func extractRolesFromToken(token jwt.Token) ([]string, error) {
	roles := []string{}
	if defaultRoleClaim != "" {
		p := strings.Split(defaultRoleClaim, ".")
		k := p[0]
		if n, ok := token.Get(k); ok {
			r := util.Dotnotation(n.(map[string]interface{}), strings.Join(p[1:], "."))
			if r == nil {
				return nil, fmt.Errorf("role claim not found")
			}
			for _, v := range r.([]interface{}) {
				switch vv := v.(type) {
				case string:
					roles = append(roles, vv)
				default:
				}
			}
		}
	}

	// filter roles based on the role map
	fRoles := []string{}
	for _, r := range roles {
		for m, rr := range defaultRoleMap {
			slog.Info("checking role", slog.String("role", r), slog.String("map", m))
			if r == rr {
				fRoles = append(fRoles, m)
			}
		}
	}

	if len(fRoles) == 0 {
		fRoles = append(fRoles, defaultRole)
	}

	return fRoles, nil
}
