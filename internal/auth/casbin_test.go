package auth

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/casbin/casbin/v2/model"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestAuthnCasbinSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping attributes integration tests")
	}
	suite.Run(t, new(AuthnCasbinSuite))
}

// ---

type AuthnCasbinSuite struct {
	suite.Suite
}

func (s *AuthnCasbinSuite) buildTokenRoles(orgAdmin bool, admin bool, readonly bool, roleMaps []string) []interface{} {
	orgAdminRole := "opentdf-org-admin"
	if len(roleMaps) > 0 {
		orgAdminRole = roleMaps[0]
	}
	adminRole := "opentdf-admin"
	if len(roleMaps) > 1 {
		adminRole = roleMaps[1]
	}
	readonlyRole := "opentdf-readonly"
	if len(roleMaps) > 2 {
		readonlyRole = roleMaps[2]
	}

	i := 0
	roles := make([]interface{}, 3)

	if orgAdmin {
		roles[i] = orgAdminRole
		i++
	}
	if admin {
		roles[i] = adminRole
		i++
	}
	if readonly {
		roles[i] = readonlyRole
		i++
	}

	return roles
}

func (s *AuthnCasbinSuite) newTokWithDefaultClaim(orgAdmin bool, admin bool, readonly bool) (string, jwt.Token) {
	tok := jwt.New()
	tok.Set("realm_access", map[string]interface{}{
		"roles": s.buildTokenRoles(orgAdmin, admin, readonly, nil),
	})
	return "", tok
}

func (s *AuthnCasbinSuite) newTokenWithCustomClaim(orgAdmin bool, admin bool, readonly bool) (string, jwt.Token) {
	tok := jwt.New()
	tok.Set("test", map[string]interface{}{
		"test_roles": s.buildTokenRoles(orgAdmin, admin, readonly, nil),
	})

	return "test.test_roles", tok
}

func (s *AuthnCasbinSuite) newTokenWithCustomRoleMap(orgAdmin bool, admin bool, readonly bool) (string, jwt.Token) {
	tok := jwt.New()
	tok.Set("realm_access", map[string]interface{}{
		"roles": s.buildTokenRoles(orgAdmin, admin, readonly, []string{"test-org-admin", "test-admin", "test-readonly"}),
	})
	return "", tok
}

func (s *AuthnCasbinSuite) SetupSuite() {
}

func (s *AuthnCasbinSuite) TeardownSuite() {
}

func (s *AuthnCasbinSuite) Test_NewEnforcerWithDefaults() {
	eModel, err := model.NewModelFromString(defaultModel)
	if err != nil {
		s.T().Fatal(err)
	}
	enforcer, err := NewCasbinEnforcer(CasbinConfig{})

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), enforcer)
	assert.Equal(s.T(), eModel.ToText(), enforcer.GetModel().ToText())
	assert.NotNil(s.T(), enforcer.GetPolicy())
}

func (s *AuthnCasbinSuite) Test_NewEnforcerWithCustomModel() {
	enforcer, err := NewCasbinEnforcer(CasbinConfig{
		PolicyConfig: PolicyConfig{
			Model: `
			[request_definition]
			r = sub, res, act
			[policy_definition]
			p = sub, res, act, eft
			[role_definition]
			g = _, _
			[policy_effect]
			e = some(where (p.eft == allow))
			[matchers]
			m = g(r.sub, p.sub)
			`,
			Csv: "p, role:unknown, res, act, allow",
		},
	})
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), enforcer)

	tok := jwt.New()
	tok.Set("realm_access", map[string]interface{}{
		"roles": []interface{}{"role:unknown"},
	})
	allowed, err := enforcer.Enforce(tok, "", "")
	assert.Nil(s.T(), err)
	assert.True(s.T(), allowed)
}

func (s *AuthnCasbinSuite) Test_NewEnforcerWithBadCustomModel() {
	enforcer, err := NewCasbinEnforcer(CasbinConfig{
		PolicyConfig: PolicyConfig{
			Model: "p, sub, obj, act",
			Csv:   "xxxx",
		},
	})
	assert.ErrorContains(s.T(), err, "failed to create casbin model")
	assert.Nil(s.T(), enforcer)
}

func (s *AuthnCasbinSuite) Test_Enforcement() {
	orgadmin := []bool{true, false, false}
	admin := []bool{false, true, false}
	readonly := []bool{false, false, true}
	unknown := []bool{false, false, false}

	var tests = []struct {
		name     string
		allowed  bool
		roles    []bool
		resource string
		action   string
	}{
		// org-admin role
		{
			allowed:  true,
			roles:    orgadmin,
			resource: "policy.attributes.DoSomething",
			action:   "read",
		},
		{
			allowed:  true,
			roles:    orgadmin,
			resource: "policy.attributes.DoSomething",
			action:   "write",
		},
		{
			allowed:  true,
			roles:    orgadmin,
			resource: "/attributes/do/something",
			action:   "read",
		},
		{
			allowed:  true,
			roles:    orgadmin,
			resource: "/attributes/do/something",
			action:   "write",
		},
		{
			allowed:  false,
			roles:    orgadmin,
			resource: "non-existent",
			action:   "read",
		},

		// admin role
		{
			allowed:  true,
			roles:    admin,
			resource: "policy.attributes.DoSomething",
			action:   "read",
		},
		{
			allowed:  true,
			roles:    admin,
			resource: "policy.attributes.DoSomething",
			action:   "write",
		},
		{
			allowed:  true,
			roles:    admin,
			resource: "/attributes/do/something",
			action:   "read",
		},
		{
			allowed:  true,
			roles:    admin,
			resource: "/attributes/do/something",
			action:   "write",
		},
		{
			allowed:  false,
			roles:    admin,
			resource: "non-existent",
			action:   "read",
		},

		// readonly role
		{
			allowed:  true,
			roles:    readonly,
			resource: "policy.attributes.DoSomething",
			action:   "read",
		},
		{
			allowed:  false,
			roles:    readonly,
			resource: "policy.attributes.DoSomething",
			action:   "write",
		},
		{
			allowed:  true,
			roles:    readonly,
			resource: "/attributes",
			action:   "read",
		},
		{
			allowed:  false,
			roles:    readonly,
			resource: "/attributes",
			action:   "write",
		},
		{
			allowed:  false,
			roles:    readonly,
			resource: "non-existent",
			action:   "read",
		},

		// undefined role
		{
			allowed:  false,
			roles:    unknown,
			resource: "policy.attributes.DoSomething",
			action:   "read",
		},
		{
			allowed:  false,
			roles:    unknown,
			resource: "policy.attributes.DoSomething",
			action:   "write",
		},
		{
			allowed:  false,
			roles:    unknown,
			resource: "/attributes",
			action:   "read",
		},
		{
			allowed:  false,
			roles:    unknown,
			resource: "/attributes",
			action:   "write",
		},
		{
			allowed:  false,
			roles:    unknown,
			resource: "non-existent",
			action:   "read",
		},
	}

	for _, test := range tests {
		should := "should"
		if !test.allowed {
			should = "should not"
		}
		actor := ""
		if test.roles[0] {
			actor = "org-admin"
		} else if test.roles[1] {
			actor = "admin"
		} else if test.roles[2] {
			actor = "readonly"
		} else {
			actor = "undefined"
		}
		name := fmt.Sprintf("%s **%s** be allowed to _%s_ %s resource", actor, should, test.action, test.resource)

		slog.Info("running test w/ default claim", slog.String("name", name))
		enforcer, err := NewCasbinEnforcer(CasbinConfig{})
		assert.Nil(s.T(), err)
		_, tok := s.newTokWithDefaultClaim(test.roles[0], test.roles[1], test.roles[2])
		allowed, err := enforcer.Enforce(tok, test.resource, test.action)
		if !test.allowed {
			assert.NotNil(s.T(), err)
		} else {
			assert.Nil(s.T(), err)
		}
		assert.Equal(s.T(), test.allowed, allowed)

		slog.Info("running test w/ custom claim", slog.String("name", name))
		enforcer, err = NewCasbinEnforcer(CasbinConfig{
			PolicyConfig: PolicyConfig{
				RoleClaim: "test.test_roles",
			},
		})
		assert.Nil(s.T(), err)
		_, tok = s.newTokenWithCustomClaim(test.roles[0], test.roles[1], test.roles[2])
		allowed, err = enforcer.Enforce(tok, test.resource, test.action)
		if !test.allowed {
			assert.NotNil(s.T(), err)
		} else {
			assert.Nil(s.T(), err)
		}
		assert.Equal(s.T(), test.allowed, allowed)

		slog.Info("running test w/ custom rolemap", slog.String("name", name))
		enforcer, err = NewCasbinEnforcer(CasbinConfig{
			PolicyConfig: PolicyConfig{
				RoleMap: map[string]string{
					"org-admin": "test-org-admin",
					"admin":     "test-admin",
					"readonly":  "test-readonly",
				},
			},
		})
		assert.Nil(s.T(), err)
		_, tok = s.newTokenWithCustomRoleMap(test.roles[0], test.roles[1], test.roles[2])
		allowed, err = enforcer.Enforce(tok, test.resource, test.action)
		if !test.allowed {
			assert.NotNil(s.T(), err)
		} else {
			assert.Nil(s.T(), err)
		}
		assert.Equal(s.T(), test.allowed, allowed)
	}
}
