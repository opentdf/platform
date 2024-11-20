package auth

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2/model"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
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

func (s *AuthnCasbinSuite) buildTokenRoles(admin bool, standard bool, roleMaps []string) []interface{} {
	adminRole := "opentdf-admin"
	if len(roleMaps) > 0 {
		adminRole = roleMaps[0]
	}
	standardRole := "opentdf-standard"
	if len(roleMaps) > 1 {
		standardRole = roleMaps[1]
	}

	i := 0
	roles := make([]interface{}, 2)

	if admin {
		roles[i] = adminRole
		i++
	}
	if standard {
		roles[i] = standardRole
	}

	return roles
}

func (s *AuthnCasbinSuite) newTokWithDefaultClaim(admin bool, standard bool) jwt.Token {
	tok := jwt.New()
	tokenRoles := s.buildTokenRoles(admin, standard, nil)
	if err := tok.Set("realm_access", map[string]interface{}{"roles": tokenRoles}); err != nil {
		s.T().Fatal(err)
	}
	return tok
}

func (s *AuthnCasbinSuite) newTokenWithCustomClaim(admin bool, standard bool) (string, jwt.Token) {
	tok := jwt.New()
	tokenRoles := s.buildTokenRoles(admin, standard, nil)
	if err := tok.Set("test", map[string]interface{}{"test_roles": map[string]interface{}{"roles": tokenRoles}}); err != nil {
		s.T().Fatal(err)
	}
	return "test.test_roles.roles", tok
}

func (s *AuthnCasbinSuite) newTokenWithCustomRoleMap(admin bool, standard bool) (string, jwt.Token) {
	tok := jwt.New()
	tokenRoles := s.buildTokenRoles(admin, standard, []string{"test-admin", "test-standard"})
	if err := tok.Set("realm_access", map[string]interface{}{"roles": tokenRoles}); err != nil {
		s.T().Fatal(err)
	}
	return "", tok
}

func (s *AuthnCasbinSuite) newTokenWithCilentID() (string, jwt.Token) {
	tok := jwt.New()
	if err := tok.Set("client_id", "test"); err != nil {
		s.T().Fatal(err)
	}
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
	enforcer, err := NewCasbinEnforcer(CasbinConfig{}, logger.CreateTestLogger())

	s.Require().NoError(err)
	s.NotNil(enforcer)
	s.Equal(eModel.ToText(), enforcer.GetModel().ToText())
	s.NotNil(enforcer.GetPolicy())
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
	}, logger.CreateTestLogger())
	s.Require().NoError(err)
	s.NotNil(enforcer)

	tok := jwt.New()
	err = tok.Set("realm_access", map[string]interface{}{
		"roles": []interface{}{"role:unknown"},
	})
	s.Require().NoError(err)

	allowed, err := enforcer.Enforce(tok, "", "")
	s.Require().NoError(err)
	s.True(allowed)
}

func (s *AuthnCasbinSuite) Test_NewEnforcerWithBadCustomModel() {
	enforcer, err := NewCasbinEnforcer(CasbinConfig{
		PolicyConfig: PolicyConfig{
			Model: "p, sub, obj, act",
			Csv:   "xxxx",
		},
	}, logger.CreateTestLogger())
	s.Require().ErrorContains(err, "failed to create casbin model")
	s.Nil(enforcer)
}

func (s *AuthnCasbinSuite) Test_Enforcement() {
	admin := []bool{true, false}
	standard := []bool{false, true}
	unknown := []bool{false, false}

	tests := []struct {
		name     string
		allowed  bool
		roles    []bool
		resource string
		action   string
	}{
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
			allowed:  true,
			roles:    admin,
			resource: "non-existent",
			action:   "read",
		},

		// standard role
		{
			allowed:  true,
			roles:    standard,
			resource: "policy.attributes.DoSomething",
			action:   "read",
		},
		{
			allowed:  false,
			roles:    standard,
			resource: "policy.attributes.DoSomething",
			action:   "write",
		},
		{
			allowed:  true,
			roles:    standard,
			resource: "/attributes",
			action:   "read",
		},
		{
			allowed:  false,
			roles:    standard,
			resource: "/attributes",
			action:   "write",
		},
		{
			allowed:  false,
			roles:    standard,
			resource: "non-existent",
			action:   "read",
		},
		{
			allowed:  true,
			roles:    standard,
			resource: "/kas/v2/rewrap",
			action:   "write",
		},
		{
			allowed:  true,
			roles:    standard,
			resource: "authorization.AuthorizationService/GetDecisions",
			action:   "read",
		},
		{
			allowed:  true,
			roles:    standard,
			resource: "authorization.AuthorizationService/GetDecisionsByToken",
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
		var actor string
		switch {
		case test.roles[0]:
			actor = "admin"
		case test.roles[1]:
			actor = "standard"
		default:
			actor = "undefined"
		}
		name := fmt.Sprintf("%s **%s** be allowed to _%s_ %s resource", actor, should, test.action, test.resource)

		slog.Info("running test w/ default claim", slog.String("name", name))
		enforcer, err := NewCasbinEnforcer(CasbinConfig{}, logger.CreateTestLogger())
		s.Require().NoError(err)
		tok := s.newTokWithDefaultClaim(test.roles[0], test.roles[1])
		allowed, err := enforcer.Enforce(tok, test.resource, test.action)
		if !test.allowed {
			s.Require().Error(err)
		} else {
			s.Require().NoError(err)
		}
		s.Equal(test.allowed, allowed)

		slog.Info("running test w/ custom claim", slog.String("name", name))
		enforcer, err = NewCasbinEnforcer(CasbinConfig{
			PolicyConfig: PolicyConfig{
				RoleClaim: "test.test_roles.roles",
			},
		}, logger.CreateTestLogger())
		s.Require().NoError(err)
		_, tok = s.newTokenWithCustomClaim(test.roles[0], test.roles[1])
		allowed, err = enforcer.Enforce(tok, test.resource, test.action)
		if !test.allowed {
			s.Require().Error(err)
		} else {
			s.Require().NoError(err)
		}
		s.Equal(test.allowed, allowed)

		slog.Info("running test w/ custom rolemap", slog.String("name", name))
		enforcer, err = NewCasbinEnforcer(CasbinConfig{
			PolicyConfig: PolicyConfig{
				RoleMap: map[string]string{
					"admin":    "test-admin",
					"standard": "test-standard",
				},
			},
		}, logger.CreateTestLogger())
		s.Require().NoError(err)
		_, tok = s.newTokenWithCustomRoleMap(test.roles[0], test.roles[1])
		allowed, err = enforcer.Enforce(tok, test.resource, test.action)
		if !test.allowed {
			s.Require().Error(err)
		} else {
			s.Require().NoError(err)
		}
		s.Equal(test.allowed, allowed)
		slog.Info("running test w/ client_id", slog.String("name", name))
		roleMap := make(map[string]string)
		if test.roles[0] {
			roleMap["admin"] = "test"
		}
		if test.roles[1] {
			roleMap["standard"] = "test"
		}

		enforcer, err = NewCasbinEnforcer(CasbinConfig{
			PolicyConfig: PolicyConfig{
				RoleClaim: "client_id",
				RoleMap:   roleMap,
			},
		}, logger.CreateTestLogger())
		s.Require().NoError(err)
		_, tok = s.newTokenWithCilentID()
		allowed, err = enforcer.Enforce(tok, test.resource, test.action)
		if !test.allowed {
			s.Require().Error(err)
		} else {
			s.Require().NoError(err)
		}
		s.Equal(test.allowed, allowed)
	}
}

func (s *AuthnCasbinSuite) Test_ExtendDefaultPolicies() {
	enforcer, err := NewCasbinEnforcer(CasbinConfig{}, logger.CreateTestLogger())
	s.Require().NoError(err)
	// other roles denied new policy: admin
	tok := s.newTokWithDefaultClaim(true, false)
	allowed, err := enforcer.Enforce(tok, "new.service.DoSomething", "read")
	s.Require().NoError(err)
	s.True(allowed)
	allowed, err = enforcer.Enforce(tok, "new.service.DoSomething", "write")
	s.Require().NoError(err)
	s.True(allowed)

	// other roles denied new policy: standard
	tok = s.newTokWithDefaultClaim(false, true)
	err = enforcer.ExtendDefaultPolicy([][]string{{"p", "role:standard", "new.service.*", "read", "allow"}})
	s.Require().NoError(err)
	allowed, err = enforcer.Enforce(tok, "new.service.DoSomething", "read")
	s.Require().NoError(err)
	s.True(allowed)
	allowed, err = enforcer.Enforce(tok, "new.service.DoSomething", "write")
	s.Require().Error(err)
	s.False(allowed)
}

func (s *AuthnCasbinSuite) Test_ExtendDefaultPolicies_MultipleExtensions() {
	enforcer, err := NewCasbinEnforcer(CasbinConfig{}, logger.CreateTestLogger())
	s.Require().NoError(err)

	err = enforcer.ExtendDefaultPolicy([][]string{
		{"p", "role:standard", "new.service.*", "write", "allow"},
		{"p", "role:standard", "new.hello.*", "read", "allow"},
	})
	s.Require().NoError(err)

	adminTok := s.newTokWithDefaultClaim(true, false)
	standardTok := s.newTokWithDefaultClaim(false, true)
	cases := []struct {
		tok             jwt.Token
		expectedAllowed bool
		resource        string
		action          string
	}{
		// original default policy still evaluates correctly
		{adminTok, true, "policy.attributes.CreateAttribute", "write"},
		{adminTok, true, "new.service.ActionableObject", "read"},
		{adminTok, true, "new.service.ActionableObject", "write"},
		{adminTok, true, "new.hello.World", "read"},
		{adminTok, true, "new.hello.World", "write"},
		{adminTok, true, "new.hello.SomethingElse", "read"},
		{adminTok, true, "new.hello.SomethingElse", "write"},
		{standardTok, false, "new.service.ActionableObject", "read"},
		{standardTok, true, "new.service.ActionableObject", "write"},
		{standardTok, true, "new.hello.World", "read"},
		{standardTok, false, "new.hello.World", "write"},
		{standardTok, true, "new.hello.SomethingElse", "read"},
		{standardTok, false, "new.hello.SomethingElse", "write"},
	}

	for _, c := range cases {
		allowed, err := enforcer.Enforce(c.tok, c.resource, c.action)
		if !c.expectedAllowed {
			s.Require().Error(err)
		} else {
			s.Require().NoError(err)
		}
		s.Equal(c.expectedAllowed, allowed)
	}
}

func (s *AuthnCasbinSuite) Test_ExtendDefaultPolicies_MalformedErrors() {
	enforcer, err := NewCasbinEnforcer(CasbinConfig{}, logger.CreateTestLogger())
	s.Require().NoError(err)
	tok := s.newTokWithDefaultClaim(true, false)
	allowed, err := enforcer.Enforce(tok, "policy.attributes.DoSomething", "read")
	s.Require().NoError(err)
	s.True(allowed)

	// missing 'p'
	err = enforcer.ExtendDefaultPolicy([][]string{{"role:admin", "new.service.DoSomething", "*"}})
	s.Require().Error(err)
	s.Require().ErrorIs(err, ErrPolicyMalformed)

	// missing effect
	err = enforcer.ExtendDefaultPolicy([][]string{{"p", "role:admin", "new.service.DoSomething", "*"}})
	s.Require().Error(err)
	s.Require().ErrorIs(err, ErrPolicyMalformed)

	// empty
	err = enforcer.ExtendDefaultPolicy([][]string{{}})
	s.Require().Error(err)
	s.Require().ErrorIs(err, ErrPolicyMalformed)

	// missing role prefix
	err = enforcer.ExtendDefaultPolicy([][]string{{"p", "admin", "new.service.DoSomething", "*"}})
	s.Require().Error(err)
	s.Require().ErrorIs(err, ErrPolicyMalformed)
}

func (s *AuthnCasbinSuite) Test_SetPolicy() {
	enforcer, err := NewCasbinEnforcer(CasbinConfig{}, logger.CreateTestLogger())
	s.Require().NoError(err)

	// Org-admin role
	err = enforcer.SetPolicy(strings.Join([]string{
		"p, role:admin, new.hello.*, *, allow",
		"p, role:standard, new.hello.*, read, allow",
		"p, role:standard, new.hello.*, write, deny",
	}, "\n"))
	s.Require().NoError(err)

	// unauthorized role
	tok := s.newTokWithDefaultClaim(false, false)
	allowed, err := enforcer.Enforce(tok, "new.hello.World", "read")
	s.Require().Error(err)
	s.False(allowed)
	allowed, err = enforcer.Enforce(tok, "new.hello.World", "write")
	s.Require().Error(err)
	s.False(allowed)
	allowed, err = enforcer.Enforce(tok, "new.service.DoSomething", "read")
	s.Require().Error(err)
	s.False(allowed)
	allowed, err = enforcer.Enforce(tok, "new.service.DoSomething", "write")
	s.Require().Error(err)
	s.False(allowed)

	// other roles denied new policy: admin
	tok = s.newTokWithDefaultClaim(true, false)
	allowed, err = enforcer.Enforce(tok, "new.hello.World", "read")
	s.Require().NoError(err)
	s.True(allowed)
	allowed, err = enforcer.Enforce(tok, "new.hello.World", "write")
	s.Require().NoError(err)
	s.True(allowed)
	allowed, err = enforcer.Enforce(tok, "new.service.DoSomething", "read")
	s.Require().Error(err)
	s.False(allowed)
	allowed, err = enforcer.Enforce(tok, "new.service.DoSomething", "write")
	s.Require().Error(err)
	s.False(allowed)

	// other roles denied new policy: standard
	tok = s.newTokWithDefaultClaim(false, true)
	allowed, err = enforcer.Enforce(tok, "new.hello.World", "read")
	s.Require().NoError(err)
	s.True(allowed)
	allowed, err = enforcer.Enforce(tok, "new.hello.World", "write")
	s.Require().Error(err)
	s.False(allowed)
	allowed, err = enforcer.Enforce(tok, "new.service.DoSomething", "read")
	s.Require().Error(err)
	s.False(allowed)
	allowed, err = enforcer.Enforce(tok, "new.service.DoSomething", "write")
	s.Require().Error(err)
	s.False(allowed)
}
