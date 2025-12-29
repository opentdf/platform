package auth

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/creasty/defaults"
	"gorm.io/driver/sqlite"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
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
	policyCfg := PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	policyCfg.Model = `
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
			`
	policyCfg.Csv = strings.Join([]string{
		"p, role:unknown, res, act, allow",
		"g, role:unknown, role:unknown",
	},
		"\n")

	enforcer, err := NewCasbinEnforcer(CasbinConfig{
		PolicyConfig: policyCfg,
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

		policyCfg := PolicyConfig{}
		err := defaults.Set(&policyCfg)
		s.Require().NoError(err, name)

		slog.Info("running test w/ default claim", slog.String("name", name))
		enforcer, err := NewCasbinEnforcer(CasbinConfig{PolicyConfig: policyCfg}, logger.CreateTestLogger())
		s.Require().NoError(err, name)
		tok := s.newTokWithDefaultClaim(test.roles[0], test.roles[1], "", "")
		allowed, err := enforcer.Enforce(tok, test.resource, test.action)
		if !test.allowed {
			s.Require().Error(err, name)
		} else {
			s.Require().NoError(err, name)
		}
		s.Equal(test.allowed, allowed, name)

		slog.Info("running test w/ custom claim", slog.String("name", name))

		policyCfg.GroupsClaim = "test.test_roles.roles"

		enforcer, err = NewCasbinEnforcer(CasbinConfig{
			PolicyConfig: policyCfg,
		}, logger.CreateTestLogger())
		s.Require().NoError(err, name)
		_, tok = s.newTokenWithCustomClaim(test.roles[0], test.roles[1])
		allowed, err = enforcer.Enforce(tok, test.resource, test.action)
		if !test.allowed {
			s.Require().Error(err, name)
		} else {
			s.Require().NoError(err, name)
		}
		s.Equal(test.allowed, allowed, name)

		slog.Info("running test w/ custom rolemap", slog.String("name", name))

		policyCfg.RoleMap = map[string]string{
			"admin":    "test-admin",
			"standard": "test-standard",
		}
		policyCfg.GroupsClaim = "realm_access.roles"

		enforcer, err = NewCasbinEnforcer(CasbinConfig{
			PolicyConfig: policyCfg,
		}, logger.CreateTestLogger())
		s.Require().NoError(err, name)
		_, tok = s.newTokenWithCustomRoleMap(test.roles[0], test.roles[1])
		allowed, err = enforcer.Enforce(tok, test.resource, test.action)
		if !test.allowed {
			s.Require().Error(err, name)
		} else {
			s.Require().NoError(err, name)
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

		policyCfg.RoleMap = roleMap
		policyCfg.UserNameClaim = "client_id"

		enforcer, err = NewCasbinEnforcer(CasbinConfig{
			PolicyConfig: policyCfg,
		}, logger.CreateTestLogger())
		s.Require().NoError(err, name)
		_, tok = s.newTokenWithCilentID()
		allowed, err = enforcer.Enforce(tok, test.resource, test.action)
		if !test.allowed {
			s.Require().Error(err, name)
		} else {
			s.Require().NoError(err, name)
		}
		s.Equal(test.allowed, allowed, name)
	}
}

func (s *AuthnCasbinSuite) Test_ExtendDefaultPolicies() {
	policyCfg := PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	policyCfg.Extension = strings.Join([]string{
		"p, role:standard, new.service.*, read, allow",
		"g, opentdf-admin, role:admin",
		"g, opentdf-standard, role:standard",
	}, "\n")

	enforcer, err := NewCasbinEnforcer(CasbinConfig{PolicyConfig: policyCfg}, logger.CreateTestLogger())
	s.Require().NoError(err)
	// other roles denied new policy: admin
	tok := s.newTokWithDefaultClaim(true, false, "", "")
	allowed, err := enforcer.Enforce(tok, "new.service.DoSomething", "read")
	s.Require().NoError(err)
	s.True(allowed)
	allowed, err = enforcer.Enforce(tok, "new.service.DoSomething", "write")
	s.Require().NoError(err)
	s.True(allowed)

	// other roles denied new policy: standard
	tok = s.newTokWithDefaultClaim(false, true, "", "")
	allowed, err = enforcer.Enforce(tok, "new.service.DoSomething", "read")
	s.Require().NoError(err)
	s.True(allowed)
	allowed, err = enforcer.Enforce(tok, "new.service.DoSomething", "write")
	s.Require().Error(err)
	s.False(allowed)
}

func (s *AuthnCasbinSuite) Test_ExtendDefaultPolicies_MalformedErrors() {
	policyCfg := PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	enforcer, err := NewCasbinEnforcer(CasbinConfig{PolicyConfig: policyCfg}, logger.CreateTestLogger())
	s.Require().NoError(err)
	tok := s.newTokWithDefaultClaim(true, false, "", "")
	allowed, err := enforcer.Enforce(tok, "policy.attributes.DoSomething", "read")
	s.Require().NoError(err)
	s.True(allowed)

	// missing 'p'
	policyCfg.Extension = strings.Join([]string{
		"g, opentdf-admin, role:admin",
		"g, opentdf-standard, role:standard",
		"role:admin, new.service.DoSomething, *",
	}, "\n")
	enforcer, err = NewCasbinEnforcer(CasbinConfig{
		PolicyConfig: policyCfg,
	}, logger.CreateTestLogger())
	s.Require().NoError(err)
	tok = s.newTokWithDefaultClaim(true, false, "", "")
	allowed, err = enforcer.Enforce(tok, "policy.attributes.DoSomething", "read")
	s.Require().NoError(err)
	s.True(allowed)

	// missing effect
	policyCfg.Extension = strings.Join([]string{
		"g, opentdf-admin, role:admin",
		"g, opentdf-standard, role:standard",
		"p, role:admin, new.service.DoSomething, *",
	}, "\n")
	enforcer, err = NewCasbinEnforcer(CasbinConfig{
		PolicyConfig: policyCfg,
	}, logger.CreateTestLogger())
	s.Require().NoError(err)
	tok = s.newTokWithDefaultClaim(true, false, "", "")
	allowed, err = enforcer.Enforce(tok, "policy.attributes.DoSomething", "read")
	s.Require().NoError(err)
	s.True(allowed)

	// empty
	policyCfg.Extension = strings.Join([]string{
		"",
	}, "\n")
	enforcer, err = NewCasbinEnforcer(CasbinConfig{
		PolicyConfig: policyCfg,
	}, logger.CreateTestLogger())
	s.Require().NoError(err)
	tok = s.newTokWithDefaultClaim(true, false, "", "")
	allowed, err = enforcer.Enforce(tok, "policy.attributes.DoSomething", "read")
	s.Require().NoError(err)
	s.True(allowed)

	// missing role prefix
	policyCfg.Extension = strings.Join([]string{
		"g, opentdf-admin, role:admin",
		"g, opentdf-standard, role:standard",
		"p, admin, new.service.DoSomething, *",
	}, "\n")
	enforcer, err = NewCasbinEnforcer(CasbinConfig{
		PolicyConfig: policyCfg,
	}, logger.CreateTestLogger())
	s.Require().NoError(err)
	tok = s.newTokWithDefaultClaim(true, false, "", "")
	allowed, err = enforcer.Enforce(tok, "policy.attributes.DoSomething", "read")
	s.Require().NoError(err)
	s.True(allowed)
}

func (s *AuthnCasbinSuite) Test_SetBuiltinPolicy() {
	policyCfg := PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	policyCfg.Builtin = strings.Join([]string{
		"p, role:admin, new.hello.*, *, allow",
		"p, role:standard, new.hello.*, read, allow",
		"p, role:standard, new.hello.*, write, deny",
		"g, opentdf-admin, role:admin",
		"g, opentdf-standard, role:standard",
	}, "\n")

	enforcer, err := NewCasbinEnforcer(CasbinConfig{PolicyConfig: policyCfg}, logger.CreateTestLogger())
	s.Require().NoError(err)

	// unauthorized role
	tok := s.newTokWithDefaultClaim(false, false, "", "")
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
	tok = s.newTokWithDefaultClaim(true, false, "", "")
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
	tok = s.newTokWithDefaultClaim(false, true, "", "")
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

func (s *AuthnCasbinSuite) Test_Username_Policy() {
	policyCfg := PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	policyCfg.Extension = strings.Join([]string{
		"p, casbin-user, new.service.*, read, allow",
	}, "\n")

	enforcer, err := NewCasbinEnforcer(CasbinConfig{PolicyConfig: policyCfg}, logger.CreateTestLogger())
	s.Require().NoError(err)

	tok := s.newTokWithDefaultClaim(true, false, "preferred_username", "")
	allowed, err := enforcer.Enforce(tok, "new.service.DoSomething", "read")
	s.Require().NoError(err)
	s.True(allowed)

	allowed, err = enforcer.Enforce(tok, "policy.attributes.List", "read")
	s.Require().Error(err)
	s.False(allowed)
}

func (s *AuthnCasbinSuite) Test_Override_Of_Username_Claim() {
	policyCfg := PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	policyCfg.UserNameClaim = "username"
	policyCfg.Extension = strings.Join([]string{
		"p, casbin-user, new.service.*, read, allow",
	}, "\n")

	enforcer, err := NewCasbinEnforcer(CasbinConfig{PolicyConfig: policyCfg}, logger.CreateTestLogger())
	s.Require().NoError(err)

	tok := s.newTokWithDefaultClaim(true, false, "username", "")
	allowed, err := enforcer.Enforce(tok, "new.service.DoSomething", "read")
	s.Require().NoError(err)
	s.True(allowed)

	allowed, err = enforcer.Enforce(tok, "policy.attributes.List", "read")
	s.Require().Error(err)
	s.False(allowed)
}

func (s *AuthnCasbinSuite) Test_Override_Of_Groups_Claim() {
	policyCfg := PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	policyCfg.GroupsClaim = "realm_access.groups"

	enforcer, err := NewCasbinEnforcer(CasbinConfig{PolicyConfig: policyCfg}, logger.CreateTestLogger())
	s.Require().NoError(err)

	tok := s.newTokWithDefaultClaim(false, true, "", "groups")
	allowed, err := enforcer.Enforce(tok, "new.service.DoSomething", "read")
	s.Require().Error(err)
	s.False(allowed)

	allowed, err = enforcer.Enforce(tok, "policy.attributes.List", "read")
	s.Require().NoError(err)
	s.True(allowed)
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

func (s *AuthnCasbinSuite) newTokWithDefaultClaim(admin bool, standard bool, usernameClaimName, groupClaimName string) jwt.Token {
	tok := jwt.New()

	if groupClaimName == "" {
		groupClaimName = "roles"
	}

	tokenRoles := s.buildTokenRoles(admin, standard, nil)
	if err := tok.Set("realm_access", map[string]interface{}{groupClaimName: tokenRoles}); err != nil {
		s.T().Fatal(err)
	}

	if usernameClaimName != "" {
		if err := tok.Set(usernameClaimName, "casbin-user"); err != nil {
			s.T().Fatal(err)
		}
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

// createTestSQLAdapter returns a GORM-backed Casbin adapter using an in-memory SQLite database.
func createTestSQLAdapter(t *testing.T) *gormadapter.Adapter {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite gorm db: %v", err)
	}
	if err := db.AutoMigrate(&gormadapter.CasbinRule{}); err != nil {
		t.Fatalf("failed to migrate casbin_rule: %v", err)
	}
	adp, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		t.Fatalf("failed to create gorm casbin adapter: %v", err)
	}
	return adp
}

func Test_SQLPolicySeeding_Idempotent(t *testing.T) {
	adapter := createTestSQLAdapter(t)

	cfg := CasbinConfig{PolicyConfig: PolicyConfig{}}
	cfg.EnableSQL = true
	cfg.Adapter = adapter

	e, err := NewCasbinEnforcer(cfg, logger.CreateTestLogger())
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	if err := e.LoadPolicy(); err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}
	p1, _ := e.GetPolicy()
	g1, _ := e.GetGroupingPolicy()
	if len(p1) == 0 && len(g1) == 0 {
		t.Fatalf("expected seeded policies but found none")
	}

	e2, err := NewCasbinEnforcer(cfg, logger.CreateTestLogger())
	if err != nil {
		t.Fatalf("failed to create second enforcer: %v", err)
	}
	if err := e2.LoadPolicy(); err != nil {
		t.Fatalf("failed to load policy on second enforcer: %v", err)
	}
	p2, _ := e2.GetPolicy()
	g2, _ := e2.GetGroupingPolicy()

	if len(p1) != len(p2) || len(g1) != len(g2) {
		t.Fatalf("policy count changed on second initialization: policies %d->%d, grouping %d->%d", len(p1), len(p2), len(g1), len(g2))
	}
}

func Test_CSVMode_DefaultBehavior(t *testing.T) {
	cfg := CasbinConfig{PolicyConfig: PolicyConfig{}}
	e, err := NewCasbinEnforcer(cfg, logger.CreateTestLogger())
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	if err := e.LoadPolicy(); err != nil {
		t.Fatalf("failed to load csv-backed policy: %v", err)
	}
	p, _ := e.GetPolicy()
	g, _ := e.GetGroupingPolicy()
	if len(p) == 0 && len(g) == 0 {
		t.Fatalf("expected default CSV policies to be present")
	}
}
