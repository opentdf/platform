package v1

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2/model"
	"github.com/creasty/defaults"
	"github.com/lestrrat-go/jwx/v2/jwt"
	internalauthz "github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/authz"
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

func (s *AuthnCasbinSuite) SetupSuite() {
}

func (s *AuthnCasbinSuite) TeardownSuite() {
}

func (s *AuthnCasbinSuite) Test_NewEnforcerWithDefaults() {
	eModel, err := model.NewModelFromString(defaultModel)
	if err != nil {
		s.T().Fatal(err)
	}
	enforcer, err := newCasbinEnforcer(casbinConfig{}, logger.CreateTestLogger())

	s.Require().NoError(err)
	s.NotNil(enforcer)
	s.Equal(eModel.ToText(), enforcer.casbinEnforcer.GetModel().ToText())
	s.NotNil(enforcer.casbinEnforcer.GetPolicy())
}

func (s *AuthnCasbinSuite) Test_NewEnforcerWithCustomModel() {
	policyCfg := internalauthz.PolicyConfig{}
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

	enforcer, err := newCasbinEnforcer(casbinConfig{
		PolicyConfig: policyCfg,
	}, logger.CreateTestLogger())
	s.Require().NoError(err)
	s.NotNil(enforcer)

	tok := jwt.New()
	err = tok.Set("realm_access", map[string]interface{}{
		"roles": []interface{}{"role:unknown"},
	})
	s.Require().NoError(err)

	allowed, err := s.enforce(enforcer, tok, "", "")
	s.Require().NoError(err)
	s.True(allowed)
}

func (s *AuthnCasbinSuite) Test_NewEnforcerWithBadCustomModel() {
	enforcer, err := newCasbinEnforcer(casbinConfig{
		PolicyConfig: internalauthz.PolicyConfig{
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
			allowed:  false,
			roles:    standard,
			resource: "non-existent",
			action:   "read",
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

		policyCfg := internalauthz.PolicyConfig{}
		err := defaults.Set(&policyCfg)
		s.Require().NoError(err, name)

		slog.Info("running test w/ default claim", slog.String("name", name))
		enforcer, err := newCasbinEnforcer(casbinConfig{PolicyConfig: policyCfg}, logger.CreateTestLogger())
		s.Require().NoError(err, name)
		tok := s.newTokWithDefaultClaim(test.roles[0], test.roles[1], "", "")
		allowed, err := s.enforce(enforcer, tok, test.resource, test.action)
		if !test.allowed {
			s.Require().Error(err, name)
			s.False(allowed, name)
		} else {
			s.Require().NoError(err, name)
			s.True(allowed, name)
		}

		slog.Info("running test w/ custom claim", slog.String("name", name))

		policyCfg.GroupsClaim = "test.test_roles.roles"

		enforcer, err = newCasbinEnforcer(casbinConfig{
			PolicyConfig: policyCfg,
		}, logger.CreateTestLogger())
		s.Require().NoError(err, name)
		_, tok = s.newTokenWithCustomClaim(test.roles[0], test.roles[1])
		allowed, err = s.enforce(enforcer, tok, test.resource, test.action)
		if !test.allowed {
			s.Require().Error(err, name)
			s.False(allowed, name)
		} else {
			s.Require().NoError(err, name)
			s.True(allowed, name)
		}

		slog.Info("running test w/ custom rolemap", slog.String("name", name))

		//nolint:staticcheck // Exercise deprecated RoleMap compatibility.
		policyCfg.RoleMap = map[string]string{
			"admin":    "test-admin",
			"standard": "test-standard",
		}
		policyCfg.GroupsClaim = "realm_access.roles"

		enforcer, err = newCasbinEnforcer(casbinConfig{
			PolicyConfig: policyCfg,
		}, logger.CreateTestLogger())
		s.Require().NoError(err, name)
		_, tok = s.newTokenWithCustomRoleMap(test.roles[0], test.roles[1])
		allowed, err = s.enforce(enforcer, tok, test.resource, test.action)
		if !test.allowed {
			s.Require().Error(err, name)
			s.False(allowed, name)
		} else {
			s.Require().NoError(err, name)
			s.True(allowed, name)
		}

		slog.Info("running test w/ client_id", slog.String("name", name))
		roleMap := make(map[string]string)
		if test.roles[0] {
			roleMap["admin"] = "test"
		}
		if test.roles[1] {
			roleMap["standard"] = "test"
		}

		//nolint:staticcheck // Exercise deprecated RoleMap compatibility.
		policyCfg.RoleMap = roleMap
		policyCfg.UserNameClaim = "client_id"

		enforcer, err = newCasbinEnforcer(casbinConfig{
			PolicyConfig: policyCfg,
		}, logger.CreateTestLogger())
		s.Require().NoError(err, name)
		_, tok = s.newTokenWithClientID()
		allowed, err = s.enforce(enforcer, tok, test.resource, test.action)
		if !test.allowed {
			s.Require().Error(err, name)
			s.False(allowed, name)
		} else {
			s.Require().NoError(err, name)
			s.True(allowed, name)
		}
	}
}

func (s *AuthnCasbinSuite) Test_ExtendDefaultPolicies() {
	policyCfg := internalauthz.PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	policyCfg.Extension = strings.Join([]string{
		"p, role:standard, new.service.*, read, allow",
		"g, opentdf-admin, role:admin",
		"g, opentdf-standard, role:standard",
	}, "\n")

	enforcer, err := newCasbinEnforcer(casbinConfig{PolicyConfig: policyCfg}, logger.CreateTestLogger())
	s.Require().NoError(err)
	// other roles denied new policy: admin
	tok := s.newTokWithDefaultClaim(true, false, "", "")
	allowed, err := s.enforce(enforcer, tok, "new.service.DoSomething", "read")
	s.Require().NoError(err)
	s.True(allowed)
	allowed, err = s.enforce(enforcer, tok, "new.service.DoSomething", "write")
	s.Require().NoError(err)
	s.True(allowed)

	// other roles denied new policy: standard
	tok = s.newTokWithDefaultClaim(false, true, "", "")
	allowed, err = s.enforce(enforcer, tok, "new.service.DoSomething", "read")
	s.Require().NoError(err)
	s.True(allowed)
	allowed, err = s.enforce(enforcer, tok, "new.service.DoSomething", "write")
	s.Require().Error(err)
	s.False(allowed)
}

func (s *AuthnCasbinSuite) Test_ExtendDefaultPolicies_MalformedErrors() {
	testCases := []struct {
		name      string
		extension string
		expectErr bool
		allowed   bool // expected result from enforce
	}{
		{
			name:      "admin no extension, empty resource or action",
			extension: "",
			expectErr: false,
			allowed:   true,
		},
		{
			name: "missing 'p' in policy line",
			extension: strings.Join([]string{
				"g, opentdf-admin, role:admin",
				"g, opentdf-standard, role:standard",
				"role:admin, new.service.DoSomething, *",
			}, "\n"),
			expectErr: false, // v1 casbin doesn't validate CSV format
			allowed:   true,  // admin still has access via default policy + valid group mapping
		},
		{
			name: "missing effect",
			extension: strings.Join([]string{
				"g, opentdf-admin, role:admin",
				"g, opentdf-standard, role:standard",
				"p, role:admin, new.service.DoSomething, *",
			}, "\n"),
			expectErr: false, // v1 casbin doesn't validate CSV format
			allowed:   true,  // admin still has access via default policy + valid group mapping
		},
		{
			name: "missing role prefix",
			extension: strings.Join([]string{
				"g, opentdf-admin, admin",
				"g, opentdf-standard, standard",
				"p, admin, new.service.DoSomething, *",
			}, "\n"),
			expectErr: false, // v1 casbin doesn't validate CSV format
			allowed:   false, // role mapping without prefix won't match
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			policyCfg := internalauthz.PolicyConfig{}
			err := defaults.Set(&policyCfg)
			s.Require().NoError(err)
			policyCfg.Extension = tc.extension
			enforcer, err := newCasbinEnforcer(casbinConfig{PolicyConfig: policyCfg}, logger.CreateTestLogger())
			if tc.expectErr {
				s.Require().Error(err)
				s.Nil(enforcer)
				return
			}

			s.Require().NoError(err)
			s.NotNil(enforcer)

			tok := s.newTokWithDefaultClaim(true, false, "", "")
			allowed, err := s.enforce(enforcer, tok, "policy.attributes.DoSomething", "read")
			if tc.allowed {
				s.Require().NoError(err)
				s.True(allowed)
			} else {
				s.Require().Error(err)
				s.False(allowed)
			}
		})
	}
}

func (s *AuthnCasbinSuite) Test_SetBuiltinPolicy() {
	policyCfg := internalauthz.PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	policyCfg.Builtin = strings.Join([]string{
		"p, role:admin, new.hello.*, *, allow",
		"p, role:standard, new.hello.*, read, allow",
		"p, role:standard, new.hello.*, write, deny",
		"g, opentdf-admin, role:admin",
		"g, opentdf-standard, role:standard",
	}, "\n")

	testCases := []struct {
		name     string
		admin    bool
		standard bool
		resource string
		action   string
		allowed  bool
	}{
		{
			name:     "unauthorized role cannot read new.hello.World",
			admin:    false,
			standard: false,
			resource: "new.hello.World",
			action:   "read",
			allowed:  false,
		},
		{
			name:     "unauthorized role cannot write new.hello.World",
			admin:    false,
			standard: false,
			resource: "new.hello.World",
			action:   "write",
			allowed:  false,
		},
		{
			name:     "unauthorized role cannot read new.service.DoSomething",
			admin:    false,
			standard: false,
			resource: "new.service.DoSomething",
			action:   "read",
			allowed:  false,
		},
		{
			name:     "unauthorized role cannot write new.service.DoSomething",
			admin:    false,
			standard: false,
			resource: "new.service.DoSomething",
			action:   "write",
			allowed:  false,
		},
		{
			name:     "admin can read new.hello.World",
			admin:    true,
			standard: false,
			resource: "new.hello.World",
			action:   "read",
			allowed:  true,
		},
		{
			name:     "admin can write new.hello.World",
			admin:    true,
			standard: false,
			resource: "new.hello.World",
			action:   "write",
			allowed:  true,
		},
		{
			name:     "admin cannot read new.service.DoSomething",
			admin:    true,
			standard: false,
			resource: "new.service.DoSomething",
			action:   "read",
			allowed:  false,
		},
		{
			name:     "admin cannot write new.service.DoSomething",
			admin:    true,
			standard: false,
			resource: "new.service.DoSomething",
			action:   "write",
			allowed:  false,
		},
		{
			name:     "standard can read new.hello.World",
			admin:    false,
			standard: true,
			resource: "new.hello.World",
			action:   "read",
			allowed:  true,
		},
		{
			name:     "standard cannot write new.hello.World",
			admin:    false,
			standard: true,
			resource: "new.hello.World",
			action:   "write",
			allowed:  false,
		},
		{
			name:     "standard cannot read new.service.DoSomething",
			admin:    false,
			standard: true,
			resource: "new.service.DoSomething",
			action:   "read",
			allowed:  false,
		},
		{
			name:     "standard cannot write new.service.DoSomething",
			admin:    false,
			standard: true,
			resource: "new.service.DoSomething",
			action:   "write",
			allowed:  false,
		},
	}

	enforcer, err := newCasbinEnforcer(casbinConfig{PolicyConfig: policyCfg}, logger.CreateTestLogger())
	s.Require().NoError(err)

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			tok := s.newTokWithDefaultClaim(tc.admin, tc.standard, "", "")
			allowed, err := s.enforce(enforcer, tok, tc.resource, tc.action)
			if tc.allowed {
				s.Require().NoError(err, tc.name)
				s.True(allowed, tc.name)
			} else {
				s.Require().Error(err, tc.name)
				s.False(allowed, tc.name)
			}
		})
	}
}

func (s *AuthnCasbinSuite) Test_Username_Policy() {
	policyCfg := internalauthz.PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	policyCfg.Extension = strings.Join([]string{
		"p, casbin-user, new.service.*, read, allow",
	}, "\n")

	enforcer, err := newCasbinEnforcer(casbinConfig{PolicyConfig: policyCfg}, logger.CreateTestLogger())
	s.Require().NoError(err)

	tok := s.newTokWithDefaultClaim(true, false, "preferred_username", "")
	allowed, err := s.enforce(enforcer, tok, "new.service.DoSomething", "read")
	s.Require().NoError(err)
	s.True(allowed)

	allowed, err = s.enforce(enforcer, tok, "policy.attributes.List", "read")
	s.Require().Error(err)
	s.False(allowed)
}

func (s *AuthnCasbinSuite) Test_ClientID_Policy() {
	policyCfg := internalauthz.PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	policyCfg.ClientIDClaim = "client_id"
	policyCfg.Extension = strings.Join([]string{
		"p, test-client, new.service.*, read, allow",
	}, "\n")

	enforcer, err := newCasbinEnforcer(casbinConfig{PolicyConfig: policyCfg}, logger.CreateTestLogger())
	s.Require().NoError(err)

	tok := jwt.New()
	err = tok.Set("client_id", "test-client")
	s.Require().NoError(err)

	allowed, err := s.enforce(enforcer, tok, "new.service.DoSomething", "read")
	s.Require().NoError(err)
	s.True(allowed)

	allowed, err = s.enforce(enforcer, tok, "policy.attributes.List", "read")
	s.Require().Error(err)
	s.False(allowed)
}

type staticProvider struct {
	roles []string
	err   error
}

func (p staticProvider) Roles(_ context.Context, _ jwt.Token, _ authz.RoleRequest) ([]string, error) {
	return p.roles, p.err
}

type countingProvider struct {
	roles []string
	count int
}

func (p *countingProvider) Roles(_ context.Context, _ jwt.Token, _ authz.RoleRequest) ([]string, error) {
	p.count++
	return p.roles, nil
}

func (s *AuthnCasbinSuite) Test_ExternalRoleProvider() {
	policyCfg := internalauthz.PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	policyCfg.Extension = strings.Join([]string{
		"p, role:admin, policy.attributes.*, read, allow",
	}, "\n")

	enforcer, err := newCasbinEnforcer(casbinConfig{
		PolicyConfig: policyCfg,
		RoleProvider: staticProvider{roles: []string{"role:admin"}},
	}, logger.CreateTestLogger())
	s.Require().NoError(err)

	tok := jwt.New()
	allowed, err := s.enforce(enforcer, tok, "policy.attributes.List", "read")
	s.Require().NoError(err)
	s.True(allowed)
}

func (s *AuthnCasbinSuite) Test_Enforce_Uses_Roles_From_Context() {
	policyCfg := internalauthz.PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	policyCfg.Extension = strings.Join([]string{
		"p, role:admin, policy.attributes.*, read, allow",
	}, "\n")

	provider := &countingProvider{roles: []string{"role:admin"}}
	enforcer, err := newCasbinEnforcer(casbinConfig{
		PolicyConfig: policyCfg,
		RoleProvider: provider,
	}, logger.CreateTestLogger())
	s.Require().NoError(err)

	req := authz.RoleRequest{Resource: "policy.attributes.List", Action: "read"}
	tok := jwt.New()
	ctx, err := enforcer.subjectExtractor.ContextWithClaims(s.T().Context(), tok, req)
	s.Require().NoError(err)
	s.Equal(1, provider.count)

	result, err := enforcer.enforce(ctx, tok, req)
	s.Require().NoError(err)
	s.True(result.Allowed)
	s.Equal(1, provider.count)
}

func (s *AuthnCasbinSuite) Test_Enforce_Resolves_Roles_When_Context_Has_Only_ClientID() {
	policyCfg := internalauthz.PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	policyCfg.Extension = strings.Join([]string{
		"p, role:admin, policy.attributes.*, read, allow",
	}, "\n")

	provider := &countingProvider{roles: []string{"role:admin"}}
	enforcer, err := newCasbinEnforcer(casbinConfig{
		PolicyConfig: policyCfg,
		RoleProvider: provider,
	}, logger.CreateTestLogger())
	s.Require().NoError(err)

	req := authz.RoleRequest{Resource: "policy.attributes.List", Action: "read"}
	tok := jwt.New()
	ctx := authz.ContextWithClientID(s.T().Context(), "client-123")

	result, err := enforcer.enforce(ctx, tok, req)
	s.Require().NoError(err)
	s.True(result.Allowed)
	s.Equal(1, provider.count)
}

func (s *AuthnCasbinSuite) Test_Override_Of_Username_Claim() {
	tests := []struct {
		name          string
		usernameClaim string
		resource      string
		action        string
		shouldAllow   bool
		setClaim      bool // whether to set the username claim in the token
	}{
		{
			name:          "Allow with correct username claim (override)",
			usernameClaim: "username",
			resource:      "new.service.DoSomething",
			action:        "read",
			shouldAllow:   true,
			setClaim:      true,
		},
		{
			name:          "Deny with incorrect resource (override)",
			usernameClaim: "username",
			resource:      "policy.attributes.List",
			action:        "read",
			shouldAllow:   false,
			setClaim:      true,
		},
		{
			name:          "Allow with correct username claim (default)",
			usernameClaim: "preferred_username",
			resource:      "new.service.DoSomething",
			action:        "read",
			shouldAllow:   true,
			setClaim:      true,
		},
		{
			name:          "Deny with incorrect resource (default)",
			usernameClaim: "preferred_username",
			resource:      "policy.attributes.List",
			action:        "read",
			shouldAllow:   false,
			setClaim:      true,
		},
		{
			name:          "Deny when username claim not set in token",
			usernameClaim: "username",
			resource:      "new.service.DoSomething",
			action:        "read",
			shouldAllow:   false,
			setClaim:      false,
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			policyCfg := internalauthz.PolicyConfig{}
			err := defaults.Set(&policyCfg)
			s.Require().NoError(err, tc.name)

			policyCfg.UserNameClaim = tc.usernameClaim
			policyCfg.Extension = strings.Join([]string{
				"p, casbin-user, new.service.*, read, allow",
			}, "\n")

			enforcer, err := newCasbinEnforcer(casbinConfig{PolicyConfig: policyCfg}, logger.CreateTestLogger())
			s.Require().NoError(err, tc.name)

			var tok jwt.Token
			if tc.setClaim {
				tok = s.newTokWithDefaultClaim(true, false, tc.usernameClaim, "")
			} else {
				tok = s.newTokWithDefaultClaim(true, false, "", "")
			}

			allowed, err := s.enforce(enforcer, tok, tc.resource, tc.action)
			if tc.shouldAllow {
				s.Require().NoError(err, tc.name)
				s.True(allowed, tc.name)
			} else {
				s.Require().Error(err, tc.name)
				s.False(allowed, tc.name)
			}
		})
	}
}

func (s *AuthnCasbinSuite) Test_Override_Of_Groups_Claim() {
	policyCfg := internalauthz.PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	policyCfg.GroupsClaim = "realm_access.groups"

	enforcer, err := newCasbinEnforcer(casbinConfig{PolicyConfig: policyCfg}, logger.CreateTestLogger())
	s.Require().NoError(err)

	tok := s.newTokWithDefaultClaim(false, true, "", "groups")
	allowed, err := s.enforce(enforcer, tok, "new.service.DoSomething", "read")
	s.Require().Error(err)
	s.False(allowed)

	allowed, err = s.enforce(enforcer, tok, "policy.attributes.List", "read")
	s.Require().NoError(err)
	s.True(allowed)
}

// Test_Casbin_Claims_Matrix was removed as it tested multi-claim and userInfo
// features that are now v2-only. V1 casbin uses single GroupsClaim string and
// ignores the userInfo parameter. These features are tested in
// service/internal/auth/authz/casbin/casbin_test.go for v2.

func (s *AuthnCasbinSuite) enforce(enforcer *Enforcer, tok jwt.Token, resource, action string) (bool, error) {
	result, err := enforcer.enforce(
		context.Background(),
		tok,
		authz.RoleRequest{
			Resource: resource,
			Action:   action,
		},
	)
	return result.Allowed, err
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

	roles := make([]interface{}, 0, 2)

	if admin {
		roles = append(roles, adminRole)
	}
	if standard {
		roles = append(roles, standardRole)
	}

	return roles
}

func (s *AuthnCasbinSuite) newTokWithDefaultClaim(admin bool, standard bool, usernameClaimName string, groupClaimName string) jwt.Token {
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

func (s *AuthnCasbinSuite) newTokenWithClientID() (string, jwt.Token) {
	tok := jwt.New()
	if err := tok.Set("client_id", "test"); err != nil {
		s.T().Fatal(err)
	}
	return "", tok
}
