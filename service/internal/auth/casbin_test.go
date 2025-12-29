package auth

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2/model"
	"github.com/creasty/defaults"
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

	s.True(enforcer.Enforce(tok, nil, "res", "act"))
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
		tok := s.newTokWithDefaultClaim(test.roles[0], test.roles[1], "")
		allowed := enforcer.Enforce(tok, nil, test.resource, test.action)
		if test.allowed {
			s.True(allowed, name)
		} else {
			s.False(allowed, name)
		}

		slog.Info("running test w/ custom claim", slog.String("name", name))

		policyCfg.GroupsClaim = GroupsClaimList{"test.test_roles.roles"}

		enforcer, err = NewCasbinEnforcer(CasbinConfig{
			PolicyConfig: policyCfg,
		}, logger.CreateTestLogger())
		s.Require().NoError(err, name)
		_, tok = s.newTokenWithCustomClaim(test.roles[0], test.roles[1])
		allowed = enforcer.Enforce(tok, nil, test.resource, test.action)
		if test.allowed {
			s.True(allowed, name)
		} else {
			s.False(allowed, name)
		}

		slog.Info("running test w/ custom rolemap", slog.String("name", name))

		policyCfg.RoleMap = map[string]string{
			"admin":    "test-admin",
			"standard": "test-standard",
		}
		policyCfg.GroupsClaim = GroupsClaimList{"realm_access.roles"}

		enforcer, err = NewCasbinEnforcer(CasbinConfig{
			PolicyConfig: policyCfg,
		}, logger.CreateTestLogger())
		s.Require().NoError(err, name)
		_, tok = s.newTokenWithCustomRoleMap(test.roles[0], test.roles[1])
		allowed = enforcer.Enforce(tok, nil, test.resource, test.action)
		if test.allowed {
			s.True(allowed, name)
		} else {
			s.False(allowed, name)
		}

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
		allowed = enforcer.Enforce(tok, nil, test.resource, test.action)
		if test.allowed {
			s.True(allowed, name)
		} else {
			s.False(allowed, name)
		}
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
	tok := s.newTokWithDefaultClaim(true, false, "")
	allowed := enforcer.Enforce(tok, nil, "new.service.DoSomething", "read")
	s.True(allowed)
	allowed = enforcer.Enforce(tok, nil, "new.service.DoSomething", "write")
	s.True(allowed)

	// other roles denied new policy: standard
	tok = s.newTokWithDefaultClaim(false, true, "")
	allowed = enforcer.Enforce(tok, nil, "new.service.DoSomething", "read")
	s.True(allowed)
	allowed = enforcer.Enforce(tok, nil, "new.service.DoSomething", "write")
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
			expectErr: true,  // now expect error due to malformed policy line
			allowed:   false, // fail-safe: should deny
		},
		{
			name: "missing effect",
			extension: strings.Join([]string{
				"g, opentdf-admin, role:admin",
				"g, opentdf-standard, role:standard",
				"p, role:admin, new.service.DoSomething, *",
			}, "\n"),
			expectErr: true,  // now expect error due to malformed policy line
			allowed:   false, // fail-safe: should deny
		},
		{
			name: "missing role prefix",
			extension: strings.Join([]string{
				"g, opentdf-admin, admin",
				"g, opentdf-standard, standard",
				"p, admin, new.service.DoSomething, *",
			}, "\n"),
			expectErr: true, // now expect error due to malformed policy line
			allowed:   false,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			policyCfg := PolicyConfig{}
			err := defaults.Set(&policyCfg)
			s.Require().NoError(err)
			policyCfg.Extension = tc.extension
			enforcer, err := NewCasbinEnforcer(CasbinConfig{PolicyConfig: policyCfg}, logger.CreateTestLogger())
			if tc.expectErr {
				s.Require().Error(err)
				s.Nil(enforcer)
				return
			}

			s.Require().NoError(err)
			s.NotNil(enforcer)

			tok := s.newTokWithDefaultClaim(true, false, "")
			allowed := enforcer.Enforce(tok, nil, "policy.attributes.DoSomething", "read")
			if tc.allowed {
				s.True(allowed)
			} else {
				s.False(allowed)
			}
		})
	}
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

	enforcer, err := NewCasbinEnforcer(CasbinConfig{PolicyConfig: policyCfg}, logger.CreateTestLogger())
	s.Require().NoError(err)

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			tok := s.newTokWithDefaultClaim(tc.admin, tc.standard, "")
			allowed := enforcer.Enforce(tok, nil, tc.resource, tc.action)
			if tc.allowed {
				s.True(allowed, tc.name)
			} else {
				s.False(allowed, tc.name)
			}
		})
	}
}

func (s *AuthnCasbinSuite) Test_Username_Claim_Enforcement() {
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
		policyCfg := PolicyConfig{}
		err := defaults.Set(&policyCfg)
		s.Require().NoError(err, tc.name)

		policyCfg.UserNameClaim = tc.usernameClaim
		policyCfg.Extension = strings.Join([]string{
			"p, casbin-user, new.service.*, read, allow",
		}, "\n")

		enforcer, err := NewCasbinEnforcer(CasbinConfig{PolicyConfig: policyCfg}, logger.CreateTestLogger())
		s.Require().NoError(err, tc.name)

		var tok jwt.Token
		if tc.setClaim {
			tok = s.newTokWithDefaultClaim(true, false, tc.usernameClaim)
		} else {
			tok = s.newTokWithDefaultClaim(true, false, "")
		}

		allowed := enforcer.Enforce(tok, nil, tc.resource, tc.action)
		if tc.shouldAllow && allowed {
			s.True(allowed, tc.name)
		} else {
			s.False(allowed, tc.name)
		}
	}
}

func (s *AuthnCasbinSuite) Test_Casbin_Claims_Matrix() {
	type scenario struct {
		name        string
		groupsClaim GroupsClaimList
		tokenClaims map[string]interface{}
		userInfo    []byte
		shouldAllow bool
		description string
	}

	policyCfg := PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)
	policyCfg.Extension = "p, role:admin, resource, read, allow"

	testMatrix := []scenario{
		{
			name:        "One claim supported (token)",
			groupsClaim: GroupsClaimList{"realm_access.roles"},
			tokenClaims: map[string]interface{}{"realm_access": map[string]interface{}{"roles": []interface{}{"admin"}}},
			shouldAllow: true,
			description: "Token with one supported claim should allow",
		},
		{
			name:        "Multiple claims supported (token)",
			groupsClaim: GroupsClaimList{"realm_access.roles", "custom.roles"},
			tokenClaims: map[string]interface{}{"custom": map[string]interface{}{"roles": []interface{}{"admin"}}},
			shouldAllow: true,
			description: "Token with any supported claim should allow",
		},
		{
			name:        "No claims in token or userInfo",
			groupsClaim: GroupsClaimList{"realm_access.roles", "custom.roles"},
			tokenClaims: map[string]interface{}{},
			shouldAllow: false,
			description: "No claims present should deny",
		},
		{
			name:        "Access token contains claim",
			groupsClaim: GroupsClaimList{"realm_access.roles"},
			tokenClaims: map[string]interface{}{"realm_access": map[string]interface{}{"roles": []interface{}{"admin"}}},
			shouldAllow: true,
			description: "Access token contains claim should allow",
		},
		{
			name:        "User info contains claim",
			groupsClaim: GroupsClaimList{"realm_access.roles"},
			tokenClaims: map[string]interface{}{},
			userInfo:    []byte(`{"realm_access": {"roles": ["admin"]}}`),
			shouldAllow: true,
			description: "User info contains claim should allow",
		},
		{
			name:        "Both token and userInfo have matching claim",
			groupsClaim: GroupsClaimList{"realm_access.roles"},
			tokenClaims: map[string]interface{}{"realm_access": map[string]interface{}{"roles": []interface{}{"admin"}}},
			userInfo:    []byte(`{"realm_access": {"roles": ["admin"]}}`),
			shouldAllow: true,
			description: "Should allow if either token or userInfo matches",
		},
		{
			name:        "Token has non-matching, userInfo has matching claim",
			groupsClaim: GroupsClaimList{"realm_access.roles"},
			tokenClaims: map[string]interface{}{"realm_access": map[string]interface{}{"roles": []interface{}{"other"}}},
			userInfo:    []byte(`{"realm_access": {"roles": ["admin"]}}`),
			shouldAllow: true,
			description: "Should allow if userInfo matches even if token does not",
		},
		{
			name:        "Both token and userInfo have non-matching claims",
			groupsClaim: GroupsClaimList{"realm_access.roles"},
			tokenClaims: map[string]interface{}{"realm_access": map[string]interface{}{"roles": []interface{}{"other"}}},
			userInfo:    []byte(`{"realm_access": {"roles": ["other2"]}}`),
			shouldAllow: false,
			description: "Should deny if neither token nor userInfo matches",
		},
		{
			name:        "Malformed userInfo JSON",
			groupsClaim: GroupsClaimList{"realm_access.roles"},
			tokenClaims: map[string]interface{}{},
			userInfo:    []byte(`not-a-json`),
			shouldAllow: false,
			description: "Should deny and not panic on malformed userInfo JSON",
		},
		{
			name:        "GroupsClaim with nested path that doesn't exist",
			groupsClaim: GroupsClaimList{"nonexistent.path.roles"},
			tokenClaims: map[string]interface{}{"realm_access": map[string]interface{}{"roles": []interface{}{"admin"}}},
			shouldAllow: false,
			description: "Should deny if claim path does not exist",
		},
		{
			name:        "GroupsClaim as empty list",
			groupsClaim: GroupsClaimList{},
			tokenClaims: map[string]interface{}{"realm_access": map[string]interface{}{"roles": []interface{}{"admin"}}},
			shouldAllow: false,
			description: "Should deny if no groups claim configured",
		},
		{
			name:        "GroupsClaim with multiple, only one matches",
			groupsClaim: GroupsClaimList{"realm_access.roles", "custom.roles"},
			tokenClaims: map[string]interface{}{"custom": map[string]interface{}{"roles": []interface{}{"admin"}}},
			shouldAllow: true,
			description: "Should allow if any claim in GroupsClaim matches",
		},
		{
			name:        "GroupsClaim with multiple, all match",
			groupsClaim: GroupsClaimList{"realm_access.roles", "custom.roles"},
			tokenClaims: map[string]interface{}{
				"realm_access": map[string]interface{}{"roles": []interface{}{"admin"}},
				"custom":       map[string]interface{}{"roles": []interface{}{"admin"}},
			},
			shouldAllow: true,
			description: "Should allow if all claims in GroupsClaim match",
		},
		{
			name:        "UserInfo present but empty",
			groupsClaim: GroupsClaimList{"realm_access.roles"},
			tokenClaims: map[string]interface{}{},
			userInfo:    []byte(`{}`),
			shouldAllow: false,
			description: "Should deny if userInfo is present but empty",
		},
		{
			name:        "Token and UserInfo both empty",
			groupsClaim: GroupsClaimList{"realm_access.roles"},
			tokenClaims: map[string]interface{}{},
			userInfo:    nil,
			shouldAllow: false,
			description: "Should deny if both token and userInfo are empty",
		},
		{
			name:        "UserInfo nil or empty length",
			groupsClaim: GroupsClaimList{"realm_access.roles"},
			tokenClaims: map[string]interface{}{},
			userInfo:    nil,
			shouldAllow: false,
			description: "Should deny if userInfo is nil",
		},
		{
			name:        "UserInfo empty slice",
			groupsClaim: GroupsClaimList{"realm_access.roles"},
			tokenClaims: map[string]interface{}{},
			userInfo:    []byte{},
			shouldAllow: false,
			description: "Should deny if userInfo is empty slice",
		},
	}

	for _, tc := range testMatrix {
		s.Run(tc.name, func() {
			cfg := policyCfg
			cfg.GroupsClaim = tc.groupsClaim
			enforcer, err := NewCasbinEnforcer(CasbinConfig{PolicyConfig: cfg}, logger.CreateTestLogger())
			s.Require().NoError(err)

			tok := jwt.New()
			for k, v := range tc.tokenClaims {
				if err := tok.Set(k, v); err != nil {
					s.Fail("Failed to set token claim", err)
				}
			}
			allowed := enforcer.Enforce(tok, tc.userInfo, "resource", "read")
			if tc.shouldAllow && allowed {
				s.True(allowed, tc.description)
			} else {
				s.False(allowed, tc.description)
			}
		})
	}
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

func (s *AuthnCasbinSuite) newTokWithDefaultClaim(admin bool, standard bool, usernameClaimName string) jwt.Token {
	tok := jwt.New()

	// Always using "roles" as the group claim name
	groupClaimName := "roles"

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
