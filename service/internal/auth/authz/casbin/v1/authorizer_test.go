package v1

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/suite"
)

type AuthorizerSuite struct {
	suite.Suite
	logger *logger.Logger
}

func TestAuthorizerSuite(t *testing.T) {
	suite.Run(t, new(AuthorizerSuite))
}

func (s *AuthorizerSuite) SetupTest() {
	s.logger = logger.CreateTestLogger()
}

func (s *AuthorizerSuite) TestAuthorizeGRPCPathStripsLeadingSlash() {
	authorizer, err := NewAuthorizer(authz.CasbinV1Config{
		PolicyConfig: authz.PolicyConfig{
			Issuer:      "https://issuer.example",
			GroupsClaim: "realm_access.roles",
			Csv:         "p, role:unknown, kas.AccessService/Rewrap, read, allow",
		},
	}, s.logger)
	s.Require().NoError(err)

	token := createAuthorizerTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"standard"},
		},
	})

	decision, err := authorizer.Authorize(s.T().Context(), &authz.Request{
		Token:  token,
		RPC:    "/kas.AccessService/Rewrap",
		Action: "read",
	})
	s.Require().NoError(err)
	s.True(decision.Allowed, "gRPC path should be allowed after stripping leading slash")
	s.Equal(authz.ModeV1, decision.Mode)
}

func (s *AuthorizerSuite) TestAuthorizeHTTPPathKeepsLeadingSlash() {
	authorizer, err := NewAuthorizer(authz.CasbinV1Config{
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
			Csv:         "p, role:unknown, /kas/v2/rewrap, write, allow",
		},
	}, s.logger)
	s.Require().NoError(err)

	token := createAuthorizerTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"standard"},
		},
	})

	decision, err := authorizer.Authorize(s.T().Context(), &authz.Request{
		Token:  token,
		RPC:    "/kas/v2/rewrap",
		Action: "write",
	})
	s.Require().NoError(err)
	s.True(decision.Allowed, "HTTP path should be allowed with leading slash intact")
	s.Equal(authz.ModeV1, decision.Mode)
}

func (s *AuthorizerSuite) TestAuthorizePolicyServiceGRPCPath() {
	authorizer, err := NewAuthorizer(authz.CasbinV1Config{
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
			Csv:         "p, role:unknown, policy.*, read, allow",
		},
	}, s.logger)
	s.Require().NoError(err)

	token := createAuthorizerTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"standard"},
		},
	})

	decision, err := authorizer.Authorize(s.T().Context(), &authz.Request{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/GetAttribute",
		Action: "read",
	})
	s.Require().NoError(err)
	s.True(decision.Allowed, "policy.* wildcard should match gRPC path after stripping leading slash")
	s.Equal(authz.ModeV1, decision.Mode)
}

func (s *AuthorizerSuite) TestAuthorizePathHandlingHeuristic() {
	authorizer, err := NewAuthorizer(authz.CasbinV1Config{
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
			Csv: strings.Join([]string{
				"p, role:unknown, some.Service/Method, read, allow",
				"p, role:unknown, /http/path, read, allow",
			}, "\n"),
		},
	}, s.logger)
	s.Require().NoError(err)

	token := createAuthorizerTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"test"},
		},
	})

	decision, err := authorizer.Authorize(context.Background(), &authz.Request{
		Token:  token,
		RPC:    "/some.Service/Method",
		Action: "read",
	})
	s.Require().NoError(err)
	s.True(decision.Allowed, "gRPC path should be allowed")

	decision, err = authorizer.Authorize(context.Background(), &authz.Request{
		Token:  token,
		RPC:    "/http/path",
		Action: "read",
	})
	s.Require().NoError(err)
	s.True(decision.Allowed, "HTTP path should be allowed")
}

func (s *AuthorizerSuite) TestAuthorizeDeniedResultReturnsDeniedDecision() {
	authorizer, err := NewAuthorizer(authz.CasbinV1Config{
		PolicyConfig: authz.PolicyConfig{
			Issuer:      "https://issuer.example",
			GroupsClaim: "realm_access.roles",
			Csv:         "p, role:standard, policy.attributes.AttributesService/GetAttribute, write, allow",
		},
		RoleProvider: staticProvider{roles: []string{"role:standard"}},
	}, s.logger)
	s.Require().NoError(err)

	decision, err := authorizer.Authorize(context.Background(), &authz.Request{
		Token:  jwt.New(),
		RPC:    "/policy.attributes.AttributesService/GetAttribute",
		Action: "read",
	})
	s.Require().NoError(err)
	s.Require().NotNil(decision)
	s.False(decision.Allowed)
	s.Equal(authz.ModeV1, decision.Mode)
	s.Equal("v1: denied read policy.attributes.AttributesService/GetAttribute", decision.Reason)
	s.Equal("realm_access.roles", decision.Metadata.GroupsClaim)
}

func (s *AuthorizerSuite) TestAuthorizeAllowedResultReturnsAllowedDecision() {
	authorizer, err := NewAuthorizer(authz.CasbinV1Config{
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "custom.roles",
			Csv:         "p, role:standard, /kas/v2/rewrap, write, allow",
		},
		RoleProvider: staticProvider{roles: []string{"role:standard"}},
	}, s.logger)
	s.Require().NoError(err)

	decision, err := authorizer.Authorize(context.Background(), &authz.Request{
		Token:  jwt.New(),
		RPC:    "/kas/v2/rewrap",
		Action: "write",
	})
	s.Require().NoError(err)
	s.Require().NotNil(decision)
	s.True(decision.Allowed)
	s.Equal("v1: write /kas/v2/rewrap", decision.Reason)
	s.Equal("custom.roles", decision.Metadata.GroupsClaim)
}

func (s *AuthorizerSuite) TestAuthorizeEnforcementErrorReturnsSystemError() {
	authorizer, err := NewAuthorizer(authz.CasbinV1Config{
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
			Csv:         "p, role:standard, /kas/v2/rewrap, write, allow",
		},
		RoleProvider: staticProvider{err: errors.New("role provider failed")},
	}, s.logger)
	s.Require().NoError(err)

	decision, err := authorizer.Authorize(context.Background(), &authz.Request{
		Token:  jwt.New(),
		RPC:    "/kas/v2/rewrap",
		Action: "write",
	})
	s.Require().ErrorContains(err, "v1 authorization system error")
	s.Nil(decision)
}

func (s *AuthorizerSuite) TestAuthorize_NilRequest_ReturnsError() {
	authorizer, err := NewAuthorizer(authz.CasbinV1Config{
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
			Csv:         "p, role:admin, *, *, allow",
		},
	}, s.logger)
	s.Require().NoError(err)

	decision, err := authorizer.Authorize(s.T().Context(), nil)
	s.Require().Error(err)
	s.Nil(decision)
}

func (s *AuthorizerSuite) TestAuthorize_NilToken_ReturnsError() {
	authorizer, err := NewAuthorizer(authz.CasbinV1Config{
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
			Csv:         "p, role:admin, *, *, allow",
		},
	}, s.logger)
	s.Require().NoError(err)

	decision, err := authorizer.Authorize(s.T().Context(), &authz.Request{Token: nil})
	s.Require().Error(err)
	s.Nil(decision)
}

func createAuthorizerTestToken(t *testing.T, claims map[string]interface{}) jwt.Token {
	t.Helper()
	token := jwt.New()
	for k, v := range claims {
		if err := token.Set(k, v); err != nil {
			t.Fatalf("failed to set claim %s: %v", k, err)
		}
	}
	return token
}
