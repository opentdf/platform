package v1

import (
	"context"
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

	decision, err := authorizer.Authorize(context.Background(), &authz.Request{
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

	decision, err := authorizer.Authorize(context.Background(), &authz.Request{
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

	decision, err := authorizer.Authorize(context.Background(), &authz.Request{
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
