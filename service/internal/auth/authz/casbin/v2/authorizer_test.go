package v2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/logger"
	platformauthz "github.com/opentdf/platform/service/pkg/authz"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type staticRoleProvider struct {
	roles []string
	err   error
}

func (p staticRoleProvider) Roles(_ context.Context, _ jwt.Token, _ platformauthz.RoleRequest) ([]string, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.roles, nil
}

type recordingRoleProvider struct {
	roles []string
	req   platformauthz.RoleRequest
}

func (p *recordingRoleProvider) Roles(_ context.Context, _ jwt.Token, req platformauthz.RoleRequest) ([]string, error) {
	p.req = req
	return p.roles, nil
}

type CasbinAuthorizerSuite struct {
	suite.Suite
	logger *logger.Logger
}

func TestCasbinAuthorizerSuite(t *testing.T) {
	suite.Run(t, new(CasbinAuthorizerSuite))
}

func (s *CasbinAuthorizerSuite) SetupTest() {
	s.logger = logger.CreateTestLogger()
}

func (s *CasbinAuthorizerSuite) TestNewCasbinAuthorizer_V2() {
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
		},
		Logger: s.logger,
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)
	s.Require().NotNil(authorizer)

	s.Equal("v2", authorizer.Version())
	s.True(authorizer.SupportsResourceAuthorization())
}

func (s *CasbinAuthorizerSuite) TestNewAuthorizerRequiresLogger() {
	authorizer, err := NewAuthorizer(authz.CasbinV2Config{}, nil)
	s.Require().ErrorIs(err, errLoggerRequired)
	s.Nil(authorizer)
}

func (s *CasbinAuthorizerSuite) TestAuthorizeRequiresRequestAndToken() {
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version: "v2",
			Csv:     "p, role:admin, *, *, allow",
		},
		Logger: s.logger,
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	decision, err := authorizer.Authorize(s.T().Context(), nil)
	s.Require().Error(err)
	s.Nil(decision)
	s.Contains(err.Error(), "authorization request is required")

	decision, err = authorizer.Authorize(s.T().Context(), &authz.Request{})
	s.Require().Error(err)
	s.Nil(decision)
	s.Contains(err.Error(), "authorization token is required")
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_AdminWildcard() {
	// Policy: admin can do anything
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
			Csv:         "p, role:admin, *, *, allow",
		},
		Logger: s.logger,
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	// Create token with admin role
	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"admin"},
		},
	})

	req := &authz.Request{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: "write",
		ResourceContext: &authz.ResolverContext{
			Resources: []*authz.ResolverResource{
				{"namespace": "hr", "attribute": "classification"},
			},
		},
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	s.Require().NoError(err)
	s.True(decision.Allowed)
	s.Equal(authz.ModeV2, decision.Mode)
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_DefaultPolicyIncludesDefaultRoleGroupings() {
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
		},
		Logger: s.logger,
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"opentdf-admin"},
		},
	})
	req := &authz.Request{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: "write",
	}

	decision, err := authorizer.Authorize(s.T().Context(), req)
	s.Require().NoError(err)
	s.Require().NotNil(decision)
	s.True(decision.Allowed, "default v2 policy should map opentdf-admin to role:admin")
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_NamespaceScopedAccess() {
	// Policy: hr-admin can only access HR namespace
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
			Csv: `p, role:hr-admin, /policy.attributes.AttributesService/*, namespace=hr, allow
p, role:finance-admin, /policy.attributes.AttributesService/*, namespace=finance, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	// Create token with hr-admin role
	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"hr-admin"},
		},
	})

	// Should allow access to HR namespace
	hrReq := &authz.Request{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: "write",
		ResourceContext: &authz.ResolverContext{
			Resources: []*authz.ResolverResource{
				{"namespace": "hr"},
			},
		},
	}

	decision, err := authorizer.Authorize(context.Background(), hrReq)
	s.Require().NoError(err)
	s.True(decision.Allowed, "hr-admin should be allowed to access HR namespace")

	// Should deny access to Finance namespace
	financeReq := &authz.Request{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: "write",
		ResourceContext: &authz.ResolverContext{
			Resources: []*authz.ResolverResource{
				{"namespace": "finance"},
			},
		},
	}

	decision, err = authorizer.Authorize(context.Background(), financeReq)
	s.Require().NoError(err)
	s.False(decision.Allowed, "hr-admin should NOT be allowed to access Finance namespace")
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_MultipleDimensions() {
	// Policy: requires both namespace and attribute dimensions
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
			Csv:         `p, role:classification-owner, /policy.attributes.AttributesService/Update*, namespace=hr&attribute=classification, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"classification-owner"},
		},
	})

	// Should allow with both dimensions matching
	req := &authz.Request{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: "write",
		ResourceContext: &authz.ResolverContext{
			Resources: []*authz.ResolverResource{
				{"namespace": "hr", "attribute": "classification"},
			},
		},
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	s.Require().NoError(err)
	s.True(decision.Allowed, "should be allowed with matching namespace and attribute")

	// Should deny with wrong attribute
	wrongAttrReq := &authz.Request{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: "write",
		ResourceContext: &authz.ResolverContext{
			Resources: []*authz.ResolverResource{
				{"namespace": "hr", "attribute": "department"},
			},
		},
	}

	decision, err = authorizer.Authorize(context.Background(), wrongAttrReq)
	s.Require().NoError(err)
	s.False(decision.Allowed, "should NOT be allowed with wrong attribute")
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_MultipleResourcesAllOf() {
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
			Csv:         `p, role:hr-admin, /policy.attributes.AttributesService/Update*, namespace=hr, allow`, // ? This really should be a List req
		},
		Logger: s.logger,
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"hr-admin"},
		},
	})

	allowedReq := &authz.Request{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: "write",
		ResourceContext: &authz.ResolverContext{
			Resources: []*authz.ResolverResource{
				{"namespace": "hr", "attribute": "classification"},
				{"namespace": "hr", "attribute": "department"},
			},
		},
	}

	decision, err := authorizer.Authorize(s.T().Context(), allowedReq)
	s.Require().NoError(err)
	s.True(decision.Allowed, "all HR resources should be allowed")

	deniedReq := &authz.Request{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: "write",
		ResourceContext: &authz.ResolverContext{
			Resources: []*authz.ResolverResource{
				{"namespace": "hr", "attribute": "classification"},
				{"namespace": "finance", "attribute": "payroll"},
			},
		},
	}

	decision, err = authorizer.Authorize(s.T().Context(), deniedReq)
	s.Require().NoError(err)
	s.False(decision.Allowed, "one denied resource should deny the aggregate request")
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_MultipleResourcesCollectsUniqueMatchedSubjects() {
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
			Csv: `p, role:hr-admin, /policy.attributes.AttributesService/Update*, namespace=hr, allow
p, role:finance-admin, /policy.attributes.AttributesService/Update*, namespace=finance, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"hr-admin", "finance-admin"},
		},
	})

	decision, err := authorizer.Authorize(s.T().Context(), &authz.Request{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: "write",
		ResourceContext: &authz.ResolverContext{
			Resources: []*authz.ResolverResource{
				{"namespace": "hr", "attribute": "classification"},
				{"namespace": "finance", "attribute": "payroll"},
				{"namespace": "hr", "attribute": "department"},
			},
		},
	})

	s.Require().NoError(err)
	s.Require().NotNil(decision)
	s.True(decision.Allowed)
	s.Equal("role:hr-admin, role:finance-admin", decision.MatchedPolicy)
	s.Equal("v2: role:hr-admin, role:finance-admin on /policy.attributes.AttributesService/UpdateAttribute", decision.Reason)
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_MultipleResourcesSkipsNilAndEmpty() {
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
			Csv:         `p, role:hr-admin, /policy.attributes.AttributesService/Update*, namespace=hr, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"hr-admin"},
		},
	})
	emptyResource := authz.ResolverResource{}

	decision, err := authorizer.Authorize(s.T().Context(), &authz.Request{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: "write",
		ResourceContext: &authz.ResolverContext{
			Resources: []*authz.ResolverResource{
				nil,
				&emptyResource,
				{"namespace": "hr", "attribute": "classification"},
			},
		},
	})
	s.Require().NoError(err)
	s.True(decision.Allowed, "nil and empty resources should be skipped when a real resource is present")
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_EnforcementErrorReturnsSystemError() {
	brokenModel := strings.Replace(
		modelV2,
		"m = g(r.sub, p.sub) && keyMatch(r.rpc, p.rpc) && dimensionMatch(r.dims, p.dims)",
		"m = g(r.sub, p.sub) && keyMatch(r.rpc, p.rpc) && missingDimensionMatch(r.dims, p.dims)",
		1,
	)
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
			Model:       brokenModel,
			Csv:         `p, role:hr-admin, /policy.attributes.AttributesService/Update*, namespace=hr, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"hr-admin"},
		},
	})

	decision, err := authorizer.Authorize(s.T().Context(), &authz.Request{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: "write",
		ResourceContext: &authz.ResolverContext{
			Resources: []*authz.ResolverResource{
				{"namespace": "hr"},
			},
		},
	})

	s.Require().Error(err)
	s.Nil(decision)
	s.Contains(err.Error(), "v2 authorization system error")
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_WildcardDimension() {
	// Policy: wildcard for attribute dimension
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
			Csv:         `p, role:hr-viewer, /policy.attributes.AttributesService/Get*, namespace=hr&attribute=*, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"hr-viewer"},
		},
	})

	// Should allow any attribute in HR namespace
	req := &authz.Request{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/GetAttribute",
		Action: "read",
		ResourceContext: &authz.ResolverContext{
			Resources: []*authz.ResolverResource{
				{"namespace": "hr", "attribute": "any-attribute"},
			},
		},
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	s.Require().NoError(err)
	s.True(decision.Allowed, "should be allowed with wildcard attribute")
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_NoDimensions() {
	// Policy with wildcard dimensions
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
			Csv:         `p, role:standard, /policy.attributes.AttributesService/Get*, *, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"standard"},
		},
	})

	// Should allow with no resource context (nil)
	req := &authz.Request{
		Token:           token,
		RPC:             "/policy.attributes.AttributesService/GetAttribute",
		Action:          "read",
		ResourceContext: nil,
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	s.Require().NoError(err)
	s.True(decision.Allowed, "should be allowed with nil resource context when policy has wildcard")
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_NoDimensionsDeniedWhenPolicyRequiresDimension() {
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
			Csv:         `p, role:standard, /policy.attributes.AttributesService/Get*, namespace=finance, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"standard"},
		},
	})

	decision, err := authorizer.Authorize(context.Background(), &authz.Request{
		Token:           token,
		RPC:             "/policy.attributes.AttributesService/GetAttribute",
		Action:          "read",
		ResourceContext: nil,
	})
	s.Require().NoError(err)
	s.False(decision.Allowed, "should deny nil resource context when policy requires dimensions")
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_UsernameWithRolePrefixIsIgnored() {
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:       "v2",
			UserNameClaim: "preferred_username",
			Csv:           `p, role:admin, /policy.attributes.AttributesService/Get*, *, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"preferred_username": "role:admin",
	})

	req := &authz.Request{
		Token: token,
		RPC:   "/policy.attributes.AttributesService/GetAttribute",
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	s.Require().NoError(err)
	s.False(decision.Allowed, "username with reserved role prefix must not match role subjects")
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_ClientIDPolicy() {
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:       "v2",
			ClientIDClaim: "client_id",
			Csv:           `p, client:test-client, /policy.attributes.AttributesService/Get*, *, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"client_id": "test-client",
	})

	req := &authz.Request{
		Token: token,
		RPC:   "/policy.attributes.AttributesService/GetAttribute",
	}

	decision, err := authorizer.Authorize(s.T().Context(), req)
	s.Require().NoError(err)
	s.True(decision.Allowed, "client policy should allow matching client ID")
	s.Equal("client:test-client", decision.MatchedPolicy)

	req.RPC = "/policy.attributes.AttributesService/CreateAttribute"
	decision, err = authorizer.Authorize(s.T().Context(), req)
	s.Require().NoError(err)
	s.False(decision.Allowed, "client policy should deny unmatched RPC")
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_UsesSharedSubjectExtractorOrdering() {
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:       "v2",
			GroupsClaim:   "realm_access.roles",
			UserNameClaim: "preferred_username",
			ClientIDClaim: "azp",
			Csv: `p, client:test-client, /policy.attributes.AttributesService/Get*, *, allow
p, role:admin, /policy.attributes.AttributesService/Get*, *, allow
p, alice, /policy.attributes.AttributesService/Get*, *, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	casbinAuthorizer, ok := authorizer.(*Authorizer)
	s.Require().True(ok)

	token := createTestToken(s.T(), map[string]interface{}{
		"azp":                "test-client",
		"preferred_username": "alice",
		"realm_access": map[string]interface{}{
			"roles": []string{"admin"},
		},
	})

	subjectExtractor := casbinAuthorizer.subjectExtractor
	subjects, roles, err := subjectExtractor.BuildV2SubjectsFromToken(
		s.T().Context(),
		token,
		platformauthz.RoleRequest{},
	)
	s.Require().NoError(err)
	s.Equal([]string{"client:test-client", "role:admin", "alice"}, subjects)
	s.Equal([]string{"role:admin"}, roles)

	decision, err := authorizer.Authorize(s.T().Context(), &authz.Request{
		Token: token,
		RPC:   "/policy.attributes.AttributesService/GetAttribute",
	})
	s.Require().NoError(err)
	s.True(decision.Allowed)
	s.Equal("client:test-client", decision.MatchedPolicy)
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_UsesConfiguredRoleProvider() {
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
			Csv:         "p, role:external-admin, /policy.attributes.AttributesService/Get*, *, allow",
		},
		Logger:  s.logger,
		Options: []authz.Option{authz.WithRoleProvider(staticRoleProvider{roles: []string{"external-admin"}})},
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []string{"not-used"},
		},
	})

	decision, err := authorizer.Authorize(s.T().Context(), &authz.Request{
		Token: token,
		RPC:   "/policy.attributes.AttributesService/GetAttribute",
	})
	s.Require().NoError(err)
	s.True(decision.Allowed)
	s.Equal("role:external-admin", decision.MatchedPolicy)
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_PassesRoleRequestToRoleProvider() {
	roleProvider := &recordingRoleProvider{roles: []string{"external-admin"}}
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version: "v2",
			Issuer:  "https://issuer.example",
			Csv:     "p, role:external-admin, /policy.attributes.AttributesService/Get*, *, allow",
		},
		Logger:  s.logger,
		Options: []authz.Option{authz.WithRoleProvider(roleProvider)},
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	_, err = authorizer.Authorize(s.T().Context(), &authz.Request{
		Token:  jwt.New(),
		RPC:    "/policy.attributes.AttributesService/GetAttribute",
		Action: "read",
	})
	s.Require().NoError(err)
	s.Equal(platformauthz.RoleRequest{
		Issuer:   "https://issuer.example",
		Resource: "/policy.attributes.AttributesService/GetAttribute",
		Action:   "read",
	}, roleProvider.req)
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_ReturnsSubjectExtractionError() {
	roleProviderErr := errors.New("role provider unavailable")
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
			Csv:         "p, role:external-admin, /policy.attributes.AttributesService/Get*, *, allow",
		},
		Logger:  s.logger,
		Options: []authz.Option{authz.WithRoleProvider(staticRoleProvider{err: roleProviderErr})},
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	decision, err := authorizer.Authorize(s.T().Context(), &authz.Request{
		Token: jwt.New(),
		RPC:   "/policy.attributes.AttributesService/GetAttribute",
	})
	s.Require().Error(err)
	s.Nil(decision)
	s.Require().ErrorIs(err, roleProviderErr)
	s.Require().Contains(err.Error(), "v2 authorization subject extraction error")
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_KASRESTfulPathsAllowed() {
	// v2 uses leading slashes for ALL paths (both gRPC and HTTP)
	// This test ensures KAS RESTful paths work in v2 authorization
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
			Csv: `p, role:standard, /kas.AccessService/*, *, allow
p, role:standard, /kas/v2/rewrap, *, allow
p, role:unknown, /kas.AccessService/Rewrap, *, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	standardToken := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"standard"},
		},
	})

	unknownToken := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"unknown"},
		},
	})

	tests := []struct {
		name    string
		token   jwt.Token
		rpc     string
		action  string
		allowed bool
	}{
		// gRPC paths - standard role (v2 keeps leading slash)
		{"standard gRPC rewrap read", standardToken, "/kas.AccessService/Rewrap", "read", true},
		{"standard gRPC rewrap write", standardToken, "/kas.AccessService/Rewrap", "write", true},
		// HTTP paths - standard role
		{"standard HTTP rewrap read", standardToken, "/kas/v2/rewrap", "read", true},
		{"standard HTTP rewrap write", standardToken, "/kas/v2/rewrap", "write", true},
		// gRPC paths - unknown role
		{"unknown gRPC rewrap", unknownToken, "/kas.AccessService/Rewrap", "read", true},
		// HTTP paths - unknown role
		{"unknown HTTP rewrap", unknownToken, "/kas/v2/rewrap", "write", false},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			req := &authz.Request{
				Token:  tc.token,
				RPC:    tc.rpc,
				Action: tc.action,
			}

			decision, err := authorizer.Authorize(context.Background(), req)
			s.Require().NoError(err)
			s.Equal(tc.allowed, decision.Allowed, "expected allowed=%v for %s", tc.allowed, tc.name)
			s.Equal(authz.ModeV2, decision.Mode)
		})
	}
}

// Test dimension matching logic
func TestDimensionMatch(t *testing.T) {
	tests := []struct {
		name       string
		reqDims    string
		policyDims string
		expected   bool
	}{
		{
			name:       "wildcard policy matches anything",
			reqDims:    "namespace=hr&attribute=classification",
			policyDims: "*",
			expected:   true,
		},
		{
			name:       "exact match",
			reqDims:    "namespace=hr",
			policyDims: "namespace=hr",
			expected:   true,
		},
		{
			name:       "exact match multiple dimensions - order insensitive",
			reqDims:    "attribute=classification&namespace=hr",
			policyDims: "namespace=hr&attribute=classification",
			expected:   true,
		},
		{
			name:       "wildcard value matches any",
			reqDims:    "namespace=hr&attribute=classification",
			policyDims: "namespace=hr&attribute=*",
			expected:   true,
		},
		{
			name:       "request has extra dimensions - still matches",
			reqDims:    "attribute=classification&namespace=hr&value=secret",
			policyDims: "namespace=hr",
			expected:   true,
		},
		{
			name:       "policy requires dimension not in request",
			reqDims:    "namespace=hr",
			policyDims: "namespace=hr&attribute=classification",
			expected:   false,
		},
		{
			name:       "value mismatch",
			reqDims:    "namespace=finance",
			policyDims: "namespace=hr",
			expected:   false,
		},
		{
			name:       "empty request matches wildcard",
			reqDims:    "*",
			policyDims: "*",
			expected:   true,
		},
		{
			name:       "empty policy matches empty request",
			reqDims:    "",
			policyDims: "",
			expected:   true,
		},
		{
			name:       "malformed request dimensions fail",
			reqDims:    "name&space=hr",
			policyDims: "space=hr",
			expected:   false,
		},
		{
			name:       "invalid policy key with separator fails",
			reqDims:    "namespace=hr",
			policyDims: "name&space=hr",
			expected:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := dimensionMatch(tc.reqDims, tc.policyDims)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test dimension serialization
func TestSerializeDimensions(t *testing.T) {
	tests := []struct {
		name      string
		ctx       *authz.ResolverContext
		expected  []string
		expectErr bool
	}{
		{
			name:     "nil context",
			ctx:      nil,
			expected: []string{"*"},
		},
		{
			name:     "empty context",
			ctx:      &authz.ResolverContext{},
			expected: []string{"*"},
		},
		{
			name: "single dimension",
			ctx: &authz.ResolverContext{
				Resources: []*authz.ResolverResource{
					{"namespace": "hr"},
				},
			},
			expected: []string{"namespace=hr"},
		},
		{
			name: "multiple dimensions sorted alphabetically",
			ctx: &authz.ResolverContext{
				Resources: []*authz.ResolverResource{
					{"namespace": "hr", "attribute": "classification"},
				},
			},
			expected: []string{"attribute=classification&namespace=hr"},
		},
		{
			name: "multiple resources remain independent",
			ctx: &authz.ResolverContext{
				Resources: []*authz.ResolverResource{
					{"namespace": "hr", "attribute": "classification"},
					{"namespace": "finance", "attribute": "payroll"},
				},
			},
			expected: []string{
				"attribute=classification&namespace=hr",
				"attribute=payroll&namespace=finance",
			},
		},
		{
			name: "conflicting duplicate keys across resources are allowed",
			ctx: &authz.ResolverContext{
				Resources: []*authz.ResolverResource{
					{"namespace": "hr"},
					{"namespace": "finance"},
				},
			},
			expected: []string{"namespace=hr", "namespace=finance"},
		},
		{
			name: "mixed real nil and empty resources skips nil and empty",
			ctx: &authz.ResolverContext{
				Resources: []*authz.ResolverResource{
					nil,
					{},
					{"namespace": "hr"},
				},
			},
			expected: []string{"namespace=hr"},
		},
		{
			name: "only nil and empty resources returns wildcard",
			ctx: &authz.ResolverContext{
				Resources: []*authz.ResolverResource{
					nil,
					{},
				},
			},
			expected: []string{"*"},
		},
		{
			name: "invalid key with separator fails",
			ctx: &authz.ResolverContext{
				Resources: []*authz.ResolverResource{
					{"name=space": "hr"},
				},
			},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := serializeDimensions(tc.ctx)
			if tc.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test dimension value injection prevention via URL-encoding
func TestSerializeDimensions_InjectionPrevention(t *testing.T) {
	tests := []struct {
		name     string
		ctx      *authz.ResolverContext
		expected string
	}{
		{
			name: "value with ampersand is safely encoded",
			ctx: &authz.ResolverContext{
				Resources: []*authz.ResolverResource{
					{"kas_uri": "https://kas.example.com?foo=bar&second_dim=injected"},
				},
			},
			// The '&' in the value must be percent-encoded so parseDimensions
			// sees only one key-value pair, not two.
			expected: "kas_uri=https://kas.example.com?foo=bar%26second_dim=injected",
		},
		{
			name: "value with equals sign is unchanged",
			ctx: &authz.ResolverContext{
				Resources: []*authz.ResolverResource{
					{"kas_uri": "https://kas.example.com?key=value"},
				},
			},
			expected: "kas_uri=https://kas.example.com?key=value",
		},
		{
			name: "plain URI with colon and slashes is unchanged",
			ctx: &authz.ResolverContext{
				Resources: []*authz.ResolverResource{
					{"kas_uri": "https://kas.example.com"},
				},
			},
			expected: "kas_uri=https://kas.example.com",
		},
		{
			name: "value with percent sign is safely encoded",
			ctx: &authz.ResolverContext{
				Resources: []*authz.ResolverResource{
					{"label": "done%complete"},
				},
			},
			expected: "label=done%25complete",
		},
		{
			name: "wildcard token value is safely encoded",
			ctx: &authz.ResolverContext{
				Resources: []*authz.ResolverResource{
					{"label": "*"},
				},
			},
			expected: "label=%2A",
		},
		{
			name: "plain value without special chars is unchanged",
			ctx: &authz.ResolverContext{
				Resources: []*authz.ResolverResource{
					{"namespace": "hr"},
				},
			},
			expected: "namespace=hr",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := serializeDimensions(tc.ctx)
			require.NoError(t, err)
			require.Len(t, result, 1)
			assert.Equal(t, tc.expected, result[0])
		})
	}
}

// TestParseDimensions_RoundTrip verifies that values containing special characters
// survive a serialize→parse round-trip without being misinterpreted.
func TestParseDimensions_RoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input map[string]string
	}{
		{
			name:  "value with ampersand round-trips correctly",
			input: map[string]string{"kas_uri": "https://kas.example.com?foo=bar&second_dim=injected"},
		},
		{
			name:  "value with equals sign round-trips correctly",
			input: map[string]string{"kas_uri": "https://kas.example.com?key=value"},
		},
		{
			name:  "full URI with query string round-trips correctly",
			input: map[string]string{"kas_uri": "https://kas.example.com?foo=bar&baz=qux"},
		},
		{
			name:  "value with literal plus round-trips correctly",
			input: map[string]string{"kas_uri": "https://kas.example.com/path+plus?token=a+b"},
		},
		{
			name:  "value with space round-trips correctly",
			input: map[string]string{"display_name": "first last"},
		},
		{
			name:  "value with percent round-trips correctly",
			input: map[string]string{"label": "done%complete"},
		},
		{
			name:  "wildcard token value round-trips correctly",
			input: map[string]string{"label": "*"},
		},
		{
			name:  "plain value round-trips correctly",
			input: map[string]string{"namespace": "hr"},
		},
		{
			name:  "multiple dimensions including URI round-trip correctly",
			input: map[string]string{"kas_uri": "https://kas.example.com?x=1&y=2", "namespace": "hr"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Build a ResolverContext from the input map
			res := authz.ResolverResource(tc.input)
			ctx := &authz.ResolverContext{
				Resources: []*authz.ResolverResource{&res},
			}

			serialized, err := serializeDimensions(ctx)
			require.NoError(t, err)
			require.Len(t, serialized, 1)

			parsed, ok := parseDimensions(serialized[0])
			require.True(t, ok, "parseDimensions must succeed on serialized output")
			assert.Equal(t, tc.input, parsed, "round-trip must preserve original values exactly")
		})
	}
}

// TestDimensionMatch_WithURIValues verifies that dimensionMatch works correctly
// when dimension values are URIs (which get URL-encoded by serializeDimensions).
func TestDimensionMatch_WithURIValues(t *testing.T) {
	tests := []struct {
		name       string
		input      map[string]string
		policyDims string
		expected   bool
	}{
		{
			name:       "serialized URI matches policy with same URI",
			input:      map[string]string{"kas_uri": "https://kas.example.com"},
			policyDims: "kas_uri=https://kas.example.com",
			expected:   true,
		},
		{
			name:       "serialized URI with query string matches escaped policy URI",
			input:      map[string]string{"kas_uri": "https://kas.example.com?foo=bar&baz=qux"},
			policyDims: "kas_uri=" + escapeDimensionValue("https://kas.example.com?foo=bar&baz=qux"),
			expected:   true,
		},
		{
			name:       "serialized URI with literal plus matches escaped policy URI",
			input:      map[string]string{"kas_uri": "https://kas.example.com/path+plus?token=a+b"},
			policyDims: "kas_uri=" + escapeDimensionValue("https://kas.example.com/path+plus?token=a+b"),
			expected:   true,
		},
		{
			name:       "URI value with query string does not match policy for base URI only",
			input:      map[string]string{"kas_uri": "https://kas.example.com?foo=bar"},
			policyDims: "kas_uri=https://kas.example.com",
			// The query string makes the URIs different; policy requires exact match.
			expected: false,
		},
		{
			name:       "escaped literal star policy value does not act as wildcard",
			input:      map[string]string{"kas_uri": "https://kas.example.com"},
			policyDims: "kas_uri=" + escapeDimensionValue("*"),
			expected:   false,
		},
		{
			name:       "serialized literal star matches escaped policy value",
			input:      map[string]string{"label": "*"},
			policyDims: "label=" + escapeDimensionValue("*"),
			expected:   true,
		},
		{
			name:       "serialized literal star matches raw wildcard policy value",
			input:      map[string]string{"label": "*"},
			policyDims: "label=*",
			expected:   true,
		},
		{
			name:       "injected extra dimension does not satisfy a different policy key",
			input:      map[string]string{"kas_uri": "https://kas.example.com?foo=bar&second_dim=injected"},
			policyDims: "second_dim=injected",
			// The injected 'second_dim' must NOT appear as a separate dimension.
			expected: false,
		},
		{
			name:       "wildcard policy matches URI dimension",
			input:      map[string]string{"kas_uri": "https://kas.example.com"},
			policyDims: "*",
			expected:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Serialize the input dimensions as the authorizer would
			res := authz.ResolverResource(tc.input)
			ctx := &authz.ResolverContext{
				Resources: []*authz.ResolverResource{&res},
			}
			serialized, err := serializeDimensions(ctx)
			require.NoError(t, err)
			require.Len(t, serialized, 1)

			result := dimensionMatch(serialized[0], tc.policyDims)
			assert.Equal(t, tc.expected, result, "dimensionMatch(%q, %q)", serialized[0], tc.policyDims)
		})
	}
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_KasURIDimensionAllowed() {
	const kasURI = "https://kas-a.example.com?q=1&foo=bar"
	escapedURI := escapeDimensionValue(kasURI)
	csvPolicy := "p, role:kas-reader, /policy.kasregistry.KeyAccessServerRegistryService/GetKey, kas_uri=" + escapedURI + ", allow"

	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
			Csv:         csvPolicy,
		},
		Logger: s.logger,
	}
	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"kas-reader"},
		},
	})

	kasURIResource := authz.ResolverResource(map[string]string{"kas_uri": kasURI})
	req := &authz.Request{
		Token:  token,
		RPC:    "/policy.kasregistry.KeyAccessServerRegistryService/GetKey",
		Action: "read",
		ResourceContext: &authz.ResolverContext{
			Resources: []*authz.ResolverResource{&kasURIResource},
		},
	}

	decision, err := authorizer.Authorize(s.T().Context(), req)
	s.Require().NoError(err)
	s.True(decision.Allowed, "kas-reader with matching kas_uri (containing & and =) should be allowed")
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_KasURIDimensionDeniedOnMismatch() {
	const kasURI = "https://kas-a.example.com?q=1&foo=bar"
	escapedURI := escapeDimensionValue(kasURI)
	csvPolicy := "p, role:kas-reader, /policy.kasregistry.KeyAccessServerRegistryService/GetKey, kas_uri=" + escapedURI + ", allow"

	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
			Csv:         csvPolicy,
		},
		Logger: s.logger,
	}
	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"kas-reader"},
		},
	})

	// Different URI — should be denied
	differentURI := authz.ResolverResource(map[string]string{"kas_uri": "https://kas-b.example.com"})
	req := &authz.Request{
		Token:  token,
		RPC:    "/policy.kasregistry.KeyAccessServerRegistryService/GetKey",
		Action: "read",
		ResourceContext: &authz.ResolverContext{
			Resources: []*authz.ResolverResource{&differentURI},
		},
	}

	decision, err := authorizer.Authorize(s.T().Context(), req)
	s.Require().NoError(err)
	s.False(decision.Allowed, "kas-reader with different kas_uri should be denied")
}

func TestDimensionMatchFunc(t *testing.T) {
	t.Run("too few args returns error", func(t *testing.T) {
		result, err := dimensionMatchFunc("only-one")
		require.Error(t, err)
		boolResult, ok := result.(bool)
		require.True(t, ok, "result must be bool")
		require.False(t, boolResult)
	})

	t.Run("first arg is int returns error", func(t *testing.T) {
		result, err := dimensionMatchFunc(42, "namespace=hr")
		require.Error(t, err)
		boolResult, ok := result.(bool)
		require.True(t, ok, "result must be bool")
		require.False(t, boolResult)
	})

	t.Run("second arg is int returns error", func(t *testing.T) {
		result, err := dimensionMatchFunc("namespace=hr", 42)
		require.Error(t, err)
		boolResult, ok := result.(bool)
		require.True(t, ok, "result must be bool")
		require.False(t, boolResult)
	})

	t.Run("two valid strings returns correct bool", func(t *testing.T) {
		result, err := dimensionMatchFunc("namespace=hr", "namespace=hr")
		require.NoError(t, err)
		boolResult, ok := result.(bool)
		require.True(t, ok, "result must be bool")
		require.True(t, boolResult)
	})

	t.Run("two valid strings no match returns false", func(t *testing.T) {
		result, err := dimensionMatchFunc("namespace=finance", "namespace=hr")
		require.NoError(t, err)
		boolResult, ok := result.(bool)
		require.True(t, ok, "result must be bool")
		require.False(t, boolResult)
	})
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_DefaultPolicyCoverage() {
	// Use the built-in default policy (no custom Csv)
	cfg := authz.Config{
		PolicyConfig: authz.PolicyConfig{
			Version:     "v2",
			GroupsClaim: "realm_access.roles",
		},
		Logger: s.logger,
	}
	authorizer, err := s.newAuthorizer(cfg)
	s.Require().NoError(err)

	standardToken := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{"roles": []interface{}{"opentdf-standard"}},
	})
	unknownToken := createTestToken(s.T(), map[string]interface{}{})
	adminToken := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{"roles": []interface{}{"opentdf-admin"}},
	})

	readRPCs := []string{
		"/policy.actions.ActionService/GetAction",
		"/policy.actions.ActionService/ListActions",
		"/policy.attributes.AttributesService/GetAttribute",
		"/policy.attributes.AttributesService/ListAttributes",
		"/policy.kasregistry.KeyAccessServerRegistryService/GetKey",
		"/policy.kasregistry.KeyAccessServerRegistryService/ListKeys",
		"/policy.keymanagement.KeyManagementService/GetProviderConfig",
		"/policy.keymanagement.KeyManagementService/ListProviderConfigs",
		"/policy.namespaces.NamespaceService/GetNamespace",
		"/policy.namespaces.NamespaceService/ListNamespaces",
		"/policy.obligations.Service/GetObligation",
		"/policy.obligations.Service/ListObligations",
		"/policy.registeredresources.RegisteredResourcesService/GetRegisteredResource",
		"/policy.registeredresources.RegisteredResourcesService/ListRegisteredResources",
		"/policy.resourcemapping.ResourceMappingService/GetResourceMapping",
		"/policy.resourcemapping.ResourceMappingService/ListResourceMappings",
		"/policy.subjectmapping.SubjectMappingService/GetSubjectConditionSet",
		"/policy.subjectmapping.SubjectMappingService/ListSubjectConditionSets",
	}

	mutatingRPCs := []string{
		"/policy.actions.ActionService/CreateAction",
		"/policy.kasregistry.KeyAccessServerRegistryService/CreateKey",
		"/policy.kasregistry.KeyAccessServerRegistryService/RotateKey",
		"/policy.keymanagement.KeyManagementService/DeleteProviderConfig",
		"/policy.obligations.Service/UpdateObligation",
		"/policy.registeredresources.RegisteredResourcesService/DeleteRegisteredResource",
		"/policy.subjectmapping.SubjectMappingService/DeleteAllUnmappedSubjectConditionSets",
	}

	type testCase struct {
		name    string
		token   jwt.Token
		rpc     string
		action  string
		allowed bool
	}

	tests := []testCase{
		{
			name:    "standard can hit rewrap",
			token:   standardToken,
			rpc:     "/kas.AccessService/Rewrap",
			action:  "read",
			allowed: true,
		},
	}

	for _, rpc := range readRPCs {
		tests = append(
			tests,
			testCase{
				name:    "admin can read " + rpc,
				token:   adminToken,
				rpc:     rpc,
				action:  "read",
				allowed: true,
			},
			testCase{
				name:    "standard can read " + rpc,
				token:   standardToken,
				rpc:     rpc,
				action:  "read",
				allowed: true,
			},
			testCase{
				name:    "unknown cannot read " + rpc,
				token:   unknownToken,
				rpc:     rpc,
				action:  "read",
				allowed: false,
			},
		)
	}

	for _, rpc := range mutatingRPCs {
		tests = append(
			tests,
			testCase{
				name:    "admin can mutate " + rpc,
				token:   adminToken,
				rpc:     rpc,
				action:  "write",
				allowed: true,
			},
			testCase{
				name:    "standard cannot mutate " + rpc,
				token:   standardToken,
				rpc:     rpc,
				action:  "write",
				allowed: false,
			},
			testCase{
				name:    "unknown cannot mutate " + rpc,
				token:   unknownToken,
				rpc:     rpc,
				action:  "write",
				allowed: false,
			},
		)
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			decision, err := authorizer.Authorize(s.T().Context(), &authz.Request{
				Token:  tc.token,
				RPC:    tc.rpc,
				Action: tc.action,
			})
			s.Require().NoError(err)
			s.Require().NotNil(decision)
			s.Equal(tc.allowed, decision.Allowed)
		})
	}

	// Unknown can hit rewrap
	req := &authz.Request{
		Token:  unknownToken,
		RPC:    "/kas.AccessService/Rewrap",
		Action: "read",
	}
	decision, err := authorizer.Authorize(s.T().Context(), req)
	s.Require().NoError(err)
	s.Require().NotNil(decision)
	s.True(decision.Allowed)
}

func (s *CasbinAuthorizerSuite) newAuthorizer(cfg authz.Config) (authz.Authorizer, error) {
	adapterCfg := authz.AdapterConfigFromExternal(cfg)
	v2Cfg, ok := adapterCfg.(authz.CasbinV2Config)
	if !ok {
		return nil, fmt.Errorf("expected v2 config, got %T", adapterCfg)
	}
	return NewAuthorizer(v2Cfg, s.logger)
}

// Test NewAuthorizer factory function via authz.New
func createTestToken(t *testing.T, claims map[string]interface{}) jwt.Token {
	t.Helper()

	token := jwt.New()
	for k, v := range claims {
		if err := token.Set(k, v); err != nil {
			t.Fatalf("failed to set claim %s: %v", k, err)
		}
	}
	return token
}
