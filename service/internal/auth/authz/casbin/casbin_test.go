package casbin

import (
	"context"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/logger"
	platformauthz "github.com/opentdf/platform/service/pkg/authz"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// mockV1Enforcer implements authz.V1Enforcer for testing
type mockV1Enforcer struct {
	enforceFunc func(ctx context.Context, token jwt.Token, req platformauthz.RoleRequest) (bool, map[string]any, error)
}

func (m *mockV1Enforcer) Enforce(ctx context.Context, token jwt.Token, req platformauthz.RoleRequest) (bool, map[string]any, error) {
	if m.enforceFunc != nil {
		return m.enforceFunc(ctx, token, req)
	}
	return false, nil, nil
}

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

func (s *CasbinAuthorizerSuite) TestNewCasbinAuthorizer_V1() {
	mockEnforcer := &mockV1Enforcer{}

	cfg := authz.Config{
		Version: "v1",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
		},
		Logger:  s.logger,
		Options: []authz.Option{authz.WithV1Enforcer(mockEnforcer)},
	}

	authorizer, err := NewAuthorizer(cfg)
	s.Require().NoError(err)
	s.Require().NotNil(authorizer)

	s.Equal("v1", authorizer.Version())
	s.False(authorizer.SupportsResourceAuthorization())
}

func (s *CasbinAuthorizerSuite) TestNewCasbinAuthorizer_V2() {
	cfg := authz.Config{
		Version: "v2",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
		},
		Logger: s.logger,
	}

	authorizer, err := NewAuthorizer(cfg)
	s.Require().NoError(err)
	s.Require().NotNil(authorizer)

	s.Equal("v2", authorizer.Version())
	s.True(authorizer.SupportsResourceAuthorization())
}

func (s *CasbinAuthorizerSuite) TestAuthorizeRequiresRequestAndToken() {
	cfg := authz.Config{
		Version: "v2",
		PolicyConfig: authz.PolicyConfig{
			Csv: "p, role:admin, *, *, allow",
		},
		Logger: s.logger,
	}

	authorizer, err := NewAuthorizer(cfg)
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

func (s *CasbinAuthorizerSuite) TestNewCasbinAuthorizer_UnknownVersionFallsBackToV1() {
	// Unknown versions default to v1, which requires a v1 enforcer.
	// This maintains backwards compatibility while providing a clear error.
	cfg := authz.Config{
		Version: "v99",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
		},
		Logger: s.logger,
	}

	authorizer, err := NewAuthorizer(cfg)
	s.Require().Error(err)
	s.Nil(authorizer)
	s.Contains(err.Error(), "v1 enforcer is required")
}

func (s *CasbinAuthorizerSuite) TestNewCasbinAuthorizer_NilLogger() {
	cfg := authz.Config{
		Version: "v1",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
		},
		Logger: nil,
	}

	authorizer, err := NewAuthorizer(cfg)
	s.Require().Error(err)
	s.Nil(authorizer)
	s.Contains(err.Error(), "logger is required")
}

func (s *CasbinAuthorizerSuite) TestNewCasbinAuthorizer_V1_NoEnforcerError() {
	cfg := authz.Config{
		Version: "v1",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
		},
		Logger: s.logger,
		// No V1Enforcer option provided
	}

	authorizer, err := NewAuthorizer(cfg)
	s.Require().Error(err)
	s.Nil(authorizer)
	s.Contains(err.Error(), "v1 enforcer is required")
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_AdminWildcard() {
	// Policy: admin can do anything
	cfg := authz.Config{
		Version: "v2",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
			Csv:         "p, role:admin, *, *, allow",
		},
		Logger: s.logger,
	}

	authorizer, err := NewAuthorizer(cfg)
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
		Version: "v2",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
		},
		Logger: s.logger,
	}

	authorizer, err := NewAuthorizer(cfg)
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
		Version: "v2",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
			Csv: `p, role:hr-admin, /policy.attributes.AttributesService/*, namespace=hr, allow
p, role:finance-admin, /policy.attributes.AttributesService/*, namespace=finance, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := NewAuthorizer(cfg)
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
		Version: "v2",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
			Csv:         `p, role:classification-owner, /policy.attributes.AttributesService/Update*, namespace=hr&attribute=classification, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := NewAuthorizer(cfg)
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

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_WildcardDimension() {
	// Policy: wildcard for attribute dimension
	cfg := authz.Config{
		Version: "v2",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
			Csv:         `p, role:hr-viewer, /policy.attributes.AttributesService/Get*, namespace=hr&attribute=*, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := NewAuthorizer(cfg)
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
		Version: "v2",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
			Csv:         `p, role:standard, /policy.attributes.AttributesService/Get*, *, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := NewAuthorizer(cfg)
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
		Version: "v2",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
			Csv:         `p, role:standard, /policy.attributes.AttributesService/Get*, namespace=finance, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := NewAuthorizer(cfg)
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
		Version: "v2",
		PolicyConfig: authz.PolicyConfig{
			UserNameClaim: "preferred_username",
			Csv:           `p, role:admin, /policy.attributes.AttributesService/Get*, *, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := NewAuthorizer(cfg)
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
		Version: "v2",
		PolicyConfig: authz.PolicyConfig{
			ClientIDClaim: "client_id",
			Csv:           `p, client:test-client, /policy.attributes.AttributesService/Get*, *, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := NewAuthorizer(cfg)
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
		Version: "v2",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim:   "realm_access.roles",
			UserNameClaim: "preferred_username",
			ClientIDClaim: "azp",
			Csv: `p, client:test-client, /policy.attributes.AttributesService/Get*, *, allow
p, role:admin, /policy.attributes.AttributesService/Get*, *, allow
p, alice, /policy.attributes.AttributesService/Get*, *, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := NewAuthorizer(cfg)
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

	subjects, roles, err := casbinAuthorizer.subjectExtractor.BuildSubjectFromToken(
		s.T().Context(),
		token,
		platformauthz.RoleRequest{},
		true,
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
		Version: "v2",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
			Csv:         "p, role:external-admin, /policy.attributes.AttributesService/Get*, *, allow",
		},
		Logger:  s.logger,
		Options: []authz.Option{authz.WithRoleProvider(staticRoleProvider{roles: []string{"external-admin"}})},
	}

	authorizer, err := NewAuthorizer(cfg)
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
		Version: "v2",
		PolicyConfig: authz.PolicyConfig{
			Issuer: "https://issuer.example",
			Csv:    "p, role:external-admin, /policy.attributes.AttributesService/Get*, *, allow",
		},
		Logger:  s.logger,
		Options: []authz.Option{authz.WithRoleProvider(roleProvider)},
	}

	authorizer, err := NewAuthorizer(cfg)
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
		Version: "v2",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
			Csv:         "p, role:external-admin, /policy.attributes.AttributesService/Get*, *, allow",
		},
		Logger:  s.logger,
		Options: []authz.Option{authz.WithRoleProvider(staticRoleProvider{err: roleProviderErr})},
	}

	authorizer, err := NewAuthorizer(cfg)
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
		Version: "v2",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
			Csv: `p, role:standard, /kas.AccessService/*, *, allow
p, role:standard, /kas/v2/rewrap, *, allow
p, role:unknown, /kas.AccessService/Rewrap, *, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := NewAuthorizer(cfg)
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
			name:       "exact match multiple dimensions",
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
		expected  string
		expectErr bool
	}{
		{
			name:     "nil context",
			ctx:      nil,
			expected: "*",
		},
		{
			name:     "empty context",
			ctx:      &authz.ResolverContext{},
			expected: "*",
		},
		{
			name: "single dimension",
			ctx: &authz.ResolverContext{
				Resources: []*authz.ResolverResource{
					{"namespace": "hr"},
				},
			},
			expected: "namespace=hr",
		},
		{
			name: "multiple dimensions sorted alphabetically",
			ctx: &authz.ResolverContext{
				Resources: []*authz.ResolverResource{
					{"namespace": "hr", "attribute": "classification"},
				},
			},
			expected: "attribute=classification&namespace=hr",
		},
		{
			name: "multiple resources merged",
			ctx: &authz.ResolverContext{
				Resources: []*authz.ResolverResource{
					{"namespace": "hr"},
					{"attribute": "classification"},
				},
			},
			expected: "attribute=classification&namespace=hr",
		},
		{
			name: "conflicting duplicate dimension key fails",
			ctx: &authz.ResolverContext{
				Resources: []*authz.ResolverResource{
					{"namespace": "hr"},
					{"namespace": "finance"},
				},
			},
			expectErr: true,
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
			assert.Equal(t, tc.expected, result)
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

			parsed, ok := parseDimensions(serialized)
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

			result := dimensionMatch(serialized, tc.policyDims)
			assert.Equal(t, tc.expected, result, "dimensionMatch(%q, %q)", serialized, tc.policyDims)
		})
	}
}

// Test NewAuthorizer factory function via authz.New
func TestNewAuthorizer(t *testing.T) {
	log := logger.CreateTestLogger()
	mockEnforcer := &mockV1Enforcer{}

	tests := []struct {
		name          string
		version       string
		expectVersion string
		expectError   bool
		withEnforcer  bool
	}{
		{
			name:          "empty version defaults to v1",
			version:       "",
			expectVersion: "v1",
			expectError:   false,
			withEnforcer:  true,
		},
		{
			name:          "explicit v1",
			version:       "v1",
			expectVersion: "v1",
			expectError:   false,
			withEnforcer:  true,
		},
		{
			name:          "explicit v2",
			version:       "v2",
			expectVersion: "v2",
			expectError:   false,
			withEnforcer:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := authz.Config{
				Version: tc.version,
				PolicyConfig: authz.PolicyConfig{
					GroupsClaim: "realm_access.roles",
				},
				Logger: log,
			}
			if tc.withEnforcer {
				cfg.Options = []authz.Option{authz.WithV1Enforcer(mockEnforcer)}
			}

			authorizer, err := authz.New(cfg)
			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, authorizer)
			assert.Equal(t, tc.expectVersion, authorizer.Version())
		})
	}
}

// =============================================================================
// V1 Path Handling Tests - Ensuring backwards compatibility
// =============================================================================
// The v1 policy file uses two different path formats:
// - gRPC paths WITHOUT leading slash: kas.AccessService/Rewrap
// - HTTP paths WITH leading slash: /kas/v2/rewrap
//
// The authorizeV1 function must handle paths from ConnectRPC (which always
// have leading slashes) and translate them correctly for v1 policy matching.
// =============================================================================

func (s *CasbinAuthorizerSuite) TestAuthorizeV1_GRPCPathStripsLeadingSlash() {
	// v1 policy: gRPC paths have NO leading slash
	// Create a mock enforcer that validates the resource path
	var receivedResource string
	var receivedIssuer string
	mockEnforcer := &mockV1Enforcer{
		enforceFunc: func(_ context.Context, _ jwt.Token, req platformauthz.RoleRequest) (bool, map[string]any, error) {
			receivedResource = req.Resource
			receivedIssuer = req.Issuer
			// Allow if resource matches expected stripped path
			return req.Resource == "kas.AccessService/Rewrap", nil, nil
		},
	}

	cfg := authz.Config{
		Version: "v1",
		PolicyConfig: authz.PolicyConfig{
			Issuer:      "https://issuer.example",
			GroupsClaim: "realm_access.roles",
		},
		Logger:  s.logger,
		Options: []authz.Option{authz.WithV1Enforcer(mockEnforcer)},
	}

	authorizer, err := NewAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"standard"},
		},
	})

	// ConnectRPC passes paths WITH leading slash, even for gRPC
	// The authorizer must strip it to match v1 policy
	req := &authz.Request{
		Token:  token,
		RPC:    "/kas.AccessService/Rewrap", // ConnectRPC format
		Action: "read",
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	s.Require().NoError(err)
	s.True(decision.Allowed, "gRPC path should be allowed after stripping leading slash")
	s.Equal(authz.ModeV1, decision.Mode)
	s.Equal("kas.AccessService/Rewrap", receivedResource, "resource should have leading slash stripped")
	s.Equal("https://issuer.example", receivedIssuer)
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV1_HTTPPathKeepsLeadingSlash() {
	// v1 policy: HTTP paths KEEP their leading slash
	var receivedResource string
	mockEnforcer := &mockV1Enforcer{
		enforceFunc: func(_ context.Context, _ jwt.Token, req platformauthz.RoleRequest) (bool, map[string]any, error) {
			receivedResource = req.Resource
			// Allow if resource matches expected path with leading slash
			return req.Resource == "/kas/v2/rewrap", nil, nil
		},
	}

	cfg := authz.Config{
		Version: "v1",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
		},
		Logger:  s.logger,
		Options: []authz.Option{authz.WithV1Enforcer(mockEnforcer)},
	}

	authorizer, err := NewAuthorizer(cfg)
	s.Require().NoError(err)

	testToken := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"standard"},
		},
	})

	// HTTP paths should keep their leading slash for v1 policy matching
	req := &authz.Request{
		Token:  testToken,
		RPC:    "/kas/v2/rewrap",
		Action: "write",
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	s.Require().NoError(err)
	s.True(decision.Allowed, "HTTP path should be allowed with leading slash intact")
	s.Equal(authz.ModeV1, decision.Mode)
	s.Equal("/kas/v2/rewrap", receivedResource, "HTTP path should keep leading slash")
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV1_PolicyServiceGRPCPath() {
	// Test policy.* wildcard matching with gRPC path
	var receivedResource string
	mockEnforcer := &mockV1Enforcer{
		enforceFunc: func(_ context.Context, _ jwt.Token, req platformauthz.RoleRequest) (bool, map[string]any, error) {
			receivedResource = req.Resource
			// Allow if resource starts with policy. (gRPC style, no leading slash)
			return len(req.Resource) > 7 && req.Resource[:7] == "policy.", nil, nil
		},
	}

	cfg := authz.Config{
		Version: "v1",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
		},
		Logger:  s.logger,
		Options: []authz.Option{authz.WithV1Enforcer(mockEnforcer)},
	}

	authorizer, err := NewAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"standard"},
		},
	})

	// gRPC path from ConnectRPC
	req := &authz.Request{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/GetAttribute",
		Action: "read",
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	s.Require().NoError(err)
	s.True(decision.Allowed, "policy.* wildcard should match gRPC path after stripping leading slash")
	s.Equal(authz.ModeV1, decision.Mode)
	s.Equal("policy.attributes.AttributesService/GetAttribute", receivedResource)
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV1_PathHandlingHeuristic() {
	// Test the specific heuristic: paths with "." are gRPC, others are HTTP
	var receivedResources []string
	mockEnforcer := &mockV1Enforcer{
		enforceFunc: func(_ context.Context, _ jwt.Token, req platformauthz.RoleRequest) (bool, map[string]any, error) {
			receivedResources = append(receivedResources, req.Resource)
			return true, nil, nil
		},
	}

	cfg := authz.Config{
		Version: "v1",
		PolicyConfig: authz.PolicyConfig{
			GroupsClaim: "realm_access.roles",
		},
		Logger:  s.logger,
		Options: []authz.Option{authz.WithV1Enforcer(mockEnforcer)},
	}

	authorizer, err := NewAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"test"},
		},
	})

	// gRPC path (contains ".") - leading slash should be stripped
	grpcReq := &authz.Request{
		Token:  token,
		RPC:    "/some.Service/Method",
		Action: "read",
	}

	decision, err := authorizer.Authorize(context.Background(), grpcReq)
	s.Require().NoError(err)
	s.True(decision.Allowed, "gRPC path should be allowed")
	s.Equal("some.Service/Method", receivedResources[0], "gRPC path should have leading slash stripped")

	// HTTP path (no ".") - leading slash should be kept
	httpReq := &authz.Request{
		Token:  token,
		RPC:    "/http/path",
		Action: "read",
	}

	decision, err = authorizer.Authorize(context.Background(), httpReq)
	s.Require().NoError(err)
	s.True(decision.Allowed, "HTTP path should be allowed")
	s.Equal("/http/path", receivedResources[1], "HTTP path should keep leading slash")
}

// Helper function to create test JWT tokens
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
