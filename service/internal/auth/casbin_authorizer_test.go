package auth

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

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
	cfg := AuthorizerConfig{
		Version: "v1",
		PolicyConfig: PolicyConfig{
			GroupsClaim: []string{"realm_access.roles"},
		},
		Logger: s.logger,
	}

	authorizer, err := NewCasbinAuthorizer(cfg)
	s.Require().NoError(err)
	s.Require().NotNil(authorizer)

	s.Equal("v1", authorizer.Version())
	s.False(authorizer.SupportsResourceAuthorization())
}

func (s *CasbinAuthorizerSuite) TestNewCasbinAuthorizer_V2() {
	cfg := AuthorizerConfig{
		Version: "v2",
		PolicyConfig: PolicyConfig{
			GroupsClaim: []string{"realm_access.roles"},
		},
		Logger: s.logger,
	}

	authorizer, err := NewCasbinAuthorizer(cfg)
	s.Require().NoError(err)
	s.Require().NotNil(authorizer)

	s.Equal("v2", authorizer.Version())
	s.True(authorizer.SupportsResourceAuthorization())
}

func (s *CasbinAuthorizerSuite) TestNewCasbinAuthorizer_InvalidVersion() {
	cfg := AuthorizerConfig{
		Version: "v99",
		PolicyConfig: PolicyConfig{
			GroupsClaim: []string{"realm_access.roles"},
		},
		Logger: s.logger,
	}

	authorizer, err := NewCasbinAuthorizer(cfg)
	s.Require().Error(err)
	s.Nil(authorizer)
	s.Contains(err.Error(), "unsupported authorization version")
}

func (s *CasbinAuthorizerSuite) TestNewCasbinAuthorizer_NilLogger() {
	cfg := AuthorizerConfig{
		Version: "v1",
		PolicyConfig: PolicyConfig{
			GroupsClaim: []string{"realm_access.roles"},
		},
		Logger: nil,
	}

	authorizer, err := NewCasbinAuthorizer(cfg)
	s.Require().Error(err)
	s.Nil(authorizer)
	s.Contains(err.Error(), "logger is required")
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_AdminWildcard() {
	// Policy: admin can do anything
	cfg := AuthorizerConfig{
		Version: "v2",
		PolicyConfig: PolicyConfig{
			GroupsClaim: []string{"realm_access.roles"},
			Csv:         "p, role:admin, *, *, allow",
		},
		Logger: s.logger,
	}

	authorizer, err := NewCasbinAuthorizer(cfg)
	s.Require().NoError(err)

	// Create token with admin role
	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"admin"},
		},
	})

	req := &AuthorizationRequest{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: "write",
		ResourceContext: &AuthzResolverContext{
			Resources: []*AuthzResolverResource{
				{"namespace": "hr", "attribute": "classification"},
			},
		},
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	s.Require().NoError(err)
	s.True(decision.Allowed)
	s.Equal(AuthzModeV2, decision.Mode)
}

func (s *CasbinAuthorizerSuite) TestAuthorizeV2_NamespaceScopedAccess() {
	// Policy: hr-admin can only access HR namespace
	cfg := AuthorizerConfig{
		Version: "v2",
		PolicyConfig: PolicyConfig{
			GroupsClaim: []string{"realm_access.roles"},
			Csv: `p, role:hr-admin, /policy.attributes.AttributesService/*, namespace=hr, allow
p, role:finance-admin, /policy.attributes.AttributesService/*, namespace=finance, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := NewCasbinAuthorizer(cfg)
	s.Require().NoError(err)

	// Create token with hr-admin role
	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"hr-admin"},
		},
	})

	// Should allow access to HR namespace
	hrReq := &AuthorizationRequest{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: "write",
		ResourceContext: &AuthzResolverContext{
			Resources: []*AuthzResolverResource{
				{"namespace": "hr"},
			},
		},
	}

	decision, err := authorizer.Authorize(context.Background(), hrReq)
	s.Require().NoError(err)
	s.True(decision.Allowed, "hr-admin should be allowed to access HR namespace")

	// Should deny access to Finance namespace
	financeReq := &AuthorizationRequest{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: "write",
		ResourceContext: &AuthzResolverContext{
			Resources: []*AuthzResolverResource{
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
	cfg := AuthorizerConfig{
		Version: "v2",
		PolicyConfig: PolicyConfig{
			GroupsClaim: []string{"realm_access.roles"},
			Csv:         `p, role:classification-owner, /policy.attributes.AttributesService/Update*, namespace=hr&attribute=classification, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := NewCasbinAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"classification-owner"},
		},
	})

	// Should allow with both dimensions matching
	req := &AuthorizationRequest{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: "write",
		ResourceContext: &AuthzResolverContext{
			Resources: []*AuthzResolverResource{
				{"namespace": "hr", "attribute": "classification"},
			},
		},
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	s.Require().NoError(err)
	s.True(decision.Allowed, "should be allowed with matching namespace and attribute")

	// Should deny with wrong attribute
	wrongAttrReq := &AuthorizationRequest{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: "write",
		ResourceContext: &AuthzResolverContext{
			Resources: []*AuthzResolverResource{
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
	cfg := AuthorizerConfig{
		Version: "v2",
		PolicyConfig: PolicyConfig{
			GroupsClaim: []string{"realm_access.roles"},
			Csv:         `p, role:hr-viewer, /policy.attributes.AttributesService/Get*, namespace=hr&attribute=*, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := NewCasbinAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"hr-viewer"},
		},
	})

	// Should allow any attribute in HR namespace
	req := &AuthorizationRequest{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/GetAttribute",
		Action: "read",
		ResourceContext: &AuthzResolverContext{
			Resources: []*AuthzResolverResource{
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
	cfg := AuthorizerConfig{
		Version: "v2",
		PolicyConfig: PolicyConfig{
			GroupsClaim: []string{"realm_access.roles"},
			Csv:         `p, role:standard, /policy.attributes.AttributesService/Get*, *, allow`,
		},
		Logger: s.logger,
	}

	authorizer, err := NewCasbinAuthorizer(cfg)
	s.Require().NoError(err)

	token := createTestToken(s.T(), map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"standard"},
		},
	})

	// Should allow with no resource context (nil)
	req := &AuthorizationRequest{
		Token:           token,
		RPC:             "/policy.attributes.AttributesService/GetAttribute",
		Action:          "read",
		ResourceContext: nil,
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	s.Require().NoError(err)
	s.True(decision.Allowed, "should be allowed with nil resource context when policy has wildcard")
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
		name     string
		ctx      *AuthzResolverContext
		expected string
	}{
		{
			name:     "nil context",
			ctx:      nil,
			expected: "*",
		},
		{
			name:     "empty context",
			ctx:      &AuthzResolverContext{},
			expected: "*",
		},
		{
			name: "single dimension",
			ctx: &AuthzResolverContext{
				Resources: []*AuthzResolverResource{
					{"namespace": "hr"},
				},
			},
			expected: "namespace=hr",
		},
		{
			name: "multiple dimensions sorted alphabetically",
			ctx: &AuthzResolverContext{
				Resources: []*AuthzResolverResource{
					{"namespace": "hr", "attribute": "classification"},
				},
			},
			expected: "attribute=classification&namespace=hr",
		},
		{
			name: "multiple resources merged",
			ctx: &AuthzResolverContext{
				Resources: []*AuthzResolverResource{
					{"namespace": "hr"},
					{"attribute": "classification"},
				},
			},
			expected: "attribute=classification&namespace=hr",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := serializeDimensions(tc.ctx)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test NewAuthorizer factory function
func TestNewAuthorizer(t *testing.T) {
	log := logger.CreateTestLogger()

	tests := []struct {
		name          string
		version       string
		expectVersion string
		expectError   bool
	}{
		{
			name:          "empty version defaults to v1",
			version:       "",
			expectVersion: "v1",
			expectError:   false,
		},
		{
			name:          "explicit v1",
			version:       "v1",
			expectVersion: "v1",
			expectError:   false,
		},
		{
			name:          "explicit v2",
			version:       "v2",
			expectVersion: "v2",
			expectError:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := AuthorizerConfig{
				Version: tc.version,
				PolicyConfig: PolicyConfig{
					GroupsClaim: []string{"realm_access.roles"},
				},
				Logger: log,
			}

			authorizer, err := NewAuthorizer(cfg)
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
