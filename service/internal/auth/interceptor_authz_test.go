package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/creasty/defaults"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/internal/auth/authz"
	_ "github.com/opentdf/platform/service/internal/auth/authz/casbin" // Register casbin authorizer
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/suite"
)

// InterceptorAuthzSuite tests the authorization flow through the interceptor
// with both Casbin v1 and v2 modes.
// These tests verify the core authorization decisions that the gRPC/HTTP
// interceptors rely on for permit/deny decisions.
type InterceptorAuthzSuite struct {
	suite.Suite
	logger *logger.Logger
}

func TestInterceptorAuthzSuite(t *testing.T) {
	suite.Run(t, new(InterceptorAuthzSuite))
}

func (s *InterceptorAuthzSuite) SetupTest() {
	s.logger = logger.CreateTestLogger()
}

// =============================================================================
// V1 Mode Tests - Path-based authorization (used by ConnectUnaryServerInterceptor)
// =============================================================================

func (s *InterceptorAuthzSuite) TestV1_AdminCanAccessAll() {
	policyCfg := PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	authorizer := s.createV1Authorizer(policyCfg)
	token := s.newTokenWithRoles("opentdf-admin")

	tests := []struct {
		name     string
		rpc      string
		action   string
		expected bool
	}{
		{"admin read policy", "/policy.attributes.AttributesService/GetAttribute", ActionRead, true},
		{"admin write policy", "/policy.attributes.AttributesService/CreateAttribute", ActionWrite, true},
		{"admin delete policy", "/policy.attributes.AttributesService/DeleteAttribute", ActionDelete, true},
		{"admin read kas", "/kas.AccessService/Rewrap", ActionRead, true},
		{"admin non-existent", "/non.existent.Service/Method", ActionRead, true},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			req := &authz.Request{
				Token:  token,
				RPC:    tc.rpc,
				Action: tc.action,
			}
			decision, err := authorizer.Authorize(context.Background(), req)

			s.Require().NoError(err)
			s.Require().NotNil(decision)
			s.Equal(tc.expected, decision.Allowed, "expected allowed=%v for %s", tc.expected, tc.name)
			s.Equal(authz.ModeV1, decision.Mode)
		})
	}
}

func (s *InterceptorAuthzSuite) TestV1_StandardUserPermissions() {
	policyCfg := PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	authorizer := s.createV1Authorizer(policyCfg)
	token := s.newTokenWithRoles("opentdf-standard")

	tests := []struct {
		name     string
		rpc      string
		action   string
		expected bool
	}{
		// Standard user can read policy resources
		{"standard read policy", "/policy.attributes.AttributesService/GetAttribute", ActionRead, true},
		{"standard list policy", "/policy.attributes.AttributesService/ListAttributes", ActionRead, true},
		// Standard user cannot write to policy resources
		{"standard write policy denied", "/policy.attributes.AttributesService/CreateAttribute", ActionWrite, false},
		{"standard delete policy denied", "/policy.attributes.AttributesService/DeleteAttribute", ActionDelete, false},
		// Standard user can access KAS rewrap (HTTP path)
		{"standard kas rewrap http", "/kas/v2/rewrap", ActionWrite, true},
		// Standard user cannot access non-existent resources
		{"standard non-existent denied", "/non.existent.Service/Method", ActionRead, false},
		// Standard user can access authorization service
		{"standard authz decisions", "/authorization.AuthorizationService/GetDecisions", ActionRead, true},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			req := &authz.Request{
				Token:  token,
				RPC:    tc.rpc,
				Action: tc.action,
			}
			decision, err := authorizer.Authorize(context.Background(), req)

			s.Require().NoError(err)
			s.Require().NotNil(decision)
			s.Equal(tc.expected, decision.Allowed, "expected allowed=%v for %s", tc.expected, tc.name)
			s.Equal(authz.ModeV1, decision.Mode)
		})
	}
}

func (s *InterceptorAuthzSuite) TestV1_UnknownRoleDenied() {
	policyCfg := PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	authorizer := s.createV1Authorizer(policyCfg)
	token := s.newTokenWithRoles("unknown-role")

	// Note: KAS rewrap is NOT in this list because the default v1 policy
	// explicitly allows unknown roles to access it (it's a public route for ERS).
	// The policy has: "p, role:unknown, kas.AccessService/Rewrap, *, allow"
	tests := []struct {
		name string
		rpc  string
	}{
		{"policy read", "/policy.attributes.AttributesService/GetAttribute"},
		{"policy write", "/policy.attributes.AttributesService/CreateAttribute"},
		{"non-existent", "/some.Service/Method"},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			req := &authz.Request{
				Token:  token,
				RPC:    tc.rpc,
				Action: ActionRead,
			}
			decision, err := authorizer.Authorize(context.Background(), req)

			s.Require().NoError(err)
			s.Require().NotNil(decision)
			s.False(decision.Allowed, "unknown role should be denied for %s", tc.rpc)
			s.Equal(authz.ModeV1, decision.Mode)
		})
	}
}

func (s *InterceptorAuthzSuite) TestV1_UnknownRolePublicRoutes() {
	policyCfg := PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	authorizer := s.createV1Authorizer(policyCfg)
	token := s.newTokenWithRoles("unknown-role")

	// The default v1 policy explicitly allows unknown roles to access certain
	// public routes, primarily for ERS (Entity Resolution Service) functionality.
	// This tests that behavior is maintained.
	tests := []struct {
		name string
		rpc  string
	}{
		{"kas rewrap gRPC", "/kas.AccessService/Rewrap"},
		{"kas rewrap HTTP", "/kas/v2/rewrap"},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			req := &authz.Request{
				Token:  token,
				RPC:    tc.rpc,
				Action: ActionRead,
			}
			decision, err := authorizer.Authorize(context.Background(), req)

			s.Require().NoError(err)
			s.Require().NotNil(decision)
			s.True(decision.Allowed, "unknown role should be ALLOWED for public route %s", tc.rpc)
			s.Equal(authz.ModeV1, decision.Mode)
		})
	}
}

func (s *InterceptorAuthzSuite) TestV1_CustomRoleMapping() {
	policyCfg := PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	// Map external roles to internal roles
	policyCfg.RoleMap = map[string]string{
		"admin":    "external-admin",
		"standard": "external-standard",
	}

	authorizer := s.createV1Authorizer(policyCfg)

	// Token with mapped admin role
	adminToken := s.newTokenWithRoles("external-admin")
	req := &authz.Request{
		Token:  adminToken,
		RPC:    "/policy.attributes.AttributesService/CreateAttribute",
		Action: ActionWrite,
	}
	decision, err := authorizer.Authorize(context.Background(), req)

	s.Require().NoError(err)
	s.True(decision.Allowed, "mapped admin role should be allowed")

	// Token with mapped standard role
	standardToken := s.newTokenWithRoles("external-standard")
	req = &authz.Request{
		Token:  standardToken,
		RPC:    "/policy.attributes.AttributesService/CreateAttribute",
		Action: ActionWrite,
	}
	decision, err = authorizer.Authorize(context.Background(), req)

	s.Require().NoError(err)
	s.False(decision.Allowed, "mapped standard role should be denied for write")
}

func (s *InterceptorAuthzSuite) TestV1_ExtendedPolicy() {
	policyCfg := PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	// Extend the default policy with a new rule
	policyCfg.Extension = strings.Join([]string{
		"p, role:custom-role, custom.service.*, read, allow",
		"g, custom-user, role:custom-role",
	}, "\n")

	authorizer := s.createV1Authorizer(policyCfg)
	token := s.newTokenWithRoles("custom-user")

	// Custom role can access custom service
	req := &authz.Request{
		Token:  token,
		RPC:    "/custom.service.CustomService/GetCustom",
		Action: ActionRead,
	}
	decision, err := authorizer.Authorize(context.Background(), req)

	s.Require().NoError(err)
	s.True(decision.Allowed, "custom role should be allowed for custom service")

	// Custom role cannot access other services
	req = &authz.Request{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/GetAttribute",
		Action: ActionRead,
	}
	decision, err = authorizer.Authorize(context.Background(), req)

	s.Require().NoError(err)
	s.False(decision.Allowed, "custom role should be denied for policy service")
}

// =============================================================================
// V2 Mode Tests - RPC + Dimensions authorization
// =============================================================================

func (s *InterceptorAuthzSuite) TestV2_AdminWildcardAccess() {
	csvPolicy := "p, role:admin, *, *, allow"
	authorizer := s.createV2Authorizer(csvPolicy)
	token := s.newTokenWithRoles("admin")

	tests := []struct {
		name string
		rpc  string
	}{
		{"policy service", "/policy.attributes.AttributesService/GetAttribute"},
		{"kas service", "/kas.AccessService/Rewrap"},
		{"any service", "/any.Service/AnyMethod"},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			req := &authz.Request{
				Token:  token,
				RPC:    tc.rpc,
				Action: ActionRead,
			}
			decision, err := authorizer.Authorize(context.Background(), req)

			s.Require().NoError(err)
			s.Require().NotNil(decision)
			s.True(decision.Allowed, "admin should have wildcard access to %s", tc.rpc)
			s.Equal(authz.ModeV2, decision.Mode)
		})
	}
}

func (s *InterceptorAuthzSuite) TestV2_ServiceScopedAccess() {
	csvPolicy := `p, role:policy-reader, /policy.*, *, allow
p, role:kas-user, /kas.*, *, allow`

	authorizer := s.createV2Authorizer(csvPolicy)

	// Policy reader token
	policyToken := s.newTokenWithRoles("policy-reader")
	policyReq := &authz.Request{
		Token:  policyToken,
		RPC:    "/policy.attributes.AttributesService/GetAttribute",
		Action: ActionRead,
	}
	decision, err := authorizer.Authorize(context.Background(), policyReq)

	s.Require().NoError(err)
	s.True(decision.Allowed, "policy-reader should access policy service")

	// Policy reader cannot access KAS
	kasReq := &authz.Request{
		Token:  policyToken,
		RPC:    "/kas.AccessService/Rewrap",
		Action: ActionRead,
	}
	decision, err = authorizer.Authorize(context.Background(), kasReq)

	s.Require().NoError(err)
	s.False(decision.Allowed, "policy-reader should not access kas service")

	// KAS user token
	kasToken := s.newTokenWithRoles("kas-user")
	kasReq = &authz.Request{
		Token:  kasToken,
		RPC:    "/kas.AccessService/Rewrap",
		Action: ActionRead,
	}
	decision, err = authorizer.Authorize(context.Background(), kasReq)

	s.Require().NoError(err)
	s.True(decision.Allowed, "kas-user should access kas service")
}

func (s *InterceptorAuthzSuite) TestV2_UnknownRoleDenied() {
	csvPolicy := `p, role:known-role, /some.Service/*, *, allow`
	authorizer := s.createV2Authorizer(csvPolicy)

	// Token with unknown role
	token := s.newTokenWithRoles("unknown-role")
	req := &authz.Request{
		Token:  token,
		RPC:    "/some.Service/Method",
		Action: ActionRead,
	}
	decision, err := authorizer.Authorize(context.Background(), req)

	s.Require().NoError(err)
	s.Require().NotNil(decision)
	s.False(decision.Allowed, "unknown role should be denied")
	s.Equal(authz.ModeV2, decision.Mode)
}

func (s *InterceptorAuthzSuite) TestV2_MultipleRoles() {
	// Policy where different roles have access to different services
	csvPolicy := `p, role:role-a, /service.A/*, *, allow
p, role:role-b, /service.B/*, *, allow`

	authorizer := s.createV2Authorizer(csvPolicy)

	// Token with multiple roles
	token := s.newTokenWithRoles("role-a", "role-b")

	// Should access service A
	reqA := &authz.Request{
		Token:  token,
		RPC:    "/service.A/Method",
		Action: ActionRead,
	}
	decision, err := authorizer.Authorize(context.Background(), reqA)
	s.Require().NoError(err)
	s.True(decision.Allowed, "token with role-a should access service A")

	// Should access service B
	reqB := &authz.Request{
		Token:  token,
		RPC:    "/service.B/Method",
		Action: ActionRead,
	}
	decision, err = authorizer.Authorize(context.Background(), reqB)
	s.Require().NoError(err)
	s.True(decision.Allowed, "token with role-b should access service B")

	// Should not access service C
	reqC := &authz.Request{
		Token:  token,
		RPC:    "/service.C/Method",
		Action: ActionRead,
	}
	decision, err = authorizer.Authorize(context.Background(), reqC)
	s.Require().NoError(err)
	s.False(decision.Allowed, "token should not access service C")
}

func (s *InterceptorAuthzSuite) TestV2_ResourceContextDimensions() {
	// Policy with dimension constraints
	csvPolicy := `p, role:hr-admin, /policy.attributes.AttributesService/*, namespace=hr, allow
p, role:finance-admin, /policy.attributes.AttributesService/*, namespace=finance, allow`

	authorizer := s.createV2Authorizer(csvPolicy)

	// HR admin with HR namespace dimension
	hrToken := s.newTokenWithRoles("hr-admin")
	hrResource := authz.ResolverResource(map[string]string{"namespace": "hr"})
	hrReq := &authz.Request{
		Token:  hrToken,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: ActionWrite,
		ResourceContext: &authz.ResolverContext{
			Resources: []*authz.ResolverResource{&hrResource},
		},
	}
	decision, err := authorizer.Authorize(context.Background(), hrReq)

	s.Require().NoError(err)
	s.True(decision.Allowed, "hr-admin should be allowed with namespace=hr dimension")

	// HR admin with finance namespace dimension should be denied
	financeResource := authz.ResolverResource(map[string]string{"namespace": "finance"})
	financeReq := &authz.Request{
		Token:  hrToken,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: ActionWrite,
		ResourceContext: &authz.ResolverContext{
			Resources: []*authz.ResolverResource{&financeResource},
		},
	}
	decision, err = authorizer.Authorize(context.Background(), financeReq)

	s.Require().NoError(err)
	s.False(decision.Allowed, "hr-admin should be denied for namespace=finance dimension")

	// Finance admin with finance namespace should be allowed
	financeToken := s.newTokenWithRoles("finance-admin")
	financeReq = &authz.Request{
		Token:  financeToken,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: ActionWrite,
		ResourceContext: &authz.ResolverContext{
			Resources: []*authz.ResolverResource{&financeResource},
		},
	}
	decision, err = authorizer.Authorize(context.Background(), financeReq)

	s.Require().NoError(err)
	s.True(decision.Allowed, "finance-admin should be allowed with namespace=finance dimension")
}

func (s *InterceptorAuthzSuite) TestV2_EmptyToken() {
	csvPolicy := "p, role:admin, *, *, allow"
	authorizer := s.createV2Authorizer(csvPolicy)

	// Empty token (no roles)
	token := jwt.New()
	req := &authz.Request{
		Token:  token,
		RPC:    "/some.Service/Method",
		Action: ActionRead,
	}
	decision, err := authorizer.Authorize(context.Background(), req)

	s.Require().NoError(err)
	s.Require().NotNil(decision)
	// Should be denied because no matching role (defaults to unknown)
	s.False(decision.Allowed, "empty token should be denied")
}

// =============================================================================
// Action Mapping Tests (used by getAction in the interceptor)
// =============================================================================

func (s *InterceptorAuthzSuite) TestGetAction() {
	tests := []struct {
		method   string
		expected string
	}{
		{"GetAttribute", ActionRead},
		{"ListAttributes", ActionRead},
		{"CreateAttribute", ActionWrite},
		{"UpdateAttribute", ActionWrite},
		{"AssignKeyAccess", ActionWrite},
		{"DeleteAttribute", ActionDelete},
		{"RemoveKeyAccess", ActionDelete},
		{"DeactivateEntity", ActionDelete},
		{"UnsafeOperation", ActionUnsafe},
		{"SomeOtherMethod", ActionOther},
	}

	for _, tc := range tests {
		s.Run(tc.method, func() {
			action := getAction(tc.method)
			s.Equal(tc.expected, action)
		})
	}
}

// =============================================================================
// Version and Mode Tests
// =============================================================================

func (s *InterceptorAuthzSuite) TestV1_ReturnsCorrectMode() {
	policyCfg := PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	authorizer := s.createV1Authorizer(policyCfg)
	s.Equal("v1", authorizer.Version())
	s.False(authorizer.SupportsResourceAuthorization())
}

func (s *InterceptorAuthzSuite) TestV2_ReturnsCorrectMode() {
	csvPolicy := "p, role:admin, *, *, allow"
	authorizer := s.createV2Authorizer(csvPolicy)
	s.Equal("v2", authorizer.Version())
	s.True(authorizer.SupportsResourceAuthorization())
}

// =============================================================================
// Path Handling Tests (v1 strips gRPC leading slash, keeps HTTP leading slash)
// =============================================================================

func (s *InterceptorAuthzSuite) TestV1_GRPCPathCompatibility() {
	policyCfg := PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	authorizer := s.createV1Authorizer(policyCfg)
	adminToken := s.newTokenWithRoles("opentdf-admin")

	// gRPC paths with leading slash (as provided by ConnectRPC)
	grpcPaths := []string{
		"/policy.attributes.AttributesService/GetAttribute",
		"/kas.AccessService/Rewrap",
		"/authorization.AuthorizationService/GetDecisions",
	}

	for _, path := range grpcPaths {
		s.Run(path, func() {
			req := &authz.Request{
				Token:  adminToken,
				RPC:    path,
				Action: ActionRead,
			}
			decision, err := authorizer.Authorize(context.Background(), req)

			s.Require().NoError(err)
			s.True(decision.Allowed, "admin should access gRPC path: %s", path)
			s.Equal(authz.ModeV1, decision.Mode)
		})
	}
}

func (s *InterceptorAuthzSuite) TestV1_HTTPPathCompatibility() {
	policyCfg := PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	authorizer := s.createV1Authorizer(policyCfg)
	standardToken := s.newTokenWithRoles("opentdf-standard")

	// HTTP paths with leading slash
	httpPaths := []string{
		"/kas/v2/rewrap",
	}

	for _, path := range httpPaths {
		s.Run(path, func() {
			req := &authz.Request{
				Token:  standardToken,
				RPC:    path,
				Action: ActionWrite,
			}
			decision, err := authorizer.Authorize(context.Background(), req)

			s.Require().NoError(err)
			s.True(decision.Allowed, "standard should access HTTP path: %s", path)
			s.Equal(authz.ModeV1, decision.Mode)
		})
	}
}

// =============================================================================
// Helper Methods (must be placed after all exported Test methods per lint rules)
// =============================================================================

// newTestToken creates a test JWT token with the given claims
func (s *InterceptorAuthzSuite) newTestToken(claims map[string]interface{}) jwt.Token {
	tok := jwt.New()
	for k, v := range claims {
		err := tok.Set(k, v)
		s.Require().NoError(err)
	}
	return tok
}

// newTokenWithRoles creates a token with specified roles
func (s *InterceptorAuthzSuite) newTokenWithRoles(roles ...string) jwt.Token {
	roleInterfaces := make([]interface{}, len(roles))
	for i, r := range roles {
		roleInterfaces[i] = r
	}
	return s.newTestToken(map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": roleInterfaces,
		},
	})
}

// createV1Authorizer creates a v1 Casbin authorizer using the same path as the interceptor
func (s *InterceptorAuthzSuite) createV1Authorizer(policyCfg PolicyConfig) authz.Authorizer {
	// Create the v1 Casbin enforcer (same as authn.go)
	enforcer, err := NewCasbinEnforcer(CasbinConfig{PolicyConfig: policyCfg}, s.logger)
	s.Require().NoError(err)

	// Create authz config matching authn.go initialization
	authzPolicyCfg := authz.PolicyConfig{
		Engine:        policyCfg.Engine,
		Version:       "v1",
		UserNameClaim: policyCfg.UserNameClaim,
		GroupsClaim:   policyCfg.GroupsClaim,
		ClientIDClaim: policyCfg.ClientIDClaim,
		Csv:           policyCfg.Csv,
		Extension:     policyCfg.Extension,
		Model:         policyCfg.Model,
		RoleMap:       policyCfg.RoleMap,
	}
	authzCfg := authz.Config{
		Engine:       "casbin",
		Version:      "v1",
		PolicyConfig: authzPolicyCfg,
		Logger:       s.logger,
		Options:      []authz.Option{authz.WithV1Enforcer(enforcer)},
	}

	authorizer, err := authz.New(authzCfg)
	s.Require().NoError(err)
	return authorizer
}

// createV2Authorizer creates a v2 Casbin authorizer
func (s *InterceptorAuthzSuite) createV2Authorizer(csvPolicy string) authz.Authorizer {
	authzPolicyCfg := authz.PolicyConfig{
		Engine:      "casbin",
		Version:     "v2",
		GroupsClaim: "realm_access.roles",
		Csv:         csvPolicy,
	}
	authzCfg := authz.Config{
		Engine:       "casbin",
		Version:      "v2",
		PolicyConfig: authzPolicyCfg,
		Logger:       s.logger,
	}

	authorizer, err := authz.New(authzCfg)
	s.Require().NoError(err)
	return authorizer
}
