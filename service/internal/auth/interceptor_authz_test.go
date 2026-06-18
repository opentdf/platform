package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/creasty/defaults"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry/kasregistryconnect"
	internalauthz "github.com/opentdf/platform/service/internal/auth/authz"
	_ "github.com/opentdf/platform/service/internal/auth/authz/casbin" // Register casbin authorizer
	"github.com/opentdf/platform/service/logger"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
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

// V1 Mode Tests - Path-based authorization (used by ConnectUnaryServerInterceptor)

func (s *InterceptorAuthzSuite) TestV1_AdminCanAccessAll() {
	policyCfg := internalauthz.PolicyConfig{}
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
			req := &internalauthz.Request{
				Token:  token,
				RPC:    tc.rpc,
				Action: tc.action,
			}
			decision, err := authorizer.Authorize(context.Background(), req)

			s.Require().NoError(err)
			s.Require().NotNil(decision)
			s.Equal(tc.expected, decision.Allowed, "expected allowed=%v for %s", tc.expected, tc.name)
			s.Equal(internalauthz.ModeV1, decision.Mode)
		})
	}
}

func (s *InterceptorAuthzSuite) TestV1_StandardUserPermissions() {
	policyCfg := internalauthz.PolicyConfig{}
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
			req := &internalauthz.Request{
				Token:  token,
				RPC:    tc.rpc,
				Action: tc.action,
			}
			decision, err := authorizer.Authorize(context.Background(), req)

			s.Require().NoError(err)
			s.Require().NotNil(decision)
			s.Equal(tc.expected, decision.Allowed, "expected allowed=%v for %s", tc.expected, tc.name)
			s.Equal(internalauthz.ModeV1, decision.Mode)
		})
	}
}

func (s *InterceptorAuthzSuite) TestV1_UnknownRoleDenied() {
	policyCfg := internalauthz.PolicyConfig{}
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
			req := &internalauthz.Request{
				Token:  token,
				RPC:    tc.rpc,
				Action: ActionRead,
			}
			decision, err := authorizer.Authorize(context.Background(), req)

			s.Require().NoError(err)
			s.Require().NotNil(decision)
			s.False(decision.Allowed, "unknown role should be denied for %s", tc.rpc)
			s.Equal(internalauthz.ModeV1, decision.Mode)
		})
	}
}

func (s *InterceptorAuthzSuite) TestV1_UnknownRolePublicRoutes() {
	policyCfg := internalauthz.PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	authorizer := s.createV1Authorizer(policyCfg)
	token := s.newTokenWithRoles("unknown-role")

	// The default v1 policy explicitly allows unknown roles to access the gRPC
	// rewrap route, primarily for ERS (Entity Resolution Service) functionality.
	// The v2 policy covers the HTTP rewrap route separately.
	tests := []struct {
		name string
		rpc  string
	}{
		{"kas rewrap gRPC", "/kas.AccessService/Rewrap"},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			req := &internalauthz.Request{
				Token:  token,
				RPC:    tc.rpc,
				Action: ActionRead,
			}
			decision, err := authorizer.Authorize(context.Background(), req)

			s.Require().NoError(err)
			s.Require().NotNil(decision)
			s.True(decision.Allowed, "unknown role should be ALLOWED for public route %s", tc.rpc)
			s.Equal(internalauthz.ModeV1, decision.Mode)
		})
	}
}

func (s *InterceptorAuthzSuite) TestV1_CustomRoleMapping() {
	policyCfg := internalauthz.PolicyConfig{}
	err := defaults.Set(&policyCfg)
	s.Require().NoError(err)

	// Map external roles to internal roles
	//nolint:staticcheck // Exercise deprecated RoleMap compatibility.
	policyCfg.RoleMap = map[string]string{
		"admin":    "external-admin",
		"standard": "external-standard",
	}

	authorizer := s.createV1Authorizer(policyCfg)

	// Token with mapped admin role
	adminToken := s.newTokenWithRoles("external-admin")
	req := &internalauthz.Request{
		Token:  adminToken,
		RPC:    "/policy.attributes.AttributesService/CreateAttribute",
		Action: ActionWrite,
	}
	decision, err := authorizer.Authorize(context.Background(), req)

	s.Require().NoError(err)
	s.True(decision.Allowed, "mapped admin role should be allowed")

	// Token with mapped standard role
	standardToken := s.newTokenWithRoles("external-standard")
	req = &internalauthz.Request{
		Token:  standardToken,
		RPC:    "/policy.attributes.AttributesService/CreateAttribute",
		Action: ActionWrite,
	}
	decision, err = authorizer.Authorize(context.Background(), req)

	s.Require().NoError(err)
	s.False(decision.Allowed, "mapped standard role should be denied for write")
}

func (s *InterceptorAuthzSuite) TestV1_ExtendedPolicy() {
	policyCfg := internalauthz.PolicyConfig{}
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
	req := &internalauthz.Request{
		Token:  token,
		RPC:    "/custom.service.CustomService/GetCustom",
		Action: ActionRead,
	}
	decision, err := authorizer.Authorize(context.Background(), req)

	s.Require().NoError(err)
	s.True(decision.Allowed, "custom role should be allowed for custom service")

	// Custom role cannot access other services
	req = &internalauthz.Request{
		Token:  token,
		RPC:    "/policy.attributes.AttributesService/GetAttribute",
		Action: ActionRead,
	}
	decision, err = authorizer.Authorize(context.Background(), req)

	s.Require().NoError(err)
	s.False(decision.Allowed, "custom role should be denied for policy service")
}

// V2 Mode Tests - RPC + Dimensions authorization

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
			req := &internalauthz.Request{
				Token:  token,
				RPC:    tc.rpc,
				Action: ActionRead,
			}
			decision, err := authorizer.Authorize(context.Background(), req)

			s.Require().NoError(err)
			s.Require().NotNil(decision)
			s.True(decision.Allowed, "admin should have wildcard access to %s", tc.rpc)
			s.Equal(internalauthz.ModeV2, decision.Mode)
		})
	}
}

func (s *InterceptorAuthzSuite) TestV2_ServiceScopedAccess() {
	csvPolicy := `p, role:policy-reader, /policy.*, *, allow
p, role:kas-user, /kas.*, *, allow`

	authorizer := s.createV2Authorizer(csvPolicy)

	// Policy reader token
	policyToken := s.newTokenWithRoles("policy-reader")
	policyReq := &internalauthz.Request{
		Token:  policyToken,
		RPC:    "/policy.attributes.AttributesService/GetAttribute",
		Action: ActionRead,
	}
	decision, err := authorizer.Authorize(context.Background(), policyReq)

	s.Require().NoError(err)
	s.True(decision.Allowed, "policy-reader should access policy service")

	// Policy reader cannot access KAS
	kasReq := &internalauthz.Request{
		Token:  policyToken,
		RPC:    "/kas.AccessService/Rewrap",
		Action: ActionRead,
	}
	decision, err = authorizer.Authorize(context.Background(), kasReq)

	s.Require().NoError(err)
	s.False(decision.Allowed, "policy-reader should not access kas service")

	// KAS user token
	kasToken := s.newTokenWithRoles("kas-user")
	kasReq = &internalauthz.Request{
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
	req := &internalauthz.Request{
		Token:  token,
		RPC:    "/some.Service/Method",
		Action: ActionRead,
	}
	decision, err := authorizer.Authorize(context.Background(), req)

	s.Require().NoError(err)
	s.Require().NotNil(decision)
	s.False(decision.Allowed, "unknown role should be denied")
	s.Equal(internalauthz.ModeV2, decision.Mode)
}

func (s *InterceptorAuthzSuite) TestV2_MultipleRoles() {
	// Policy where different roles have access to different services
	csvPolicy := `p, role:role-a, /service.A/*, *, allow
p, role:role-b, /service.B/*, *, allow`

	authorizer := s.createV2Authorizer(csvPolicy)

	// Token with multiple roles
	token := s.newTokenWithRoles("role-a", "role-b")

	// Should access service A
	reqA := &internalauthz.Request{
		Token:  token,
		RPC:    "/service.A/Method",
		Action: ActionRead,
	}
	decision, err := authorizer.Authorize(context.Background(), reqA)
	s.Require().NoError(err)
	s.True(decision.Allowed, "token with role-a should access service A")

	// Should access service B
	reqB := &internalauthz.Request{
		Token:  token,
		RPC:    "/service.B/Method",
		Action: ActionRead,
	}
	decision, err = authorizer.Authorize(context.Background(), reqB)
	s.Require().NoError(err)
	s.True(decision.Allowed, "token with role-b should access service B")

	// Should not access service C
	reqC := &internalauthz.Request{
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
	hrResource := internalauthz.ResolverResource(map[string]string{"namespace": "hr"})
	hrReq := &internalauthz.Request{
		Token:  hrToken,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: ActionWrite,
		ResourceContext: &internalauthz.ResolverContext{
			Resources: []*internalauthz.ResolverResource{&hrResource},
		},
	}
	decision, err := authorizer.Authorize(context.Background(), hrReq)

	s.Require().NoError(err)
	s.True(decision.Allowed, "hr-admin should be allowed with namespace=hr dimension")

	// HR admin with finance namespace dimension should be denied
	financeResource := internalauthz.ResolverResource(map[string]string{"namespace": "finance"})
	financeReq := &internalauthz.Request{
		Token:  hrToken,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: ActionWrite,
		ResourceContext: &internalauthz.ResolverContext{
			Resources: []*internalauthz.ResolverResource{&financeResource},
		},
	}
	decision, err = authorizer.Authorize(context.Background(), financeReq)

	s.Require().NoError(err)
	s.False(decision.Allowed, "hr-admin should be denied for namespace=finance dimension")

	// Finance admin with finance namespace should be allowed
	financeToken := s.newTokenWithRoles("finance-admin")
	financeReq = &internalauthz.Request{
		Token:  financeToken,
		RPC:    "/policy.attributes.AttributesService/UpdateAttribute",
		Action: ActionWrite,
		ResourceContext: &internalauthz.ResolverContext{
			Resources: []*internalauthz.ResolverResource{&financeResource},
		},
	}
	decision, err = authorizer.Authorize(context.Background(), financeReq)

	s.Require().NoError(err)
	s.True(decision.Allowed, "finance-admin should be allowed with namespace=finance dimension")
}

func (s *InterceptorAuthzSuite) TestAuthorizeV2_InvokesRegisteredResolver() {
	csvPolicy := "p, role:hr-admin, /policy.attributes.AttributesService/*, namespace=hr, allow"
	registry := internalauthz.NewResolverRegistry()
	scopedRegistry := registry.ScopedForService(&grpc.ServiceDesc{
		ServiceName: "policy.attributes.AttributesService",
		Methods: []grpc.MethodDesc{
			{MethodName: "UpdateAttribute"},
		},
	})

	resolverCalled := false
	scopedRegistry.MustRegister("UpdateAttribute", func(_ context.Context, _ connect.AnyRequest) (internalauthz.ResolverContext, error) {
		resolverCalled = true
		resolverCtx := internalauthz.NewResolverContext()
		res := resolverCtx.NewResource()
		res.AddDimension("namespace", "hr")
		resolverCtx.SetResolvedData("attribute", "resolved")
		return resolverCtx, nil
	})

	authn := &Authentication{
		logger:                s.logger,
		authorizer:            s.createV2Authorizer(csvPolicy),
		authzResolverRegistry: registry,
	}

	req := &authzTestRequest{
		Request:   connect.NewRequest(&attributes.GetAttributeRequest{}),
		procedure: "/policy.attributes.AttributesService/UpdateAttribute",
	}

	result := authn.authorize(s.T().Context(), s.logger, s.newTokenWithRoles("hr-admin"), req, ActionWrite)

	s.Require().NoError(result.err)
	s.Require().NotNil(result.decision)
	s.True(result.decision.Allowed)
	s.True(resolverCalled, "registered resolver should be invoked")
	s.Require().NotNil(result.resourceContext)
	s.Equal("resolved", result.resourceContext.GetResolvedData("attribute"))
}

func (s *InterceptorAuthzSuite) TestAuthorizeV2_ResolverErrorFailsClosed() {
	csvPolicy := "p, role:hr-admin, /policy.attributes.AttributesService/*, namespace=hr, allow"
	registry := internalauthz.NewResolverRegistry()
	scopedRegistry := registry.ScopedForService(&grpc.ServiceDesc{
		ServiceName: "policy.attributes.AttributesService",
		Methods: []grpc.MethodDesc{
			{MethodName: "UpdateAttribute"},
		},
	})

	scopedRegistry.MustRegister("UpdateAttribute", func(_ context.Context, _ connect.AnyRequest) (internalauthz.ResolverContext, error) {
		return internalauthz.NewResolverContext(), errors.New("resolver db unavailable")
	})

	authn := &Authentication{
		logger:                s.logger,
		authorizer:            s.createV2Authorizer(csvPolicy),
		authzResolverRegistry: registry,
	}

	req := &authzTestRequest{
		Request:   connect.NewRequest(&attributes.GetAttributeRequest{}),
		procedure: "/policy.attributes.AttributesService/UpdateAttribute",
	}

	result := authn.authorize(s.T().Context(), s.logger, s.newTokenWithRoles("hr-admin"), req, ActionWrite)

	s.Require().Error(result.err)
	s.Equal(connect.CodePermissionDenied, result.errCode)
	s.Equal("authorization context resolution failed", result.err.Error())
	s.Nil(result.decision)
}

func (s *InterceptorAuthzSuite) TestAuthorizeV2_UnregisteredResolverProcedureUsesNilResourceContext() {
	const requestedRPC = "/policy.attributes.AttributesService/GetAttribute"

	csvPolicy := "p, role:attribute-reader, " + requestedRPC + ", *, allow"
	registry := internalauthz.NewResolverRegistry()
	_, hasRequestedResolver := registry.Get(requestedRPC)
	s.False(hasRequestedResolver, "requested RPC should not have a resolver")

	authn := &Authentication{
		logger:                s.logger,
		authorizer:            s.createV2Authorizer(csvPolicy),
		authzResolverRegistry: registry,
	}

	req := &authzTestRequest{
		Request:   connect.NewRequest(&attributes.GetAttributeRequest{}),
		procedure: requestedRPC,
	}
	ctx := ctxAuth.ContextWithAuthNInfo(s.T().Context(), nil, s.newTokenWithRoles("attribute-reader"), "raw-token")
	nextCalled := false
	next := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		nextCalled = true
		s.Nil(internalauthz.ResolverContextFromContext(ctx), "handler context should not have resolver context")
		return connect.NewResponse(&attributes.GetAttributeResponse{}), nil
	}

	resp, err := authn.ConnectAuthZInterceptor()(next)(ctx, req)

	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.True(nextCalled, "next handler should be called when wildcard-dimension policy allows the RPC")
}

func (s *InterceptorAuthzSuite) TestV2_EmptyToken() {
	csvPolicy := "p, role:admin, *, *, allow"
	authorizer := s.createV2Authorizer(csvPolicy)

	// Empty token (no roles)
	token := jwt.New()
	req := &internalauthz.Request{
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

type authzTestRequest struct {
	*connect.Request[attributes.GetAttributeRequest]
	procedure string
}

func (r *authzTestRequest) Spec() connect.Spec {
	return connect.Spec{Procedure: r.procedure}
}

type authzGetKeyTestRequest struct {
	*connect.Request[kasregistry.GetKeyRequest]
	procedure string
}

func (r *authzGetKeyTestRequest) Spec() connect.Spec {
	return connect.Spec{Procedure: r.procedure}
}

// Action Mapping Tests (used by getAction in the interceptor)

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

// Version and Mode Tests

func (s *InterceptorAuthzSuite) TestV1_ReturnsCorrectMode() {
	policyCfg := internalauthz.PolicyConfig{}
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

// Path Handling Tests (v1 strips gRPC leading slash, keeps HTTP leading slash)

func (s *InterceptorAuthzSuite) TestV1_GRPCPathCompatibility() {
	policyCfg := internalauthz.PolicyConfig{}
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
			req := &internalauthz.Request{
				Token:  adminToken,
				RPC:    path,
				Action: ActionRead,
			}
			decision, err := authorizer.Authorize(context.Background(), req)

			s.Require().NoError(err)
			s.True(decision.Allowed, "admin should access gRPC path: %s", path)
			s.Equal(internalauthz.ModeV1, decision.Mode)
		})
	}
}

func (s *InterceptorAuthzSuite) TestV1_HTTPPathCompatibility() {
	policyCfg := internalauthz.PolicyConfig{}
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
			req := &internalauthz.Request{
				Token:  standardToken,
				RPC:    path,
				Action: ActionWrite,
			}
			decision, err := authorizer.Authorize(context.Background(), req)

			s.Require().NoError(err)
			s.True(decision.Allowed, "standard should access HTTP path: %s", path)
			s.Equal(internalauthz.ModeV1, decision.Mode)
		})
	}
}

func (s *InterceptorAuthzSuite) TestAuthorizeV2_DenyPathReturnsPermissionDenied() {
	// Policy that only allows role:kas-reader, so role:other is denied.
	csvPolicy := "p, role:kas-reader, " + kasregistryconnect.KeyAccessServerRegistryServiceGetKeyProcedure + ", *, allow"
	authn := &Authentication{
		logger:     s.logger,
		authorizer: s.createV2Authorizer(csvPolicy),
	}

	req := &authzGetKeyTestRequest{
		Request:   connect.NewRequest(&kasregistry.GetKeyRequest{}),
		procedure: kasregistryconnect.KeyAccessServerRegistryServiceGetKeyProcedure,
	}

	// token whose role is NOT authorized
	token := s.newTokenWithRoles("other-role")
	ctx := ctxAuth.ContextWithAuthNInfo(s.T().Context(), nil, token, "raw-token")
	nextCalled := false
	next := func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		nextCalled = true
		return connect.NewResponse(&kasregistry.GetKeyResponse{}), nil
	}

	_, err := authn.ConnectAuthZInterceptor()(next)(ctx, req)

	s.Require().Error(err)
	s.Equal(connect.CodePermissionDenied, connect.CodeOf(err))
	s.False(nextCalled, "next handler should not be called on denied authorization")
}

func (s *InterceptorAuthzSuite) TestAuthorize_NoToken_ReturnsCodeUnauthenticated() {
	csvPolicy := "p, role:admin, *, *, allow"
	authn := &Authentication{
		logger:     s.logger,
		authorizer: s.createV2Authorizer(csvPolicy),
	}

	req := &authzTestRequest{
		Request:   connect.NewRequest(&attributes.GetAttributeRequest{}),
		procedure: "/policy.attributes.AttributesService/GetAttribute",
	}
	nextCalled := false
	next := func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		nextCalled = true
		return connect.NewResponse(&attributes.GetAttributeResponse{}), nil
	}

	_, err := authn.ConnectAuthZInterceptor()(next)(s.T().Context(), req)

	s.Require().Error(err)
	s.Equal(connect.CodeUnauthenticated, connect.CodeOf(err))
	s.False(nextCalled, "next handler should not be called without an access token")
}

func (s *InterceptorAuthzSuite) TestAuthorize_AuthorizerReturnsError_ReturnsCodeInternal() {
	authn := &Authentication{
		logger:     s.logger,
		authorizer: &errorAuthorizer{err: errors.New("db unavailable")},
	}

	req := &authzTestRequest{
		Request:   connect.NewRequest(&attributes.GetAttributeRequest{}),
		procedure: "/policy.attributes.AttributesService/GetAttribute",
	}

	result := authn.authorize(s.T().Context(), s.logger, s.newTokenWithRoles("admin"), req, ActionRead)

	s.Require().Error(result.err)
	s.Equal(connect.CodeInternal, result.errCode)
}

func (s *InterceptorAuthzSuite) TestAuthorize_NilAuthorizer_ReturnsCodeInternal() {
	authn := &Authentication{
		logger:     s.logger,
		authorizer: nil,
	}

	req := &authzTestRequest{
		Request:   connect.NewRequest(&attributes.GetAttributeRequest{}),
		procedure: "/policy.attributes.AttributesService/GetAttribute",
	}

	result := authn.authorize(s.T().Context(), s.logger, s.newTokenWithRoles("admin"), req, ActionRead)

	s.Require().Error(result.err)
	s.Equal(connect.CodeInternal, result.errCode)
}

// errorAuthorizer is an Authorizer that always returns a non-nil error.
type errorAuthorizer struct {
	err error
}

func (e *errorAuthorizer) Authorize(_ context.Context, _ *internalauthz.Request) (*internalauthz.Decision, error) {
	return nil, e.err
}

func (e *errorAuthorizer) Version() string { return "error" }

func (e *errorAuthorizer) SupportsResourceAuthorization() bool { return false }

func (s *InterceptorAuthzSuite) TestResolveResourceContext_UnregisteredProcedure_ReturnsNil() {
	// Registry has a resolver for "OtherMethod" but not for "GetKey".
	csvPolicy := "p, role:admin, *, *, allow"
	registry := internalauthz.NewResolverRegistry()
	scopedRegistry := registry.ScopedForService(&grpc.ServiceDesc{
		ServiceName: "policy.kasregistry.KeyAccessServerRegistryService",
		Methods: []grpc.MethodDesc{
			{MethodName: "OtherMethod"},
			{MethodName: "GetKey"},
		},
	})
	scopedRegistry.MustRegister("OtherMethod", func(_ context.Context, _ connect.AnyRequest) (internalauthz.ResolverContext, error) {
		ctx := internalauthz.NewResolverContext()
		return ctx, nil
	})

	authn := &Authentication{
		logger:                s.logger,
		authorizer:            s.createV2Authorizer(csvPolicy),
		authzResolverRegistry: registry,
	}

	req := &authzTestRequest{
		Request:   connect.NewRequest(&attributes.GetAttributeRequest{}),
		procedure: "/policy.kasregistry.KeyAccessServerRegistryService/GetKey",
	}

	// resolveResourceContext for an unregistered method should return nil, errNoResourceContext
	resourceCtx, err := authn.resolveResourceContext(s.T().Context(), s.logger, req)

	s.Require().Error(err)
	s.Require().ErrorIs(err, errNoResourceContext)
	s.Nil(resourceCtx)
}

// Helper Methods (must be placed after all exported Test methods per lint rules)

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
func (s *InterceptorAuthzSuite) createV1Authorizer(policyCfg internalauthz.PolicyConfig) internalauthz.Authorizer {
	// Create authz config matching authn.go initialization
	authzPolicyCfg := internalauthz.PolicyConfig{
		Engine:        policyCfg.Engine,
		Version:       "v1",
		UserNameClaim: policyCfg.UserNameClaim,
		GroupsClaim:   policyCfg.GroupsClaim,
		ClientIDClaim: policyCfg.ClientIDClaim,
		Csv:           policyCfg.Csv,
		Extension:     policyCfg.Extension,
		Model:         policyCfg.Model,
		//nolint:staticcheck // Exercise deprecated RoleMap compatibility.
		RoleMap: policyCfg.RoleMap,
	}
	authzCfg := internalauthz.Config{
		PolicyConfig: authzPolicyCfg,
		Logger:       s.logger,
	}

	authorizer, err := internalauthz.New(authzCfg)
	s.Require().NoError(err)
	return authorizer
}

// createV2Authorizer creates a v2 Casbin authorizer
func (s *InterceptorAuthzSuite) createV2Authorizer(csvPolicy string) internalauthz.Authorizer {
	authzPolicyCfg := internalauthz.PolicyConfig{
		Engine:      "casbin",
		Version:     "v2",
		GroupsClaim: "realm_access.roles",
		Csv:         csvPolicy,
	}
	authzCfg := internalauthz.Config{
		PolicyConfig: authzPolicyCfg,
		Logger:       s.logger,
	}

	authorizer, err := internalauthz.New(authzCfg)
	s.Require().NoError(err)
	return authorizer
}
