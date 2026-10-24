package auth

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"
	connectv2 "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/attributes/attributesconnect"
	"github.com/opentdf/platform/protocol/go/policy/attributes/attributesconnectv2"
	internalauthz "github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/internal/server/memhttp"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// fakeAttributesV2 records the request and resolver context UpdateAttribute
// receives.
type fakeAttributesV2 struct {
	attributesconnectv2.UnimplementedAttributesServiceHandler

	called      bool
	request     *attributes.UpdateAttributeRequest
	resolverCtx *internalauthz.ResolverContext
}

func (f *fakeAttributesV2) UpdateAttribute(ctx context.Context, req *attributes.UpdateAttributeRequest) (*attributes.UpdateAttributeResponse, error) {
	f.called = true
	f.request = req
	f.resolverCtx = internalauthz.ResolverContextFromContext(ctx)
	return &attributes.UpdateAttributeResponse{}, nil
}

// withAccessToken stands in for the authentication interceptor.
func withAccessToken(token jwt.Token) connectv2.ServerInterceptor {
	return func(next connectv2.ServerFunc) connectv2.ServerFunc {
		return func(ctx context.Context, spec connectv2.Spec, stream connectv2.ServerStream) error {
			return next(ctxAuth.ContextWithAuthNInfo(ctx, nil, token, "raw-token"), spec, stream)
		}
	}
}

func (s *InterceptorAuthzSuite) newAttributesV2Client(authn *Authentication, token jwt.Token, fake *fakeAttributesV2) attributesconnect.AttributesServiceClient {
	server := connectv2.NewServer(withAccessToken(token), authn.ConnectAuthZInterceptorV2())
	attributesconnectv2.RegisterAttributesServiceHandler(server, fake)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	srv := memhttp.New(mux)
	s.T().Cleanup(func() { _ = srv.Close() })
	return attributesconnect.NewAttributesServiceClient(srv.Client(), srv.Listener.Addr().String())
}

func (s *InterceptorAuthzSuite) newResolverRegistry(resolver internalauthz.ResolverFunc) *internalauthz.ResolverRegistry {
	registry := internalauthz.NewResolverRegistry()
	registry.ScopedForService(&grpc.ServiceDesc{
		ServiceName: "policy.attributes.AttributesService",
		Methods:     []grpc.MethodDesc{{MethodName: "UpdateAttribute"}},
	}).MustRegister("UpdateAttribute", resolver)
	return registry
}

func (s *InterceptorAuthzSuite) TestConnectAuthZInterceptorV2_ResolverReadsRequestAndHandlerGetsIt() {
	csvPolicy := "p, role:hr-admin, /policy.attributes.AttributesService/*, namespace=hr, allow"
	var resolved proto.Message
	registry := s.newResolverRegistry(func(_ context.Context, req proto.Message) (internalauthz.ResolverContext, error) {
		resolved = req
		resolverCtx := internalauthz.NewResolverContext()
		resolverCtx.NewResource().AddDimension("namespace", "hr")
		resolverCtx.SetResolvedData("attribute", "resolved")
		return resolverCtx, nil
	})
	authn := &Authentication{logger: s.logger, authorizer: s.createV2Authorizer(csvPolicy), authzResolverRegistry: registry}
	fake := &fakeAttributesV2{}
	client := s.newAttributesV2Client(authn, s.newTokenWithRoles("hr-admin"), fake)
	sent := &attributes.UpdateAttributeRequest{Id: "8f1f5a3c-5c61-4a7c-9f3b-4f3c2f6f9e10"}

	_, err := client.UpdateAttribute(s.T().Context(), connect.NewRequest(sent))

	s.Require().NoError(err)
	s.True(fake.called)
	s.True(proto.Equal(sent, resolved), "the resolver must see the request message")
	s.True(proto.Equal(sent, fake.request), "the handler must receive the request message unchanged")
	s.Require().NotNil(fake.resolverCtx)
	s.Equal("resolved", fake.resolverCtx.GetResolvedData("attribute"))
}

func (s *InterceptorAuthzSuite) TestConnectAuthZInterceptorV2_ResolverErrorFailsClosed() {
	csvPolicy := "p, role:hr-admin, /policy.attributes.AttributesService/*, namespace=hr, allow"
	registry := s.newResolverRegistry(func(context.Context, proto.Message) (internalauthz.ResolverContext, error) {
		return internalauthz.NewResolverContext(), errors.New("resolver db unavailable")
	})
	authn := &Authentication{logger: s.logger, authorizer: s.createV2Authorizer(csvPolicy), authzResolverRegistry: registry}
	fake := &fakeAttributesV2{}
	client := s.newAttributesV2Client(authn, s.newTokenWithRoles("hr-admin"), fake)

	_, err := client.UpdateAttribute(s.T().Context(), connect.NewRequest(&attributes.UpdateAttributeRequest{}))

	s.Equal(connect.CodePermissionDenied, connect.CodeOf(err))
	s.False(fake.called)
}

func (s *InterceptorAuthzSuite) TestConnectAuthZInterceptorV2_DeniesWithoutResolver() {
	csvPolicy := "p, role:attribute-reader, /policy.attributes.AttributesService/GetAttribute, *, allow"
	authn := &Authentication{logger: s.logger, authorizer: s.createV2Authorizer(csvPolicy)}
	fake := &fakeAttributesV2{}
	client := s.newAttributesV2Client(authn, s.newTokenWithRoles("attribute-reader"), fake)

	_, err := client.UpdateAttribute(s.T().Context(), connect.NewRequest(&attributes.UpdateAttributeRequest{}))

	s.Equal(connect.CodePermissionDenied, connect.CodeOf(err))
	s.False(fake.called)
}

func (s *InterceptorAuthzSuite) TestConnectAuthZInterceptorV2_MissingTokenIsUnauthenticated() {
	authn := &Authentication{logger: s.logger, authorizer: s.createV2Authorizer("p, role:admin, *, *, allow")}
	server := connectv2.NewServer(authn.ConnectAuthZInterceptorV2())
	fake := &fakeAttributesV2{}
	attributesconnectv2.RegisterAttributesServiceHandler(server, fake)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	srv := memhttp.New(mux)
	s.T().Cleanup(func() { _ = srv.Close() })
	client := attributesconnect.NewAttributesServiceClient(srv.Client(), srv.Listener.Addr().String())

	_, err := client.UpdateAttribute(s.T().Context(), connect.NewRequest(&attributes.UpdateAttributeRequest{}))

	s.Equal(connect.CodeUnauthenticated, connect.CodeOf(err))
	s.False(fake.called)
}

func (s *InterceptorAuthzSuite) TestConnectAuthZInterceptorV2_StreamingIgnoresResolvers() {
	const streamProcedure = "/policy.attributes.AttributesService/UpdateAttribute"
	csvPolicy := "p, role:attribute-writer, " + streamProcedure + ", *, allow"
	resolverCalled := false
	registry := s.newResolverRegistry(func(context.Context, proto.Message) (internalauthz.ResolverContext, error) {
		resolverCalled = true
		return internalauthz.NewResolverContext(), nil
	})
	authn := &Authentication{logger: s.logger, authorizer: s.createV2Authorizer(csvPolicy), authzResolverRegistry: registry}
	called := false
	server := connectv2.NewServer(withAccessToken(s.newTokenWithRoles("attribute-writer")), authn.ConnectAuthZInterceptorV2())
	server.Register(connectv2.Method{
		Spec: connectv2.Spec{Procedure: streamProcedure, StreamType: connectv2.StreamTypeClient},
		Handler: func(context.Context, connectv2.Spec, connectv2.ServerStream) error {
			called = true
			return connectv2.NewError(connectv2.CodeUnimplemented, "stream handler reached")
		},
	})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	srv := memhttp.New(mux)
	s.T().Cleanup(func() { _ = srv.Close() })
	client := connect.NewClient[attributes.UpdateAttributeRequest, attributes.UpdateAttributeResponse](srv.Client(), srv.Listener.Addr().String()+streamProcedure)

	stream := client.CallClientStream(s.T().Context())
	_ = stream.Send(&attributes.UpdateAttributeRequest{})
	_, err := stream.CloseAndReceive()

	s.Equal(connect.CodeUnimplemented, connect.CodeOf(err))
	s.True(called, "procedure-level policy allows the stream")
	s.False(resolverCalled, "streams are authorized without resolvers")
}
