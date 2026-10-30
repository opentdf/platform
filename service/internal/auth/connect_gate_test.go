package auth

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	"github.com/opentdf/platform/service/internal/server/memhttp"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/emptypb"
)

// fakeAccessServiceV1 is a connect-go v1 KAS handler that records what it sees.
type fakeAccessServiceV1 struct {
	kasconnect.UnimplementedAccessServiceHandler

	record *kasRecord
}

func (f fakeAccessServiceV1) PublicKey(ctx context.Context, _ *connect.Request[kas.PublicKeyRequest]) (*connect.Response[kas.PublicKeyResponse], error) {
	f.record.recordPublicKey(ctx)
	return connect.NewResponse(&kas.PublicKeyResponse{}), nil
}

func (f fakeAccessServiceV1) Rewrap(ctx context.Context, _ *connect.Request[kas.RewrapRequest]) (*connect.Response[kas.RewrapResponse], error) {
	if f.record.recordRewrap(ctx) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("rewrap failed"))
	}
	return connect.NewResponse(&kas.RewrapResponse{}), nil
}

// newGatedKASServer serves a fake connect-go v1 KAS behind the authentication
// gate and the authn and authz interceptors, wired the way the platform wires
// external v1 handlers.
func (s *AuthSuite) newGatedKASServer(auth *Authentication, readMaxBytes int) (*memhttp.Server, *kasRecord) {
	opts := []connect.HandlerOption{
		connect.WithRequestGate(auth.ConnectAuthNRequestGate()),
		connect.WithInterceptors(auth.ConnectAuthNInterceptor(), auth.ConnectAuthZInterceptor()),
	}
	if readMaxBytes > 0 {
		opts = append(opts, connect.WithReadMaxBytes(readMaxBytes))
	}
	return s.newKASServerV1(opts...)
}

// newInterceptorKASServer serves a fake connect-go v1 KAS behind the authn and
// authz interceptors only, the wiring that existed before the authentication
// gate.
func (s *AuthSuite) newInterceptorKASServer(auth *Authentication) (*memhttp.Server, *kasRecord) {
	return s.newKASServerV1(connect.WithInterceptors(auth.ConnectAuthNInterceptor(), auth.ConnectAuthZInterceptor()))
}

func (s *AuthSuite) newKASServerV1(opts ...connect.HandlerOption) (*memhttp.Server, *kasRecord) {
	record := &kasRecord{}
	mux := http.NewServeMux()
	path, handler := kasconnect.NewAccessServiceHandler(fakeAccessServiceV1{record: record}, opts...)
	mux.Handle(path, handler)
	return s.serve(recordHTTPMethod(mux), &record.bodyRead), record
}

// newGatedGetHandler serves gateTestGetProc behind the authentication gate and
// the authn interceptor.
func newGatedGetHandler(auth *Authentication) http.Handler {
	return connect.NewUnaryHandler(
		gateTestGetProc,
		func(context.Context, *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			return connect.NewResponse(&emptypb.Empty{}), nil
		},
		connect.WithIdempotency(connect.IdempotencyNoSideEffects),
		connect.WithRequestGate(auth.ConnectAuthNRequestGate()),
		connect.WithInterceptors(auth.ConnectAuthNInterceptor()),
	)
}

func (s *AuthSuite) newGatedGetServer(auth *Authentication) *memhttp.Server {
	return s.serve(recordHTTPMethod(newGatedGetHandler(auth)), new(atomic.Int64))
}

func (s *AuthSuite) newGatedUploadServer(auth *Authentication, called *atomic.Bool) *memhttp.Server {
	handler := connect.NewClientStreamHandler(
		gateTestUploadProc,
		func(_ context.Context, stream *connect.ClientStream[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			called.Store(true)
			for stream.Receive() {
				// Drain the stream.
			}
			return connect.NewResponse(&emptypb.Empty{}), stream.Err()
		},
		connect.WithRequestGate(auth.ConnectAuthNRequestGate()),
		connect.WithInterceptors(auth.ConnectAuthNInterceptor()),
	)
	return s.serve(recordHTTPMethod(handler), new(atomic.Int64))
}

func TestHTTPMethodFromContext(t *testing.T) {
	_, ok := HTTPMethodFromContext(t.Context())
	assert.False(t, ok, "no method stored")

	method, ok := HTTPMethodFromContext(ContextWithHTTPMethod(t.Context(), http.MethodGet))
	assert.True(t, ok)
	assert.Equal(t, http.MethodGet, method)

	_, ok = HTTPMethodFromContext(ContextWithHTTPMethod(t.Context(), ""))
	assert.False(t, ok, "an empty method is treated as absent")
}

func (s *AuthSuite) Test_ConnectAuthNRequestGate_PublicRouteReturnsNilError() {
	gate := s.auth.ConnectAuthNRequestGate()

	ctx, err := gate(s.T().Context(), connect.Spec{Procedure: "/public"}, connect.Peer{}, http.Header{})

	// A typed-nil *connect.Error returned as error would fail here.
	s.Require().NoError(err)
	s.True(authenticatedByGate(ctx))
	publicRoute, ok := ctxAuth.PublicRouteFromContext(ctx)
	s.True(ok)
	s.True(publicRoute)
}

func (s *AuthSuite) Test_ConnectAuthNInterceptor_SkipsAuthenticationAfterGate() {
	tok := s.standardRoleToken()
	checks := 0
	s.auth._testCheckTokenFunc = func(ctx context.Context, _ []string, _ receiverInfo, _ []string) (jwt.Token, context.Context, error) {
		checks++
		return tok, ctxAuth.ContextWithAuthNInfo(ctx, nil, tok, "raw-token"), nil
	}
	s.T().Cleanup(func() { s.auth._testCheckTokenFunc = nil })

	header := http.Header{}
	header.Set("Authorization", "DPoP token")
	ctx, err := s.auth.ConnectAuthNRequestGate()(s.T().Context(), connect.Spec{Procedure: rewrapProcedure}, connect.Peer{}, header)
	s.Require().NoError(err)

	called := false
	next := func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
		called = true
		return connect.NewResponse(&kas.RewrapResponse{}), nil
	}
	req := &authnTestRequest{Request: connect.NewRequest(&kas.RewrapRequest{}), procedure: rewrapProcedure}
	req.Header().Set("Authorization", "DPoP token")

	_, err = s.auth.ConnectAuthNInterceptor().WrapUnary(next)(ctx, req)

	s.Require().NoError(err)
	s.True(called)
	s.Equal(1, checks, "the interceptor must not validate the credentials a second time")
}

func (s *AuthSuite) Test_ConnectAuthNInterceptor_DecodesFirstWithoutGate() {
	server, record := s.newInterceptorKASServer(s.auth)

	resp := postConnectUnary(s.T(), server, []byte{0xff, 0xff, 0xff, 0xff}, nil)

	s.Equal(http.StatusBadRequest, resp.StatusCode, "without the gate the body is unmarshaled before authentication")
	s.Zero(record.rewraps.Load())
}

// Test_ConnectAuthNRequestGate_MatchesInterceptorChallenges checks that gate
// rejections carry the same DPoP metadata as rejections from the interceptor
// wiring that preceded the gate.
func (s *AuthSuite) Test_ConnectAuthNRequestGate_MatchesInterceptorChallenges() {
	for _, protocol := range connectTestProtocols() {
		for _, tc := range dpopRejectionCases() {
			s.Run(protocol.name+"/"+tc.name, func() {
				auth := s.rejectingAuth(tc)
				gateServer, _ := s.newGatedKASServer(auth, 0)
				interceptorServer, _ := s.newInterceptorKASServer(auth)

				gateErr := s.rewrapError(gateServer, protocol.opts...)
				interceptorErr := s.rewrapError(interceptorServer, protocol.opts...)

				s.Equal(interceptorErr.Code(), gateErr.Code())
				s.Equal(interceptorErr.Meta().Get("WWW-Authenticate"), gateErr.Meta().Get("WWW-Authenticate"))
				s.Equal(interceptorErr.Meta().Get("DPoP-Nonce") != "", gateErr.Meta().Get("DPoP-Nonce") != "")
			})
		}
	}
}

// Test_ConnectAuthNRequestGate_FallsBackToPOST checks that the gate binds DPoP
// proofs to POST when the router stored no HTTP method.
func (s *AuthSuite) Test_ConnectAuthNRequestGate_FallsBackToPOST() {
	tok := s.standardRoleToken()
	var captured []string
	s.auth._testCheckTokenFunc = func(ctx context.Context, _ []string, ri receiverInfo, _ []string) (jwt.Token, context.Context, error) {
		captured = ri.m
		return tok, ctx, nil
	}
	s.T().Cleanup(func() { s.auth._testCheckTokenFunc = nil })
	server := s.serve(newGatedGetHandler(s.auth), new(atomic.Int64))
	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		server.Client(),
		memhttpBaseURL(server)+gateTestGetProc,
		connect.WithHTTPGet(),
		connect.WithIdempotency(connect.IdempotencyNoSideEffects),
	)
	req := connect.NewRequest(&emptypb.Empty{})
	req.Header().Set("Authorization", "Bearer token")

	_, err := client.CallUnary(s.T().Context(), req)

	s.Require().NoError(err)
	s.Equal([]string{http.MethodPost}, captured)
}
