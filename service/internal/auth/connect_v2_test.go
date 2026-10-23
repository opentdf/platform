package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"sync/atomic"

	"connectrpc.com/connect"
	connectv2 "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	"github.com/opentdf/platform/protocol/go/kas/kasconnectv2"
	sdkauth "github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/httputil"
	"github.com/opentdf/platform/service/internal/server/memhttp"
	"github.com/opentdf/platform/service/logger"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/opentdf/platform/service/pkg/authz"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

// fakeAccessServiceV2 records what a connect-go v2 KAS handler sees.
type fakeAccessServiceV2 struct {
	kasconnectv2.UnimplementedAccessServiceHandler

	rewrapCalls    atomic.Int32
	clientID       string
	authzClientID  string
	dpopKey        jwk.Key
	publicRoute    bool
	publicRouteSet bool
}

func (f *fakeAccessServiceV2) PublicKey(ctx context.Context, _ *kas.PublicKeyRequest) (*kas.PublicKeyResponse, error) {
	f.publicRoute, f.publicRouteSet = ctxAuth.PublicRouteFromContext(ctx)
	return &kas.PublicKeyResponse{}, nil
}

func (f *fakeAccessServiceV2) Rewrap(ctx context.Context, _ *kas.RewrapRequest) (*kas.RewrapResponse, error) {
	f.rewrapCalls.Add(1)
	f.dpopKey = ctxAuth.GetJWKFromContext(ctx, logger.CreateTestLogger())
	inbound := true
	f.clientID, _ = ctxAuth.GetClientIDFromContext(ctx, inbound)
	f.authzClientID, _ = authz.ClientIDFromContext(ctx)
	return &kas.RewrapResponse{}, nil
}

// countingBody counts the request body bytes a handler reads.
type countingBody struct {
	io.ReadCloser

	read *atomic.Int64
}

func (b countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.read.Add(int64(n))
	return n, err
}

// newV2Server serves server over an in-memory transport and counts the
// request body bytes the transport reads.
func (s *AuthSuite) newV2Server(server *connectv2.Server, opts ...connecthttp.Option) (*memhttp.Server, *atomic.Int64) {
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server, opts...)
	var read atomic.Int64
	srv := memhttp.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = countingBody{ReadCloser: r.Body, read: &read}
		mux.ServeHTTP(w, r)
	}))
	s.T().Cleanup(func() { _ = srv.Close() })
	return srv, &read
}

// newV2KASServer serves a fake connect-go v2 KAS behind the v2 authn and authz
// interceptors, wired the way the platform wires external v2 services.
func (s *AuthSuite) newV2KASServer(auth *Authentication, fake kasconnectv2.AccessServiceHandler, opts ...connecthttp.Option) (*memhttp.Server, *atomic.Int64) {
	server := connectv2.NewServer(auth.ConnectAuthNInterceptorV2(), auth.ConnectAuthZInterceptorV2())
	kasconnectv2.RegisterAccessServiceHandler(server, fake)
	return s.newV2Server(server, opts...)
}

func (s *AuthSuite) Test_ConnectAuthNInterceptorV2_RejectsBeforeReadingBody() {
	oversized := paddedProtoMessage(s.T(), 8<<20)
	gzipped := http.Header{}
	gzipped.Set("Content-Encoding", "gzip")
	cases := []struct {
		name   string
		body   []byte
		header http.Header
	}{
		{"plain", oversized, nil},
		{"gzip", gzipBytes(s.T(), oversized), gzipped},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			fake := &fakeAccessServiceV2{}
			server, read := s.newV2KASServer(s.auth, fake)

			resp := postConnectUnary(s.T(), server, tc.body, tc.header)

			s.Equal(http.StatusUnauthorized, resp.StatusCode)
			s.Zero(read.Load(), "the body must not be read before authentication")
			s.Zero(fake.rewrapCalls.Load())
		})
	}
}

func (s *AuthSuite) Test_ConnectAuthNInterceptorV2_ReadLimitAppliesAfterAuthentication() {
	const limit = 1024
	acceptAnyToken(s.auth, s.standardRoleToken())
	s.T().Cleanup(func() { s.auth._testCheckTokenFunc = nil })

	authenticated := http.Header{}
	authenticated.Set("Authorization", "Bearer token")
	authenticatedGzipped := authenticated.Clone()
	authenticatedGzipped.Set("Content-Encoding", "gzip")
	oversized := paddedProtoMessage(s.T(), 2*limit)
	cases := []struct {
		name       string
		body       []byte
		header     http.Header
		wantStatus int
		wantCalled bool
	}{
		{"authenticated oversized", oversized, authenticated, http.StatusTooManyRequests, false},
		{"authenticated oversized gzip", gzipBytes(s.T(), oversized), authenticatedGzipped, http.StatusTooManyRequests, false},
		{"authenticated at the limit", paddedProtoMessage(s.T(), limit), authenticated, http.StatusOK, true},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			fake := &fakeAccessServiceV2{}
			server, _ := s.newV2KASServer(s.auth, fake, connecthttp.WithReadMaxBytes(limit))

			resp := postConnectUnary(s.T(), server, tc.body, tc.header)

			s.Equal(tc.wantStatus, resp.StatusCode)
			s.Equal(tc.wantCalled, fake.rewrapCalls.Load() == 1)
		})
	}
}

// Test_ConnectAuthNInterceptorV2_DPoPChallengesReachClients checks that v2
// rejections carry the DPoP challenge metadata that v1 rejections carry.
func (s *AuthSuite) Test_ConnectAuthNInterceptorV2_DPoPChallengesReachClients() {
	protocols := []struct {
		name string
		opts []connect.ClientOption
	}{
		{"connect", nil},
		{"grpc", []connect.ClientOption{connect.WithGRPC()}},
		{"grpcweb", []connect.ClientOption{connect.WithGRPCWeb()}},
	}
	cases := []struct {
		name          string
		requireNonce  bool
		checkErr      error
		wantChallenge string
		wantNonce     bool
	}{
		{"nonce error", true, &DPoPNonceError{Message: "nonce required"}, `DPoP error="use_dpop_nonce"`, true},
		{"proof error", false, &DPoPProofError{err: errors.New("bad proof")}, `DPoP error="invalid_dpop_proof"`, false},
		{"proof error with required nonce", true, &DPoPProofError{err: errors.New("bad proof")}, `DPoP error="invalid_dpop_proof"`, true},
	}
	for _, protocol := range protocols {
		for _, tc := range cases {
			s.Run(protocol.name+"/"+tc.name, func() {
				auth := s.newAuthDPoP(tc.requireNonce)
				auth._testCheckTokenFunc = func(context.Context, []string, receiverInfo, []string) (jwt.Token, context.Context, error) {
					return nil, nil, tc.checkErr
				}
				fake := &fakeAccessServiceV2{}
				server, _ := s.newV2KASServer(auth, fake)
				client := kasconnect.NewAccessServiceClient(server.Client(), memhttpBaseURL(server), protocol.opts...)
				req := connect.NewRequest(&kas.RewrapRequest{})
				req.Header().Set("Authorization", "DPoP token")
				req.Header().Set("DPoP", "proof")

				_, err := client.Rewrap(s.T().Context(), req)

				var connectErr *connect.Error
				s.Require().ErrorAs(err, &connectErr)
				s.Equal(connect.CodeUnauthenticated, connectErr.Code())
				s.Equal(tc.wantChallenge, connectErr.Meta().Get("WWW-Authenticate"))
				s.Equal(tc.wantNonce, connectErr.Meta().Get("DPoP-Nonce") != "")
				s.Zero(fake.rewrapCalls.Load())
			})
		}
	}
}

// Test_ConnectAuthNInterceptorV2_DPoPEndToEnd sends a real DPoP-bound request
// through the v2 interceptors.
func (s *AuthSuite) Test_ConnectAuthNInterceptorV2_DPoPEndToEnd() {
	dpopKeyRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	dpopKey, err := jwk.FromRaw(dpopKeyRaw)
	s.Require().NoError(err)
	s.Require().NoError(dpopKey.Set(jwk.AlgorithmKey, jwa.RS256))

	tok := s.standardRoleToken()
	thumbprint, err := dpopKey.Thumbprint(crypto.SHA256)
	s.Require().NoError(err)
	cnf := map[string]string{"jkt": base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(thumbprint)}
	s.Require().NoError(tok.Set("cnf", cnf))
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))
	s.Require().NoError(err)

	fake := &fakeAccessServiceV2{}
	server, _ := s.newV2KASServer(s.auth, fake)
	addingInterceptor := sdkauth.NewTokenAddingInterceptorWithClient(&FakeTokenSource{
		key:         dpopKey,
		accessToken: string(signedTok),
	}, httputil.SafeHTTPClientWithTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12,
	}))
	client := kasconnect.NewAccessServiceClient(
		server.Client(),
		memhttpBaseURL(server),
		connect.WithInterceptors(addingInterceptor.AddCredentialsConnect()),
	)

	_, err = client.Rewrap(s.T().Context(), connect.NewRequest(&kas.RewrapRequest{}))

	s.Require().NoError(err)
	s.Equal(int32(1), fake.rewrapCalls.Load())
	s.Equal("client-gate", fake.clientID)
	s.Equal("client-gate", fake.authzClientID)
	s.NotNil(fake.dpopKey)
}

func (s *AuthSuite) Test_ConnectAuthNInterceptorV2_BindsHTTPMethod() {
	tok := s.standardRoleToken()
	var captured []string
	s.auth._testCheckTokenFunc = func(ctx context.Context, _ []string, ri receiverInfo, _ []string) (jwt.Token, context.Context, error) {
		captured = ri.m
		return tok, ctx, nil
	}
	s.T().Cleanup(func() { s.auth._testCheckTokenFunc = nil })

	server := connectv2.NewServer(s.auth.ConnectAuthNInterceptorV2())
	server.Register(connectv2.Method{
		Spec: connectv2.Spec{
			Procedure:        gateTestGetProc,
			StreamType:       connectv2.StreamTypeUnary,
			IdempotencyLevel: connectv2.IdempotencyNoSideEffects,
		},
		Handler: func(_ context.Context, _ connectv2.Spec, stream connectv2.ServerStream) error {
			var req emptypb.Empty
			if err := stream.Receive(&req); err != nil {
				return err
			}
			return stream.Send(&emptypb.Empty{})
		},
	})
	srv, _ := s.newV2Server(server)
	cases := []struct {
		name string
		opts []connect.ClientOption
		want string
	}{
		{"get", []connect.ClientOption{connect.WithHTTPGet()}, http.MethodGet},
		{"post", nil, http.MethodPost},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			captured = nil
			opts := append([]connect.ClientOption{connect.WithIdempotency(connect.IdempotencyNoSideEffects)}, tc.opts...)
			client := connect.NewClient[emptypb.Empty, emptypb.Empty](srv.Client(), memhttpBaseURL(srv)+gateTestGetProc, opts...)
			req := connect.NewRequest(&emptypb.Empty{})
			req.Header().Set("Authorization", "Bearer token")

			_, err := client.CallUnary(s.T().Context(), req)

			s.Require().NoError(err)
			s.Equal([]string{tc.want}, captured)
		})
	}
}

func (s *AuthSuite) Test_ConnectAuthNInterceptorV2_PublicRouteWithoutToken() {
	fake := &fakeAccessServiceV2{}
	server, _ := s.newV2KASServer(s.auth, fake)
	client := kasconnect.NewAccessServiceClient(server.Client(), memhttpBaseURL(server))

	_, err := client.PublicKey(s.T().Context(), connect.NewRequest(&kas.PublicKeyRequest{}))

	s.Require().NoError(err)
	s.True(fake.publicRouteSet)
	s.True(fake.publicRoute)
}

func (s *AuthSuite) Test_ConnectAuthNInterceptorV2_Streaming() {
	newServer := func(auth *Authentication, called *atomic.Bool) *memhttp.Server {
		server := connectv2.NewServer(auth.ConnectAuthNInterceptorV2())
		server.Register(connectv2.Method{
			Spec: connectv2.Spec{Procedure: gateTestUploadProc, StreamType: connectv2.StreamTypeClient},
			Handler: func(_ context.Context, _ connectv2.Spec, stream connectv2.ServerStream) error {
				called.Store(true)
				for {
					var msg emptypb.Empty
					if err := stream.Receive(&msg); err != nil {
						if errors.Is(err, io.EOF) {
							break
						}
						return err
					}
				}
				return stream.Send(&emptypb.Empty{})
			},
		})
		srv, _ := s.newV2Server(server)
		return srv
	}

	s.Run("unauthenticated stream is rejected before the handler", func() {
		var called atomic.Bool
		server := newServer(s.auth, &called)
		client := connect.NewClient[emptypb.Empty, emptypb.Empty](server.Client(), memhttpBaseURL(server)+gateTestUploadProc)

		stream := client.CallClientStream(s.T().Context())
		_ = stream.Send(&emptypb.Empty{})
		_, err := stream.CloseAndReceive()

		s.Equal(connect.CodeUnauthenticated, connect.CodeOf(err))
		s.False(called.Load())
	})

	s.Run("authenticated stream gets a fresh nonce", func() {
		auth := s.newAuthDPoP(true)
		tok := s.standardRoleToken()
		var captured []string
		auth._testCheckTokenFunc = func(ctx context.Context, _ []string, ri receiverInfo, _ []string) (jwt.Token, context.Context, error) {
			captured = ri.m
			return tok, ctxAuth.ContextWithAuthNInfo(ctx, nil, tok, "raw-token"), nil
		}
		var called atomic.Bool
		server := newServer(auth, &called)
		client := connect.NewClient[emptypb.Empty, emptypb.Empty](server.Client(), memhttpBaseURL(server)+gateTestUploadProc)

		stream := client.CallClientStream(s.T().Context())
		stream.RequestHeader().Set("Authorization", "DPoP token")
		stream.RequestHeader().Set("DPoP", "proof")
		s.Require().NoError(stream.Send(&emptypb.Empty{}))
		res, err := stream.CloseAndReceive()

		s.Require().NoError(err)
		s.True(called.Load())
		s.NotEmpty(res.Header().Get("DPoP-Nonce"))
		s.Equal([]string{http.MethodPost}, captured)
	})
}

func (s *AuthSuite) Test_IPCServerInterceptorV2() {
	var gotClientID string
	var gotRawToken []string
	server := connectv2.NewServer(s.auth.IPCServerInterceptorV2())
	server.Register(connectv2.Method{
		Spec: connectv2.Spec{Procedure: gateTestGetProc, StreamType: connectv2.StreamTypeUnary},
		Handler: func(ctx context.Context, _ connectv2.Spec, stream connectv2.ServerStream) error {
			var req emptypb.Empty
			if err := stream.Receive(&req); err != nil {
				return err
			}
			inbound := true
			gotClientID, _ = ctxAuth.GetClientIDFromContext(ctx, inbound)
			if md, ok := metadata.FromIncomingContext(ctx); ok {
				gotRawToken = md.Get(ctxAuth.AccessTokenKey)
			}
			return stream.Send(&emptypb.Empty{})
		},
	})
	srv, _ := s.newV2Server(server)
	client := connect.NewClient[emptypb.Empty, emptypb.Empty](srv.Client(), memhttpBaseURL(srv)+gateTestGetProc)
	req := connect.NewRequest(&emptypb.Empty{})
	req.Header().Set(canonicalIPCHeaderClientID, "client-ipc")

	_, err := client.CallUnary(s.T().Context(), req)

	s.Require().NoError(err)
	s.Equal("client-ipc", gotClientID)
	s.Empty(gotRawToken)

	s.Run("reauth route without credentials is rejected", func() {
		reauthServer := connectv2.NewServer(s.auth.IPCServerInterceptorV2())
		kasconnectv2.RegisterAccessServiceHandler(reauthServer, &fakeAccessServiceV2{})
		reauthSrv, _ := s.newV2Server(reauthServer)
		kasClient := kasconnect.NewAccessServiceClient(reauthSrv.Client(), memhttpBaseURL(reauthSrv))

		_, err := kasClient.Rewrap(s.T().Context(), connect.NewRequest(&kas.RewrapRequest{}))

		s.Equal(connect.CodeUnauthenticated, connect.CodeOf(err))
	})
}
