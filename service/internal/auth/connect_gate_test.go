package auth

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	sdkauth "github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/httputil"
	"github.com/opentdf/platform/service/internal/server/memhttp"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	rewrapProcedure    = "/kas.AccessService/Rewrap"
	gateTestGetProc    = "/gate.test.v1.GateService/Get"
	gateTestUploadProc = "/gate.test.v1.GateService/Upload"
)

// countingAccessServer counts Rewrap calls so tests can prove a rejected
// request never reached the service.
type countingAccessServer struct {
	FakeAccessServiceServer
	rewrapCalls atomic.Int32
}

func (c *countingAccessServer) Rewrap(ctx context.Context, req *connect.Request[kas.RewrapRequest]) (*connect.Response[kas.RewrapResponse], error) {
	c.rewrapCalls.Add(1)
	return c.FakeAccessServiceServer.Rewrap(ctx, req)
}

// memhttpBaseURL returns the base URL clients use to reach an in-memory server.
func memhttpBaseURL(server *memhttp.Server) string {
	return server.Listener.Addr().String()
}

// recordHTTPMethod mirrors the platform router, which stores the HTTP method
// for the authentication gate.
func recordHTTPMethod(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(ContextWithHTTPMethod(r.Context(), r.Method)))
	})
}

// newGatedKASServer serves fake KAS behind the authentication gate and the
// authn/authz interceptors, wired the way the platform wires external handlers.
func (s *AuthSuite) newGatedKASServer(auth *Authentication, fake kasconnect.AccessServiceHandler, opts ...connect.HandlerOption) *memhttp.Server {
	handlerOpts := append([]connect.HandlerOption{
		connect.WithRequestGate(auth.ConnectAuthNRequestGate()),
		connect.WithInterceptors(auth.ConnectAuthNInterceptor(), auth.ConnectAuthZInterceptor()),
	}, opts...)
	mux := http.NewServeMux()
	path, handler := kasconnect.NewAccessServiceHandler(fake, handlerOpts...)
	mux.Handle(path, handler)
	server := memhttp.New(recordHTTPMethod(mux))
	s.T().Cleanup(func() { _ = server.Close() })
	return server
}

// newInterceptorKASServer serves fake KAS behind the authn/authz interceptors
// only, the wiring that existed before the authentication gate.
func (s *AuthSuite) newInterceptorKASServer(auth *Authentication, fake kasconnect.AccessServiceHandler) *memhttp.Server {
	mux := http.NewServeMux()
	path, handler := kasconnect.NewAccessServiceHandler(fake, connect.WithInterceptors(auth.ConnectAuthNInterceptor(), auth.ConnectAuthZInterceptor()))
	mux.Handle(path, handler)
	server := memhttp.New(mux)
	s.T().Cleanup(func() { _ = server.Close() })
	return server
}

// standardRoleToken returns an unsigned token whose claims satisfy the default
// authorization policy for KAS rewrap.
func (s *AuthSuite) standardRoleToken() jwt.Token {
	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", s.server.URL))
	s.Require().NoError(tok.Set("aud", "test"))
	s.Require().NoError(tok.Set("cid", "client-gate"))
	s.Require().NoError(tok.Set("realm_access", map[string][]string{"roles": {"opentdf-standard"}}))
	return tok
}

// acceptAnyToken stubs token validation so any Authorization header
// authenticates as tok.
func acceptAnyToken(auth *Authentication, tok jwt.Token) {
	auth._testCheckTokenFunc = func(ctx context.Context, _ []string, _ receiverInfo, _ []string) (jwt.Token, context.Context, error) {
		return tok, ctxAuth.ContextWithAuthNInfo(ctx, nil, tok, "raw-token"), nil
	}
}

// paddedProtoMessage returns a serialized protobuf message of exactly size bytes
// holding one unknown length-delimited field, which every message type accepts.
func paddedProtoMessage(t *testing.T, size int) []byte {
	t.Helper()
	const fieldNum = protowire.Number(1000)
	tagLen := protowire.SizeTag(fieldNum)
	for lenLen := 1; lenLen <= binary.MaxVarintLen32; lenLen++ {
		payloadLen := size - tagLen - lenLen
		if payloadLen >= 0 && protowire.SizeVarint(uint64(payloadLen)) == lenLen {
			b := protowire.AppendTag(nil, fieldNum, protowire.BytesType)
			b = protowire.AppendBytes(b, make([]byte, payloadLen))
			require.Len(t, b, size)
			return b
		}
	}
	t.Fatalf("cannot pad a protobuf message to %d bytes", size)
	return nil
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(b)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// postConnectUnary sends a raw Connect unary request with a binary protobuf body.
func postConnectUnary(t *testing.T, server *memhttp.Server, procedure string, body []byte, header http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, memhttpBaseURL(server)+procedure, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/proto")
	req.Header.Set("Connect-Protocol-Version", "1")
	for key, values := range header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
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

func (s *AuthSuite) Test_ConnectAuthNRequestGate_RejectsBeforeDecode() {
	undecodable := []byte{0xff, 0xff, 0xff, 0xff}

	s.Run("gate returns 401 without decoding", func() {
		fake := &countingAccessServer{}
		server := s.newGatedKASServer(s.auth, fake)

		resp := postConnectUnary(s.T(), server, rewrapProcedure, undecodable, nil)

		s.Equal(http.StatusUnauthorized, resp.StatusCode)
		s.Zero(fake.rewrapCalls.Load())
	})

	s.Run("interceptors alone decode first", func() {
		fake := &countingAccessServer{}
		server := s.newInterceptorKASServer(s.auth, fake)

		resp := postConnectUnary(s.T(), server, rewrapProcedure, undecodable, nil)

		s.Equal(http.StatusBadRequest, resp.StatusCode, "without the gate the body is unmarshaled before authentication")
		s.Zero(fake.rewrapCalls.Load())
	})
}

func (s *AuthSuite) Test_ConnectAuthNRequestGate_RunsBeforeReadLimit() {
	const limit = 1024
	acceptAnyToken(s.auth, s.standardRoleToken())
	s.T().Cleanup(func() { s.auth._testCheckTokenFunc = nil })

	authenticated := http.Header{}
	authenticated.Set("Authorization", "Bearer token")
	gzipped := http.Header{}
	gzipped.Set("Content-Encoding", "gzip")
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
		{"unauthenticated oversized", oversized, nil, http.StatusUnauthorized, false},
		{"unauthenticated oversized gzip", gzipBytes(s.T(), oversized), gzipped, http.StatusUnauthorized, false},
		{"authenticated oversized", oversized, authenticated, http.StatusTooManyRequests, false},
		{"authenticated oversized gzip", gzipBytes(s.T(), oversized), authenticatedGzipped, http.StatusTooManyRequests, false},
		{"authenticated at the limit", paddedProtoMessage(s.T(), limit), authenticated, http.StatusOK, true},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			fake := &countingAccessServer{}
			server := s.newGatedKASServer(s.auth, fake, connect.WithReadMaxBytes(limit))

			resp := postConnectUnary(s.T(), server, rewrapProcedure, tc.body, tc.header)

			s.Equal(tc.wantStatus, resp.StatusCode)
			s.Equal(tc.wantCalled, fake.rewrapCalls.Load() == 1)
		})
	}
}

// Test_ConnectAuthNRequestGate_DPoPChallengesReachClients checks that gate
// rejections carry the same DPoP challenge metadata as interceptor rejections
// for every protocol the platform serves.
func (s *AuthSuite) Test_ConnectAuthNRequestGate_DPoPChallengesReachClients() {
	protocols := []struct {
		name string
		opts []connect.ClientOption
		// Go's HTTP/2 server drops WWW-Authenticate from trailers, where gRPC
		// carries error metadata, with or without the gate.
		challengeDropped bool
	}{
		{"connect", nil, false},
		{"grpc", []connect.ClientOption{connect.WithGRPC()}, true},
		{"grpcweb", []connect.ClientOption{connect.WithGRPCWeb()}, false},
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
				rewrapErr := func(server *memhttp.Server) *connect.Error {
					client := kasconnect.NewAccessServiceClient(server.Client(), memhttpBaseURL(server), protocol.opts...)
					req := connect.NewRequest(&kas.RewrapRequest{})
					req.Header().Set("Authorization", "DPoP token")
					req.Header().Set("DPoP", "proof")
					_, err := client.Rewrap(s.T().Context(), req)
					var connectErr *connect.Error
					s.Require().ErrorAs(err, &connectErr)
					return connectErr
				}

				fake := &countingAccessServer{}
				gateErr := rewrapErr(s.newGatedKASServer(auth, fake))
				interceptorErr := rewrapErr(s.newInterceptorKASServer(auth, &countingAccessServer{}))

				s.Equal(connect.CodeUnauthenticated, gateErr.Code())
				s.Equal(interceptorErr.Code(), gateErr.Code())
				s.Equal(interceptorErr.Meta().Get("WWW-Authenticate"), gateErr.Meta().Get("WWW-Authenticate"))
				if !protocol.challengeDropped {
					s.Equal(tc.wantChallenge, gateErr.Meta().Get("WWW-Authenticate"))
				}
				s.Equal(tc.wantNonce, gateErr.Meta().Get("DPoP-Nonce") != "")
				s.Equal(tc.wantNonce, interceptorErr.Meta().Get("DPoP-Nonce") != "")
				s.Zero(fake.rewrapCalls.Load())
			})
		}
	}
}

// Test_ConnectAuthNRequestGate_DPoPEndToEnd sends a real DPoP-bound request
// through the gate and the interceptors. The interceptor must reuse the gate's
// authentication; validating the same proof again would fail replay detection.
func (s *AuthSuite) Test_ConnectAuthNRequestGate_DPoPEndToEnd() {
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

	fake := &countingAccessServer{}
	server := s.newGatedKASServer(s.auth, fake)

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

func (s *AuthSuite) Test_ConnectAuthNRequestGate_BindsStoredHTTPMethod() {
	tok := s.standardRoleToken()
	var captured []string
	s.auth._testCheckTokenFunc = func(ctx context.Context, _ []string, ri receiverInfo, _ []string) (jwt.Token, context.Context, error) {
		captured = ri.m
		return tok, ctx, nil
	}
	s.T().Cleanup(func() { s.auth._testCheckTokenFunc = nil })

	handler := connect.NewUnaryHandler(
		gateTestGetProc,
		func(context.Context, *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			return connect.NewResponse(&emptypb.Empty{}), nil
		},
		connect.WithIdempotency(connect.IdempotencyNoSideEffects),
		connect.WithRequestGate(s.auth.ConnectAuthNRequestGate()),
	)
	cases := []struct {
		name    string
		handler http.Handler
		want    string
	}{
		{"stored method", recordHTTPMethod(handler), http.MethodGet},
		{"no stored method falls back to POST", handler, http.MethodPost},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			captured = nil
			server := memhttp.New(tc.handler)
			s.T().Cleanup(func() { _ = server.Close() })
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
			s.Equal([]string{tc.want}, captured)
		})
	}
}

func (s *AuthSuite) Test_ConnectAuthNRequestGate_PublicRouteWithoutToken() {
	fake := &countingAccessServer{}
	server := s.newGatedKASServer(s.auth, fake)
	client := kasconnect.NewAccessServiceClient(server.Client(), memhttpBaseURL(server))

	_, err := client.PublicKey(s.T().Context(), connect.NewRequest(&kas.PublicKeyRequest{}))

	s.Require().NoError(err)
	s.True(fake.publicRouteSet)
	s.True(fake.publicRoute)
}

func (s *AuthSuite) Test_ConnectAuthNRequestGate_Streaming() {
	newServer := func(auth *Authentication, called *atomic.Bool) *memhttp.Server {
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
		server := memhttp.New(recordHTTPMethod(handler))
		s.T().Cleanup(func() { _ = server.Close() })
		return server
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
