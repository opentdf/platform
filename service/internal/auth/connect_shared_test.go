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
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/creasty/defaults"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	sdkauth "github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/httputil"
	internalauthz "github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/internal/server/memhttp"
	"github.com/opentdf/platform/service/logger"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/opentdf/platform/service/pkg/authz"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	rewrapProcedure    = "/kas.AccessService/Rewrap"
	gateTestGetProc    = "/gate.test.v1.GateService/Get"
	gateTestUploadProc = "/gate.test.v1.GateService/Upload"
)

// connectStack builds servers with the platform's Connect authentication
// wiring for one connect-go version, so shared scenarios run against both.
type connectStack struct {
	name string
	// kas serves a fake KAS behind authentication and authorization. A
	// positive readMaxBytes overrides the default read limit.
	kas func(auth *Authentication, readMaxBytes int) (*memhttp.Server, *kasRecord)
	// get serves gateTestGetProc, an idempotent unary procedure, behind
	// authentication.
	get func(auth *Authentication) *memhttp.Server
	// upload serves gateTestUploadProc, a client-streaming procedure, behind
	// authentication and records whether its handler ran.
	upload func(auth *Authentication, called *atomic.Bool) *memhttp.Server
	// grpcDropsChallenge reports that gRPC clients never receive
	// WWW-Authenticate, because Go's HTTP/2 server drops it from the trailers
	// that carry gRPC error metadata.
	grpcDropsChallenge bool
}

func (s *AuthSuite) connectStacks() []connectStack {
	return []connectStack{
		{
			name:               "v1",
			kas:                s.newGatedKASServer,
			get:                s.newGatedGetServer,
			upload:             s.newGatedUploadServer,
			grpcDropsChallenge: true,
		},
		{
			name:   "v2",
			kas:    s.newV2KASServer,
			get:    s.newV2GetServer,
			upload: s.newV2UploadServer,
		},
	}
}

// connectTestProtocol is a wire protocol the platform serves.
type connectTestProtocol struct {
	name string
	grpc bool
	opts []connect.ClientOption
}

func connectTestProtocols() []connectTestProtocol {
	return []connectTestProtocol{
		{name: "connect"},
		{name: "grpc", grpc: true, opts: []connect.ClientOption{connect.WithGRPC()}},
		{name: "grpcweb", opts: []connect.ClientOption{connect.WithGRPCWeb()}},
	}
}

// dpopRejectionCase is a failed token check and the DPoP metadata clients
// should receive for it.
type dpopRejectionCase struct {
	name          string
	requireNonce  bool
	checkErr      error
	wantChallenge string
	wantNonce     bool
}

func dpopRejectionCases() []dpopRejectionCase {
	return []dpopRejectionCase{
		{"nonce error", true, &DPoPNonceError{Message: "nonce required"}, `DPoP error="use_dpop_nonce"`, true},
		{"proof error", false, &DPoPProofError{err: errors.New("bad proof")}, `DPoP error="invalid_dpop_proof"`, false},
		{"proof error with required nonce", true, &DPoPProofError{err: errors.New("bad proof")}, `DPoP error="invalid_dpop_proof"`, true},
	}
}

// rejectingAuth returns a DPoP-enforcing Authentication whose token check
// fails with tc.checkErr.
func (s *AuthSuite) rejectingAuth(tc dpopRejectionCase) *Authentication {
	auth := s.newAuthDPoP(tc.requireNonce)
	auth._testCheckTokenFunc = func(context.Context, []string, receiverInfo, []string) (jwt.Token, context.Context, error) {
		return nil, nil, tc.checkErr
	}
	return auth
}

// newAuthRequiringNonce returns a DPoP-enforcing Authentication that requires
// nonces and authorizes with the default policy.
func (s *AuthSuite) newAuthRequiringNonce() *Authentication {
	var policy internalauthz.PolicyConfig
	s.Require().NoError(defaults.Set(&policy))
	auth, err := NewAuthenticator(
		s.T().Context(),
		Config{
			AuthNConfig: AuthNConfig{
				Issuer:    s.server.URL,
				Audience:  "test",
				DPoPSkew:  time.Hour,
				TokenSkew: time.Minute,
				Policy:    policy,
				DPoP: DPoPConfig{
					Enforce:         true,
					RequireNonce:    true,
					NonceExpiration: 5 * time.Minute,
				},
			},
		},
		logger.CreateTestLogger(),
		func(_ string, _ any) error { return nil },
	)
	s.Require().NoError(err)
	return auth
}

// kasRecord is what a fake KAS server observed, for either connect-go version.
type kasRecord struct {
	bodyRead       atomic.Int64 // request body bytes read from the transport
	rewraps        atomic.Int32
	failRewrap     atomic.Bool // makes Rewrap return FailedPrecondition
	clientID       string
	authzClientID  string
	dpopKey        jwk.Key
	publicRoute    bool
	publicRouteSet bool
}

// recordRewrap records a Rewrap call and reports whether the call should fail.
func (r *kasRecord) recordRewrap(ctx context.Context) bool {
	r.rewraps.Add(1)
	r.dpopKey = ctxAuth.GetJWKFromContext(ctx, logger.CreateTestLogger())
	inbound := true
	r.clientID, _ = ctxAuth.GetClientIDFromContext(ctx, inbound)
	r.authzClientID, _ = authz.ClientIDFromContext(ctx)
	return r.failRewrap.Load()
}

func (r *kasRecord) recordPublicKey(ctx context.Context) {
	r.publicRoute, r.publicRouteSet = ctxAuth.PublicRouteFromContext(ctx)
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

// serve serves handler over an in-memory transport and adds the request body
// bytes the handler reads to bodyRead.
func (s *AuthSuite) serve(handler http.Handler, bodyRead *atomic.Int64) *memhttp.Server {
	server := memhttp.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = countingBody{ReadCloser: r.Body, read: bodyRead}
		handler.ServeHTTP(w, r)
	}))
	s.T().Cleanup(func() { _ = server.Close() })
	return server
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

// postConnectUnary sends a raw Connect unary Rewrap request with a binary protobuf body.
func postConnectUnary(t *testing.T, server *memhttp.Server, body []byte, header http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, memhttpBaseURL(server)+rewrapProcedure, bytes.NewReader(body))
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

// rewrapError calls Rewrap with DPoP credentials and returns the Connect error.
func (s *AuthSuite) rewrapError(server *memhttp.Server, opts ...connect.ClientOption) *connect.Error {
	client := kasconnect.NewAccessServiceClient(server.Client(), memhttpBaseURL(server), opts...)
	req := connect.NewRequest(&kas.RewrapRequest{})
	req.Header().Set("Authorization", "DPoP token")
	req.Header().Set("DPoP", "proof")
	_, err := client.Rewrap(s.T().Context(), req)
	var connectErr *connect.Error
	s.Require().ErrorAs(err, &connectErr)
	return connectErr
}

// Test_ConnectAuthN_RejectsBeforeReadingBody checks that unauthenticated
// requests are rejected from their headers, before any of the body is read.
func (s *AuthSuite) Test_ConnectAuthN_RejectsBeforeReadingBody() {
	oversized := paddedProtoMessage(s.T(), 8<<20)
	gzipped := http.Header{}
	gzipped.Set("Content-Encoding", "gzip")
	cases := []struct {
		name   string
		body   []byte
		header http.Header
	}{
		{"undecodable", []byte{0xff, 0xff, 0xff, 0xff}, nil},
		{"oversized", oversized, nil},
		{"oversized gzip", gzipBytes(s.T(), oversized), gzipped},
	}
	for _, stack := range s.connectStacks() {
		for _, tc := range cases {
			s.Run(stack.name+"/"+tc.name, func() {
				server, record := stack.kas(s.auth, 0)

				resp := postConnectUnary(s.T(), server, tc.body, tc.header)

				s.Equal(http.StatusUnauthorized, resp.StatusCode)
				s.Zero(record.bodyRead.Load(), "the body must not be read before authentication")
				s.Zero(record.rewraps.Load())
			})
		}
	}
}

func (s *AuthSuite) Test_ConnectAuthN_ReadLimitAppliesAfterAuthentication() {
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
	for _, stack := range s.connectStacks() {
		for _, tc := range cases {
			s.Run(stack.name+"/"+tc.name, func() {
				server, record := stack.kas(s.auth, limit)

				resp := postConnectUnary(s.T(), server, tc.body, tc.header)

				s.Equal(tc.wantStatus, resp.StatusCode)
				s.Equal(tc.wantCalled, record.rewraps.Load() == 1)
			})
		}
	}
}

// Test_ConnectAuthN_DPoPChallengesReachClients checks that authentication
// rejections carry DPoP challenge metadata for every protocol the platform
// serves.
func (s *AuthSuite) Test_ConnectAuthN_DPoPChallengesReachClients() {
	for _, stack := range s.connectStacks() {
		for _, protocol := range connectTestProtocols() {
			for _, tc := range dpopRejectionCases() {
				s.Run(stack.name+"/"+protocol.name+"/"+tc.name, func() {
					server, record := stack.kas(s.rejectingAuth(tc), 0)

					connectErr := s.rewrapError(server, protocol.opts...)

					s.Equal(connect.CodeUnauthenticated, connectErr.Code())
					if !protocol.grpc || !stack.grpcDropsChallenge {
						s.Equal(tc.wantChallenge, connectErr.Meta().Get("WWW-Authenticate"))
					}
					s.Equal(tc.wantNonce, connectErr.Meta().Get("DPoP-Nonce") != "")
					s.Zero(record.rewraps.Load())
				})
			}
		}
	}
}

// Test_ConnectAuthN_NonceOnUnaryResponses checks that, with nonces required,
// a unary call returns a fresh DPoP nonce whether the handler succeeds or
// fails.
func (s *AuthSuite) Test_ConnectAuthN_NonceOnUnaryResponses() {
	for _, stack := range s.connectStacks() {
		for _, protocol := range connectTestProtocols() {
			for _, fail := range []bool{false, true} {
				outcome := "success"
				if fail {
					outcome = "handler error"
				}
				s.Run(stack.name+"/"+protocol.name+"/"+outcome, func() {
					auth := s.newAuthRequiringNonce()
					acceptAnyToken(auth, s.standardRoleToken())
					server, record := stack.kas(auth, 0)
					record.failRewrap.Store(fail)
					client := kasconnect.NewAccessServiceClient(server.Client(), memhttpBaseURL(server), protocol.opts...)
					req := connect.NewRequest(&kas.RewrapRequest{})
					req.Header().Set("Authorization", "DPoP token")
					req.Header().Set("DPoP", "proof")

					res, err := client.Rewrap(s.T().Context(), req)

					s.Equal(int32(1), record.rewraps.Load())
					if !fail {
						s.Require().NoError(err)
						s.NotEmpty(res.Header().Get("DPoP-Nonce"))
						return
					}
					var connectErr *connect.Error
					s.Require().ErrorAs(err, &connectErr)
					s.Equal(connect.CodeFailedPrecondition, connectErr.Code())
					s.NotEmpty(connectErr.Meta().Get("DPoP-Nonce"))
				})
			}
		}
	}
}

// Test_ConnectAuthN_DPoPEndToEnd sends a real DPoP-bound request through each
// stack. On v1 the interceptor must reuse the gate's authentication, because
// validating the same proof again would fail replay detection.
func (s *AuthSuite) Test_ConnectAuthN_DPoPEndToEnd() {
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

	for _, stack := range s.connectStacks() {
		s.Run(stack.name, func() {
			server, record := stack.kas(s.auth, 0)
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

			_, err := client.Rewrap(s.T().Context(), connect.NewRequest(&kas.RewrapRequest{}))

			s.Require().NoError(err)
			s.Equal(int32(1), record.rewraps.Load())
			s.Equal("client-gate", record.clientID)
			s.Equal("client-gate", record.authzClientID)
			s.NotNil(record.dpopKey)
		})
	}
}

func (s *AuthSuite) Test_ConnectAuthN_BindsHTTPMethod() {
	tok := s.standardRoleToken()
	var captured []string
	s.auth._testCheckTokenFunc = func(ctx context.Context, _ []string, ri receiverInfo, _ []string) (jwt.Token, context.Context, error) {
		captured = ri.m
		return tok, ctx, nil
	}
	s.T().Cleanup(func() { s.auth._testCheckTokenFunc = nil })

	cases := []struct {
		name string
		opts []connect.ClientOption
		want string
	}{
		{"get", []connect.ClientOption{connect.WithHTTPGet()}, http.MethodGet},
		{"post", nil, http.MethodPost},
	}
	for _, stack := range s.connectStacks() {
		for _, tc := range cases {
			s.Run(stack.name+"/"+tc.name, func() {
				captured = nil
				server := stack.get(s.auth)
				opts := append([]connect.ClientOption{connect.WithIdempotency(connect.IdempotencyNoSideEffects)}, tc.opts...)
				client := connect.NewClient[emptypb.Empty, emptypb.Empty](server.Client(), memhttpBaseURL(server)+gateTestGetProc, opts...)
				req := connect.NewRequest(&emptypb.Empty{})
				req.Header().Set("Authorization", "Bearer token")

				_, err := client.CallUnary(s.T().Context(), req)

				s.Require().NoError(err)
				s.Equal([]string{tc.want}, captured)
			})
		}
	}
}

func (s *AuthSuite) Test_ConnectAuthN_PublicRouteWithoutToken() {
	for _, stack := range s.connectStacks() {
		s.Run(stack.name, func() {
			server, record := stack.kas(s.auth, 0)
			client := kasconnect.NewAccessServiceClient(server.Client(), memhttpBaseURL(server))

			_, err := client.PublicKey(s.T().Context(), connect.NewRequest(&kas.PublicKeyRequest{}))

			s.Require().NoError(err)
			s.True(record.publicRouteSet)
			s.True(record.publicRoute)
		})
	}
}

func (s *AuthSuite) Test_ConnectAuthN_Streaming() {
	for _, stack := range s.connectStacks() {
		s.Run(stack.name+"/unauthenticated stream is rejected before the handler", func() {
			var called atomic.Bool
			server := stack.upload(s.auth, &called)
			client := connect.NewClient[emptypb.Empty, emptypb.Empty](server.Client(), memhttpBaseURL(server)+gateTestUploadProc)

			stream := client.CallClientStream(s.T().Context())
			_ = stream.Send(&emptypb.Empty{})
			_, err := stream.CloseAndReceive()

			s.Equal(connect.CodeUnauthenticated, connect.CodeOf(err))
			s.False(called.Load())
		})

		s.Run(stack.name+"/authenticated stream gets a fresh nonce", func() {
			auth := s.newAuthDPoP(true)
			tok := s.standardRoleToken()
			var captured []string
			auth._testCheckTokenFunc = func(ctx context.Context, _ []string, ri receiverInfo, _ []string) (jwt.Token, context.Context, error) {
				captured = ri.m
				return tok, ctxAuth.ContextWithAuthNInfo(ctx, nil, tok, "raw-token"), nil
			}
			var called atomic.Bool
			server := stack.upload(auth, &called)
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
}
