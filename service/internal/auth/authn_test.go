package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/creasty/defaults"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	sdkauth "github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/httputil"
	"github.com/opentdf/platform/service/internal/server/memhttp"
	"github.com/opentdf/platform/service/logger"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type AuthSuite struct {
	suite.Suite
	server *httptest.Server
	key    jwk.Key
	auth   *Authentication
}

type FakeAccessTokenSource struct {
	dpopKey     jwk.Key
	accessToken string
}

type FakeAccessServiceServer struct {
	clientID    string
	accessToken []string
	dpopKey     jwk.Key
	kas.UnimplementedAccessServiceServer
}

func (f *FakeAccessServiceServer) PublicKey(_ context.Context, _ *connect.Request[kas.PublicKeyRequest]) (*connect.Response[kas.PublicKeyResponse], error) {
	return &connect.Response[kas.PublicKeyResponse]{Msg: &kas.PublicKeyResponse{}}, status.Error(codes.Unauthenticated, "no public key for you")
}

func (f *FakeAccessServiceServer) LegacyPublicKey(_ context.Context, _ *connect.Request[kas.LegacyPublicKeyRequest]) (*connect.Response[wrapperspb.StringValue], error) {
	return &connect.Response[wrapperspb.StringValue]{Msg: &wrapperspb.StringValue{}}, nil
}

func (f *FakeAccessServiceServer) Rewrap(ctx context.Context, req *connect.Request[kas.RewrapRequest]) (*connect.Response[kas.RewrapResponse], error) {
	f.accessToken = req.Header()["Authorization"]
	f.dpopKey = ctxAuth.GetJWKFromContext(ctx, logger.CreateTestLogger())
	inbound := true
	f.clientID, _ = ctxAuth.GetClientIDFromContext(ctx, inbound)

	return &connect.Response[kas.RewrapResponse]{Msg: &kas.RewrapResponse{}}, nil
}

type FakeTokenSource struct {
	key         jwk.Key
	accessToken string
}

func (fts *FakeTokenSource) AccessToken(context.Context, *http.Client) (sdkauth.AccessToken, error) {
	return sdkauth.AccessToken(fts.accessToken), nil
}

func (fts *FakeTokenSource) MakeToken(f func(jwk.Key) ([]byte, error)) ([]byte, error) {
	if fts.key == nil {
		return nil, errors.New("no such key")
	}
	return f(fts.key)
}

func (fake FakeAccessTokenSource) AccessToken() (sdkauth.AccessToken, error) {
	return sdkauth.AccessToken(fake.accessToken), nil
}

func (fake FakeAccessTokenSource) MakeToken(tokenMaker func(jwk.Key) ([]byte, error)) ([]byte, error) {
	return tokenMaker(fake.dpopKey)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func (s *AuthSuite) SetupTest() {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		slog.Error("failed to generate RSA private key", slog.String("error", err.Error()))
		panic(err)
	}

	pubKeyJWK, err := jwk.FromRaw(privKey.PublicKey)
	if err != nil {
		slog.Error("failed to create jwk.Key from RSA public key", slog.String("error", err.Error()))
		panic(err)
	}
	must(pubKeyJWK.Set(jws.KeyIDKey, "test"))
	must(pubKeyJWK.Set(jwk.AlgorithmKey, jwa.RS256))

	// Create a new set with rsa public key
	set := jwk.NewSet()
	must(set.AddKey(pubKeyJWK))

	key, err := jwk.FromRaw(privKey)
	must(err)
	must(key.Set(jws.KeyIDKey, "test"))

	s.key = key

	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/.well-known/openid-configuration" {
			_, err := fmt.Fprintf(w, `{"issuer":"%s","jwks_uri": "%s/jwks"}`, s.server.URL, s.server.URL)
			if err != nil {
				panic(err)
			}
			return
		}
		if r.URL.Path == "/jwks" {
			err := json.NewEncoder(w).Encode(set)
			if err != nil {
				panic(err)
			}
		}
	}))

	policyCfg := PolicyConfig{
		ClientIDClaim: "cid",
	}
	err = defaults.Set(&policyCfg)
	s.Require().NoError(err)

	auth, err := NewAuthenticator(
		context.Background(),
		Config{
			AuthNConfig: AuthNConfig{
				EnforceDPoP: true,
				Issuer:      s.server.URL,
				Audience:    "test",
				DPoPSkew:    time.Hour,
				TokenSkew:   time.Minute,
				Policy:      policyCfg,
			},
			PublicRoutes: []string{
				"/public",
				"/public2/*",
				"/public3/static",
				"/static/*",
				"/static/*/*",
				"/static-doublestar/**",
				"/static-doublestar2/**/*",
				"/static-doublestar3/*/**",
				"/static-doublestar4/x/**",
			},
		},
		logger.CreateTestLogger(),
		func(_ string, _ any) error { return nil },
	)

	s.Require().NoError(err)

	s.auth = auth
}

func (s *AuthSuite) TearDownTest() {
	s.server.Close()
}

func TestAuthSuite(t *testing.T) {
	suite.Run(t, new(AuthSuite))
}

func TestNormalizeUrl(t *testing.T) {
	for _, tt := range []struct {
		origin, path, out string
	}{
		{"http://localhost", "/", "http://localhost/"},
		{"https://localhost", "/somewhere", "https://localhost/somewhere"},
		{"http://localhost", "", "http://localhost"},
	} {
		t.Run(tt.origin+tt.path, func(t *testing.T) {
			u, err := url.Parse(tt.path)
			require.NoError(t, err)
			s := normalizeURL(tt.origin, u)
			assert.Equal(t, s, tt.out)
		})
	}
}

func (s *AuthSuite) Test_IPCUnaryServerInterceptor() {
	// Mock the checkToken method to return a valid token and context
	mockToken := jwt.New()
	err := mockToken.Set("cid", "mockClientID")
	s.Require().NoError(err)

	type contextKey string
	mockCtx := context.WithValue(context.Background(), contextKey("mockKey"), "mockValue")
	s.auth._testCheckTokenFunc = func(_ context.Context, authHeader []string, _ receiverInfo, _ []string) (jwt.Token, context.Context, error) {
		if len(authHeader) == 0 {
			return nil, nil, errors.New("missing authorization header")
		}
		if authHeader[0] != "Bearer valid" {
			return nil, nil, errors.New("unauthenticated")
		}
		return mockToken, mockCtx, nil
	}

	// Test ipcReauthCheck directly
	validAuthHeader := http.Header{}
	validAuthHeader.Add("Authorization", "Bearer valid")
	t1Path := "/kas.AccessService/Rewrap"
	nextCtx, err := s.auth.ipcReauthCheck(context.Background(), t1Path, validAuthHeader)
	s.Require().NoError(err)
	s.Require().NotNil(nextCtx)
	s.Equal("mockValue", nextCtx.Value(contextKey("mockKey")))

	inbound := true
	clientID, err := ctxAuth.GetClientIDFromContext(nextCtx, inbound)
	s.Require().NoError(err)
	s.Equal("mockClientID", clientID)

	// Test with a route not requiring reauthorization
	nextCtx, err = s.auth.ipcReauthCheck(context.Background(), "/kas.AccessService/PublicKey", nil)
	s.Require().NoError(err)
	s.Require().NotNil(nextCtx)
	s.Nil(nextCtx.Value(contextKey("mockKey")))

	// Test with missing authorization header
	_, err = s.auth.ipcReauthCheck(context.Background(), "/kas.AccessService/Rewrap", nil)
	s.Require().Error(err)
	s.Contains(err.Error(), "missing authorization header")

	// Test with invalid token
	unauthHeader := http.Header{}
	unauthHeader.Add("Authorization", "Bearer invalid")
	_, err = s.auth.ipcReauthCheck(context.Background(), "/kas.AccessService/Rewrap", unauthHeader)
	s.Require().Error(err)
	s.Contains(err.Error(), "unauthenticated")
}

func (s *AuthSuite) Test_ConnectUnaryServerInterceptor_ClientIDPropagated() {
	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", s.server.URL))
	s.Require().NoError(tok.Set("aud", "test"))
	// default client ID claim in policy config is 'azp'
	s.Require().NoError(tok.Set("azp", "test-client-id"))
	s.Require().NoError(tok.Set("realm_access", map[string][]string{"roles": {"opentdf-standard"}}))

	policyCfg := new(PolicyConfig)
	err := defaults.Set(policyCfg)
	s.Require().NoError(err)

	authnConfig := AuthNConfig{
		Issuer:   s.server.URL,
		Audience: "test",
		Policy:   *policyCfg,
	}
	config := Config{
		AuthNConfig: authnConfig,
	}
	auth, err := NewAuthenticator(s.T().Context(), config, logger.CreateTestLogger(), func(_ string, _ any) error { return nil })
	s.Require().NoError(err)

	// Sign the token
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))
	s.Require().NoError(err)

	// Create a minimal connect server setup to properly test the interceptor
	// This is necessary because connect requests need proper procedure routing
	interceptor := connect.WithInterceptors(auth.ConnectUnaryServerInterceptor())

	fakeServer := &FakeAccessServiceServer{}
	mux := http.NewServeMux()
	path, handler := kasconnect.NewAccessServiceHandler(fakeServer, interceptor)
	mux.Handle(path, handler)

	server := memhttp.New(mux)
	defer server.Close()

	// Create a connect client that sends a Bearer token
	conn, _ := grpc.NewClient("passthrough://bufconn", grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return server.Listener.DialContext(ctx, "tcp", "http://localhost:8080")
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))

	client := kas.NewAccessServiceClient(conn)

	// Make the request
	_, err = client.Rewrap(metadata.AppendToOutgoingContext(s.T().Context(), "authorization", "Bearer "+string(signedTok)), &kas.RewrapRequest{})
	s.Require().NoError(err)

	// Assert that the client ID was properly extracted and set in the context
	s.Equal("test-client-id", fakeServer.clientID)
}

func (s *AuthSuite) Test_CheckToken_When_JWT_Expired_Expect_Error() {
	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)))

	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	s.NotNil(signedTok)
	s.Require().NoError(err)

	_, _, err = s.auth.checkToken(context.Background(), []string{"Bearer " + string(signedTok)}, receiverInfo{}, nil)
	s.Require().Error(err)
	s.Equal("\"exp\" not satisfied", err.Error())
}

func (s *AuthSuite) Test_MuxHandler_When_Authorization_Header_Missing_Expect_Error() {
	handler := s.auth.MuxHandler(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	s.Equal(http.StatusUnauthorized, rec.Code)
	s.Equal("missing authorization header\n", rec.Body.String())
}

func (s *AuthSuite) Test_UnaryServerInterceptor_When_Authorization_Header_Missing_Expect_Error() {
	// Create the interceptor
	interceptor := s.auth.ConnectUnaryServerInterceptor()

	// Create a dummy next handler
	next := func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		// Return a dummy response
		return connect.NewResponse[string](nil), nil
	}

	// Create a request
	req := connect.NewRequest[string](nil)

	_, err := interceptor(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		return next(ctx, req)
	})(context.Background(), req)

	s.Require().Error(err)

	connectErr := connect.NewError(connect.CodeUnauthenticated, errors.New("missing authorization header"))

	s.Require().ErrorAs(err, &connectErr)
}

func (s *AuthSuite) Test_CheckToken_When_Authorization_Header_Invalid_Expect_Error() {
	_, _, err := s.auth.checkToken(context.Background(), []string{"BPOP "}, receiverInfo{}, nil)
	s.Require().Error(err)
	s.Equal("not of type bearer or dpop", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_Missing_Issuer_Expect_Error() {
	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))

	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	s.NotNil(signedTok)
	s.Require().NoError(err)

	_, _, err = s.auth.checkToken(context.Background(), []string{"Bearer " + string(signedTok)}, receiverInfo{}, nil)
	s.Require().Error(err)
	s.Equal("\"iss\" not satisfied: claim \"iss\" does not exist", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_Invalid_Issuer_Value_Expect_Error() {
	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", "invalid"))

	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	s.NotNil(signedTok)
	s.Require().NoError(err)

	_, _, err = s.auth.checkToken(context.Background(), []string{"Bearer " + string(signedTok)}, receiverInfo{}, nil)
	s.Require().Error(err)
	s.Contains(err.Error(), "\"iss\" not satisfied: values do not match")
}

func (s *AuthSuite) Test_CheckToken_When_Audience_Missing_Expect_Error() {
	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", s.server.URL))
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	s.NotNil(signedTok)
	s.Require().NoError(err)

	_, _, err = s.auth.checkToken(context.Background(), []string{"Bearer " + string(signedTok)}, receiverInfo{}, nil)
	s.Require().Error(err)
	s.Equal("claim \"aud\" not found", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_Audience_Invalid_Expect_Error() {
	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", s.server.URL))
	s.Require().NoError(tok.Set("aud", "invalid"))
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	s.NotNil(signedTok)
	s.Require().NoError(err)

	_, _, err = s.auth.checkToken(context.Background(), []string{"Bearer " + string(signedTok)}, receiverInfo{}, nil)
	s.Require().Error(err)
	s.Equal("\"aud\" not satisfied", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_Valid_No_DPoP_Expect_Error() {
	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", s.server.URL))
	s.Require().NoError(tok.Set("aud", "test"))
	s.Require().NoError(tok.Set("client_id", "client1"))
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	s.NotNil(signedTok)
	s.Require().NoError(err)

	_, _, err = s.auth.checkToken(context.Background(), []string{"Bearer " + string(signedTok)}, receiverInfo{}, nil)
	s.Require().Error(err)
	s.Require().Contains(err.Error(), "dpop")
}

type dpopTestCase struct {
	key              jwk.Key
	actualSigningKey jwk.Key
	accessToken      []byte
	alg              jwa.SignatureAlgorithm
	typ              string
	htm              string
	htu              string
	ath              string
	iat              time.Time
	errorMessage     string
}

func (s *AuthSuite) TestInvalid_DPoP_Cases() {
	dpopRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	dpopKey, err := jwk.FromRaw(dpopRaw)
	s.Require().NoError(err)
	s.Require().NoError(dpopKey.Set(jwk.AlgorithmKey, jwa.RS256))

	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", s.server.URL))
	s.Require().NoError(tok.Set("aud", "test"))
	s.Require().NoError(tok.Set("cid", "client2"))
	dpopPublic, err := dpopKey.PublicKey()
	s.Require().NoError(err)
	thumbprint, err := dpopKey.Thumbprint(crypto.SHA256)
	s.Require().NoError(err)
	cnf := map[string]string{"jkt": base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(thumbprint)}
	s.Require().NoError(tok.Set("cnf", cnf))
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	s.NotNil(signedTok)
	s.Require().NoError(err)

	otherKeyRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	otherKey, err := jwk.FromRaw(otherKeyRaw)
	s.Require().NoError(err)
	otherKeyPublic, err := otherKey.PublicKey()
	s.Require().NoError(err)
	s.Require().NoError(otherKey.Set(jwk.AlgorithmKey, jwa.RS256))

	tokenWithNoCNF := jwt.New()
	s.Require().NoError(tokenWithNoCNF.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tokenWithNoCNF.Set("iss", s.server.URL))
	s.Require().NoError(tokenWithNoCNF.Set("aud", "test"))
	s.Require().NoError(tokenWithNoCNF.Set("cid", "client2"))
	signedTokWithNoCNF, err := jwt.Sign(tokenWithNoCNF, jwt.WithKey(jwa.RS256, s.key))
	s.NotNil(signedTokWithNoCNF)
	s.Require().NoError(err)

	testCases := []dpopTestCase{
		{dpopPublic, dpopKey, signedTok, jwa.RS256, "dpop+jwt", http.MethodPost, "/a/path", "", time.Now().Add(time.Hour * -100), "the DPoP JWT has expired"},
		{dpopKey, dpopKey, signedTok, jwa.RS256, "dpop+jwt", http.MethodPost, "/a/path", "", time.Now(), "cannot use a private key for DPoP"},
		{dpopPublic, dpopKey, signedTok, jwa.RS256, "a weird type", http.MethodPost, "/a/path", "", time.Now(), "invalid typ on DPoP JWT: a weird type"},
		{dpopPublic, otherKey, signedTok, jwa.RS256, "dpop+jwt", http.MethodPost, "/a/path", "", time.Now(), "failed to verify signature on DPoP JWT"},
		{dpopPublic, dpopKey, signedTok, jwa.RS256, "dpop+jwt", http.MethodPost, "/a/different/path", "", time.Now(), "incorrect `htu` claim in DPoP JWT"},
		{dpopPublic, dpopKey, signedTok, jwa.RS256, "dpop+jwt", "POSTERS", "/a/path", "", time.Now(), "incorrect `htm` claim in DPoP JWT"},
		{dpopPublic, dpopKey, signedTok, jwa.RS256, "dpop+jwt", http.MethodPost, "/a/path", "bad ath", time.Now(), "incorrect `ath` claim in DPoP JWT"},
		{dpopPublic, dpopKey, signedTok, jwa.RS256, "dpop+jwt", http.MethodPost, "/a/path", "bad iat", time.Now().Add(2 * time.Hour), "\"iat\" not satisfied"},
		{
			otherKeyPublic, dpopKey, signedTok, jwa.RS256, "dpop+jwt", http.MethodPost, "/a/path", "", time.Now(),
			"the `jkt` from the DPoP JWT didn't match the thumbprint from the access token",
		},
		{
			dpopPublic, dpopKey, signedTokWithNoCNF, jwa.RS256, "dpop+jwt", http.MethodPost, "/a/path", "", time.Now(),
			"missing `cnf` claim in access token",
		},
	}

	for _, testCase := range testCases {
		s.Run(testCase.errorMessage, func() {
			dpopToken := makeDPoPToken(s.T(), testCase)
			_, _, err = s.auth.checkToken(
				context.Background(),
				[]string{"DPoP " + string(testCase.accessToken)},
				receiverInfo{
					u: []string{"/a/path"},
					m: []string{http.MethodPost},
				},
				[]string{dpopToken},
			)

			s.Require().Error(err)
			s.Contains(err.Error(), testCase.errorMessage)
		})
	}
}

func (s *AuthSuite) TestDPoPEndToEnd_GRPC() {
	dpopKeyRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	dpopKey, err := jwk.FromRaw(dpopKeyRaw)
	s.Require().NoError(err)
	s.Require().NoError(dpopKey.Set(jwk.AlgorithmKey, jwa.RS256))

	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", s.server.URL))
	s.Require().NoError(tok.Set("aud", "test"))
	s.Require().NoError(tok.Set("cid", "client-123"))
	s.Require().NoError(tok.Set("realm_access", map[string][]string{"roles": {"opentdf-standard"}}))
	thumbprint, err := dpopKey.Thumbprint(crypto.SHA256)
	s.Require().NoError(err)
	cnf := map[string]string{"jkt": base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(thumbprint)}
	s.Require().NoError(tok.Set("cnf", cnf))
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))
	s.Require().NoError(err)

	interceptor := connect.WithInterceptors(s.auth.ConnectUnaryServerInterceptor())

	fakeServer := &FakeAccessServiceServer{}

	mux := http.NewServeMux()
	path, handler := kasconnect.NewAccessServiceHandler(fakeServer, interceptor)
	mux.Handle(path, handler)

	server := memhttp.New(mux)
	defer server.Close()

	addingInterceptor := sdkauth.NewTokenAddingInterceptorWithClient(&FakeTokenSource{
		key:         dpopKey,
		accessToken: string(signedTok),
	}, httputil.SafeHTTPClientWithTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12,
	}))

	conn, _ := grpc.NewClient("passthrough://bufconn", grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return server.Listener.DialContext(ctx, "tcp", "http://localhost:8080")
	}), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithUnaryInterceptor(addingInterceptor.AddCredentials))

	client := kas.NewAccessServiceClient(conn)

	_, err = client.Rewrap(context.Background(), &kas.RewrapRequest{})
	s.Require().NoError(err)

	// interceptor propagated clientID from the token at the configured claim
	s.Equal("client-123", fakeServer.clientID)

	s.NotNil(fakeServer.dpopKey)
	dpopJWKFromRequest, ok := fakeServer.dpopKey.(jwk.RSAPublicKey)
	s.True(ok)
	dpopPublic, err := dpopKey.PublicKey()
	s.Require().NoError(err)
	dpopJWK, ok := dpopPublic.(jwk.RSAPublicKey)
	s.True(ok)

	s.Equal(dpopJWK.Algorithm(), dpopJWKFromRequest.Algorithm())
	s.Equal(dpopJWK.E(), dpopJWKFromRequest.E())
	s.Equal(dpopJWK.N(), dpopJWKFromRequest.N())
}

func (s *AuthSuite) TestDPoPEndToEnd_HTTP() {
	dpopKeyRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	dpopKey, err := jwk.FromRaw(dpopKeyRaw)
	s.Require().NoError(err)
	s.Require().NoError(dpopKey.Set(jwk.AlgorithmKey, jwa.RS256))

	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", s.server.URL))
	s.Require().NoError(tok.Set("aud", "test"))
	s.Require().NoError(tok.Set("cid", "client2"))
	s.Require().NoError(tok.Set("realm_access", map[string][]string{"roles": {"opentdf-standard"}}))
	thumbprint, err := dpopKey.Thumbprint(crypto.SHA256)
	s.Require().NoError(err)
	cnf := map[string]string{"jkt": base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(thumbprint)}
	s.Require().NoError(tok.Set("cnf", cnf))
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))
	s.Require().NoError(err)

	jwkChan := make(chan jwk.Key, 1)
	timeout := make(chan string, 1)
	clientIDChan := make(chan string, 1)
	go func() {
		time.Sleep(5 * time.Second)
		timeout <- ""
	}()
	server := httptest.NewServer(s.auth.MuxHandler(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		jwkChan <- ctxAuth.GetJWKFromContext(req.Context(), logger.CreateTestLogger())
		inbound := true
		cid, _ := ctxAuth.GetClientIDFromContext(req.Context(), inbound)
		clientIDChan <- cid
	})))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/attributes", nil)

	addingInterceptor := sdkauth.NewTokenAddingInterceptorWithClient(&FakeTokenSource{
		key:         dpopKey,
		accessToken: string(signedTok),
	}, httputil.SafeHTTPClientWithTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12,
	}))
	s.Require().NoError(err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", signedTok))
	dpopTok, err := addingInterceptor.GetDPoPToken(server.URL+"/attributes", "GET", string(signedTok))
	s.Require().NoError(err)
	req.Header.Set("DPoP", dpopTok)

	client := httputil.SafeHTTPClient() // use safe client to help validate the client
	_, err = client.Do(req)
	s.Require().NoError(err)
	var dpopKeyFromRequest jwk.Key
	select {
	case k := <-jwkChan:
		dpopKeyFromRequest = k
	case <-timeout:
		s.Require().FailNow("timed out waiting for call to complete")
	}
	var clientID string
	select {
	case cid := <-clientIDChan:
		clientID = cid
	case <-timeout:
		s.Require().FailNow("timed out waiting for call to complete")
	}

	s.Equal("client2", clientID)

	s.NotNil(dpopKeyFromRequest)
	dpopJWKFromRequest, ok := dpopKeyFromRequest.(jwk.RSAPublicKey)
	s.True(ok)
	s.Require().NoError(err)
	dpopPublic, err := dpopKey.PublicKey()
	s.Require().NoError(err)
	dpopJWK, ok := dpopPublic.(jwk.RSAPublicKey)
	s.True(ok)

	s.Equal(dpopJWK.Algorithm(), dpopJWKFromRequest.Algorithm())
	s.Equal(dpopJWK.E(), dpopJWKFromRequest.E())
	s.Equal(dpopJWK.N(), dpopJWKFromRequest.N())
}

func makeDPoPToken(t *testing.T, tc dpopTestCase) string {
	jtiBytes := make([]byte, sdkauth.JTILength)
	_, err := rand.Read(jtiBytes)
	if err != nil {
		t.Fatalf("error creating jti for dpop jwt: %v", err)
	}

	headers := jws.NewHeaders()
	err = headers.Set(jws.JWKKey, tc.key)
	if err != nil {
		t.Fatalf("error setting the key on the DPoP token: %v", err)
	}
	err = headers.Set(jws.TypeKey, tc.typ)
	if err != nil {
		t.Fatalf("error setting the type on the DPoP token: %v", err)
	}
	err = headers.Set(jws.AlgorithmKey, tc.alg)
	if err != nil {
		t.Fatalf("error setting the algorithm on the DPoP token: %v", err)
	}

	var ath string
	if tc.ath == "" {
		h := sha256.New()
		h.Write(tc.accessToken)
		ath = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h.Sum(nil))
	} else {
		ath = tc.ath
	}

	b := jwt.NewBuilder().
		Claim("htu", tc.htu).
		Claim("htm", tc.htm).
		Claim("ath", ath).
		Claim("jti", base64.StdEncoding.EncodeToString(jtiBytes))

	if tc.iat.IsZero() {
		b = b.IssuedAt(time.Now())
	} else {
		b = b.IssuedAt(tc.iat)
	}

	dpopTok, err := b.Build()
	if err != nil {
		t.Fatalf("error creating dpop jwt: %v", err)
	}

	signedToken, err := jwt.Sign(dpopTok, jwt.WithKey(tc.actualSigningKey.Algorithm(), tc.actualSigningKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		t.Fatalf("error signing dpop jwt: %v", err)
		return ""
	}
	return string(signedToken)
}

func (s *AuthSuite) Test_Allowing_Auth_With_No_DPoP() {
	authnConfig := AuthNConfig{
		EnforceDPoP: false,
		Issuer:      s.server.URL,
		Audience:    "test",
	}
	config := Config{}
	config.AuthNConfig = authnConfig
	auth, err := NewAuthenticator(context.Background(), config, &logger.Logger{
		Logger: slog.New(slog.Default().Handler()),
	},
		func(_ string, _ any) error { return nil },
	)

	s.Require().NoError(err)

	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", s.server.URL))
	s.Require().NoError(tok.Set("aud", "test"))
	s.Require().NoError(tok.Set("client_id", "client1"))
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	s.NotNil(signedTok)
	s.Require().NoError(err)

	_, ctx, err := auth.checkToken(context.Background(), []string{"Bearer " + string(signedTok)}, receiverInfo{}, nil)
	s.Require().NoError(err)
	s.Require().Nil(ctxAuth.GetJWKFromContext(ctx, logger.CreateTestLogger()))
}

func (s *AuthSuite) Test_PublicPath_Matches() {
	// Passing routes
	s.Require().True(slices.ContainsFunc(s.auth.publicRoutes, s.auth.isPublicRoute("/public")))
	s.Require().True(slices.ContainsFunc(s.auth.publicRoutes, s.auth.isPublicRoute("/public2/test")))
	s.Require().True(slices.ContainsFunc(s.auth.publicRoutes, s.auth.isPublicRoute("/public3/static")))
	s.Require().True(slices.ContainsFunc(s.auth.publicRoutes, s.auth.isPublicRoute("/public2/")))
	s.Require().True(slices.ContainsFunc(s.auth.publicRoutes, s.auth.isPublicRoute("/static/test")))
	s.Require().True(slices.ContainsFunc(s.auth.publicRoutes, s.auth.isPublicRoute("/static/test/next")))

	s.Require().True(slices.ContainsFunc(s.auth.publicRoutes, s.auth.isPublicRoute("/static-doublestar/test")))
	s.Require().True(slices.ContainsFunc(s.auth.publicRoutes, s.auth.isPublicRoute("/static-doublestar2/test/next")))
	s.Require().True(slices.ContainsFunc(s.auth.publicRoutes, s.auth.isPublicRoute("/static-doublestar3/test/next")))
	s.Require().True(slices.ContainsFunc(s.auth.publicRoutes, s.auth.isPublicRoute("/static-doublestar4/x/test/next")))

	// Failing routes
	s.Require().False(slices.ContainsFunc(s.auth.publicRoutes, s.auth.isPublicRoute("/public3/")))
	s.Require().False(slices.ContainsFunc(s.auth.publicRoutes, s.auth.isPublicRoute("/public2")))
	s.Require().False(slices.ContainsFunc(s.auth.publicRoutes, s.auth.isPublicRoute("/private")))
	s.Require().False(slices.ContainsFunc(s.auth.publicRoutes, s.auth.isPublicRoute("/public2/test/fail")))
}

func (s *AuthSuite) Test_GetAction() {
	cases := []struct {
		method   string
		expected string
	}{
		{"GetSomething", ActionRead},
		{"CreateSomething", ActionWrite},
		{"UpdateSomething", ActionWrite},
		{"AssignSomething", ActionWrite},
		{"DeleteSomething", ActionDelete},
		{"RemoveSomething", ActionDelete},
		{"DeactivateSomething", ActionDelete},
		{"ListSomething", ActionRead},
		{"UnsafeDelete", ActionUnsafe},
		{"UnsafeUpdate", ActionUnsafe},
		{"UnsafeActivate", ActionUnsafe},
		{"UnsafeReactivate", ActionUnsafe},
		{"DoSomething", ActionOther},
	}
	for _, c := range cases {
		s.Equal(c.expected, getAction(c.method))
	}
}

func (s *AuthSuite) Test_LookupGatewayPaths() {
	tests := []struct {
		name     string
		path     string
		header   http.Header
		expected []string
	}{
		{
			name: "Valid Rewrap Path",
			path: "/kas.AccessService/Rewrap",
			header: http.Header{
				"Grpcgateway-Origin": []string{s.server.URL},
			},
			expected: []string{s.server.URL + "/kas/v2/rewrap"},
		},
		{
			name: "Multiple Origins",
			path: "/kas.AccessService/Rewrap",
			header: http.Header{
				"Grpcgateway-Origin": []string{s.server.URL, "https://origin.1.com"},
				"Origin":             []string{"https://origin.com"},
			},
			expected: []string{
				s.server.URL + "/kas/v2/rewrap",
				"https://origin.1.com/kas/v2/rewrap", "https://origin.com/kas/v2/rewrap",
			},
		},
		{
			name: "Unknown Path with Pattern",
			path: "/unknown/path",
			header: http.Header{
				"Grpcgateway-Origin": []string{"https://origin.com"},
				"Pattern":            []string{"some-pattern"},
			},
			expected: []string{"https://origin.com/some-pattern"},
		},
		{
			name: "Unknown Path without Pattern",
			path: "/unknown/path",
			header: http.Header{
				"Grpcgateway-Origin": []string{"https://origin.com"},
			},
			expected: []string{"https://origin.com/wellknownconfiguration.WellKnownService/GetWellKnownConfiguration", "https://origin.com/.well-known/opentdf-configuration", "https://origin.com/kas.AccessService/PublicKey", "https://origin.com/kas.AccessService/LegacyPublicKey", "https://origin.com/kas/kas_public_key", "https://origin.com/kas/v2/kas_public_key", "https://origin.com/healthz", "https://origin.com/grpc.health.v1.Health/Check"},
		},
		{
			name: "Bad Path",
			path: "/unkown.App",
			header: http.Header{
				"Origin":  []string{"https://origin.com"},
				"Pattern": []string{"/?this. is=bad"},
			},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			result := s.auth.lookupGatewayPaths(context.Background(), tt.path, tt.header)
			s.Equal(tt.expected, result)
		})
	}
}

func Test_GetClientIDFromToken(t *testing.T) {
	tests := []struct {
		name             string
		claims           map[string]interface{}
		clientIDClaim    string
		expectedClientID string
		expectedErr      error
		expectError      bool
	}{
		{
			name: "Happy Path - simple claim",
			claims: map[string]interface{}{
				"cid": "test-client-id",
			},
			clientIDClaim:    "cid",
			expectedClientID: "test-client-id",
			expectError:      false,
		},
		{
			name: "Happy Path - different claim name",
			claims: map[string]interface{}{
				"client": "test-client-id",
			},
			clientIDClaim:    "client",
			expectedClientID: "test-client-id",
			expectError:      false,
		},
		{
			name: "Happy Path - dot notation",
			claims: map[string]interface{}{
				"client": map[string]interface{}{
					"info": map[string]interface{}{
						"id": "test-client-id",
					},
				},
			},
			clientIDClaim:    "client.info.id",
			expectedClientID: "test-client-id",
			expectError:      false,
		},
		{
			name:             "Error - no client ID claim configured",
			claims:           map[string]interface{}{"cid": "test"},
			clientIDClaim:    "", // empty claim name
			expectedClientID: "",
			expectedErr:      ErrClientIDClaimNotConfigured,
			expectError:      true,
		},
		{
			name: "Error - claim not found",
			claims: map[string]interface{}{
				"other-claim": "some-value",
			},
			clientIDClaim:    "cid",
			expectedClientID: "",
			expectedErr:      ErrClientIDClaimNotFound,
			expectError:      true,
		},
		{
			name: "Error - claim is not a string (int)",
			claims: map[string]interface{}{
				"cid": 12345,
			},
			clientIDClaim:    "cid",
			expectedClientID: "",
			expectedErr:      ErrClientIDClaimNotString,
			expectError:      true,
		},
		{
			name: "Error - claim is not a string (bool)",
			claims: map[string]interface{}{
				"cid": true,
			},
			clientIDClaim:    "cid",
			expectedClientID: "",
			expectedErr:      ErrClientIDClaimNotString,
			expectError:      true,
		},
		{
			name: "Error - claim is not a string (object)",
			claims: map[string]interface{}{
				"cid": map[string]interface{}{"nested": "value"},
			},
			clientIDClaim:    "cid",
			expectedClientID: "",
			expectedErr:      ErrClientIDClaimNotString,
			expectError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &Authentication{
				oidcConfiguration: AuthNConfig{
					Policy: PolicyConfig{
						ClientIDClaim: tt.clientIDClaim,
					},
				},
			}

			tok := jwt.New()
			for k, v := range tt.claims {
				err := tok.Set(k, v)
				require.NoError(t, err)
			}

			clientID, err := auth.getClientIDFromToken(t.Context(), tok)

			assert.Equal(t, tt.expectedClientID, clientID)

			if tt.expectError {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
