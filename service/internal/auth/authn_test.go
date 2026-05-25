package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
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
	// CWT bearer-token signing material. priv signs the CWTs the tests mint;
	// kid is the COSE key id the server advertises in its key set.
	priv *ecdsa.PrivateKey
	kid  []byte
	auth *Authentication
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

func (s *AuthSuite) SetupTest() {
	// Generate the EC P-256 signing key and a small COSE Key Set wrapping
	// its public half. Helpers come from cwt_verifier_test.go (same package).
	priv, kid := newP256(s.T())
	s.priv = priv
	s.kid = kid
	keySetCBOR := coseKeySetFromPub(s.T(), &priv.PublicKey, kid)

	// Fake IdP — serves OIDC discovery (with the arkavo_cose_keys_uri
	// extension so NewAuthenticator can find the key set) and the COSE Key
	// Set itself. JWKS is still served (empty) so anything that consults the
	// discovery doc and follows jwks_uri sees a well-formed response, even
	// though the platform now verifies bearers as CWTs.
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w,
				`{"issuer":%q,"jwks_uri":%q,"arkavo_cose_keys_uri":%q}`,
				s.server.URL, s.server.URL+"/jwks", s.server.URL+"/cose-keys")
		case "/cose-keys":
			w.Header().Set("Content-Type", "application/cose-key-set+cbor")
			_, _ = w.Write(keySetCBOR)
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))

	policyCfg := PolicyConfig{
		ClientIDClaim: "cid",
	}
	err := defaults.Set(&policyCfg)
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
	// Default policy ClientIDClaim is "azp"; we set it as a custom CWT
	// text-label claim so getClientIDFromToken can extract it after the
	// CWT verifier hydrates a jwt.Token. realm_access.roles is included so
	// any role provider that defaults to it has data to read.
	bearer := s.mintCWT(map[string]any{
		"azp":          "test-client-id",
		"realm_access": map[string]any{"roles": []any{"opentdf-standard"}},
	})

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
	_, err = client.Rewrap(metadata.AppendToOutgoingContext(s.T().Context(), "authorization", "Bearer "+bearer), &kas.RewrapRequest{})
	s.Require().NoError(err)

	// Assert that the client ID was properly extracted and set in the context
	s.Equal("test-client-id", fakeServer.clientID)
}

// NOTE: Tests that asserted jwx error strings for expired / missing-iss /
// invalid-iss / missing-aud / invalid-aud have been removed. Token-format
// claim validation is now exclusively CWTVerifier's responsibility and is
// covered by cwt_verifier_test.go (see TestCWTVerifier_*Claim* there). The
// auth middleware just propagates whatever error the verifier returns.

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

func (s *AuthSuite) Test_CheckToken_When_Valid_No_DPoP_Expect_Error() {
	// Default suite config enforces DPoP. A bearer with no `cnf` claim
	// should be rejected before any access decision is made.
	bearer := s.mintCWT(map[string]any{"cid": "client1"})
	_, _, err := s.auth.checkToken(context.Background(), []string{"Bearer " + bearer}, receiverInfo{}, nil)
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
	// DPoP *proofs* remain JWTs per RFC 9449. The access token they're
	// bound to is now a CWT. So we mint a CWT bearer with a `cnf.jkt`
	// matching the DPoP proof's key thumbprint, and an RSA key for the
	// DPoP proof itself.
	dpopRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	dpopKey, err := jwk.FromRaw(dpopRaw)
	s.Require().NoError(err)
	s.Require().NoError(dpopKey.Set(jwk.AlgorithmKey, jwa.RS256))

	dpopPublic, err := dpopKey.PublicKey()
	s.Require().NoError(err)
	thumbprint, err := dpopKey.Thumbprint(crypto.SHA256)
	s.Require().NoError(err)
	jkt := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(thumbprint)

	signedTok := s.mintCWT(map[string]any{
		"cid": "client2",
		"cnf": map[string]any{"jkt": jkt},
	})
	signedTokWithNoCNF := s.mintCWT(map[string]any{
		"cid": "client2",
	})

	otherKeyRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	otherKey, err := jwk.FromRaw(otherKeyRaw)
	s.Require().NoError(err)
	otherKeyPublic, err := otherKey.PublicKey()
	s.Require().NoError(err)
	s.Require().NoError(otherKey.Set(jwk.AlgorithmKey, jwa.RS256))

	signedTokBytes := []byte(signedTok)
	signedTokNoCNFBytes := []byte(signedTokWithNoCNF)
	testCases := []dpopTestCase{
		{dpopPublic, dpopKey, signedTokBytes, jwa.RS256, "dpop+jwt", http.MethodPost, "/a/path", "", time.Now().Add(time.Hour * -100), "the DPoP JWT has expired"},
		{dpopKey, dpopKey, signedTokBytes, jwa.RS256, "dpop+jwt", http.MethodPost, "/a/path", "", time.Now(), "cannot use a private key for DPoP"},
		{dpopPublic, dpopKey, signedTokBytes, jwa.RS256, "a weird type", http.MethodPost, "/a/path", "", time.Now(), "invalid typ on DPoP JWT: a weird type"},
		{dpopPublic, otherKey, signedTokBytes, jwa.RS256, "dpop+jwt", http.MethodPost, "/a/path", "", time.Now(), "failed to verify signature on DPoP JWT"},
		{dpopPublic, dpopKey, signedTokBytes, jwa.RS256, "dpop+jwt", http.MethodPost, "/a/different/path", "", time.Now(), "incorrect `htu` claim in DPoP JWT"},
		{dpopPublic, dpopKey, signedTokBytes, jwa.RS256, "dpop+jwt", "POSTERS", "/a/path", "", time.Now(), "incorrect `htm` claim in DPoP JWT"},
		{dpopPublic, dpopKey, signedTokBytes, jwa.RS256, "dpop+jwt", http.MethodPost, "/a/path", "bad ath", time.Now(), "incorrect `ath` claim in DPoP JWT"},
		{dpopPublic, dpopKey, signedTokBytes, jwa.RS256, "dpop+jwt", http.MethodPost, "/a/path", "bad iat", time.Now().Add(2 * time.Hour), "\"iat\" not satisfied"},
		{
			otherKeyPublic, dpopKey, signedTokBytes, jwa.RS256, "dpop+jwt", http.MethodPost, "/a/path", "", time.Now(),
			"the `jkt` from the DPoP JWT didn't match the thumbprint from the access token",
		},
		{
			dpopPublic, dpopKey, signedTokNoCNFBytes, jwa.RS256, "dpop+jwt", http.MethodPost, "/a/path", "", time.Now(),
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
	// As in TestInvalid_DPoP_Cases: DPoP proof stays as a JWT, the access
	// token is now a CWT carrying the matching jkt in its cnf claim.
	dpopKeyRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	dpopKey, err := jwk.FromRaw(dpopKeyRaw)
	s.Require().NoError(err)
	s.Require().NoError(dpopKey.Set(jwk.AlgorithmKey, jwa.RS256))

	thumbprint, err := dpopKey.Thumbprint(crypto.SHA256)
	s.Require().NoError(err)
	jkt := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(thumbprint)

	signedTok := s.mintCWT(map[string]any{
		"cid":          "client-123",
		"realm_access": map[string]any{"roles": []any{"opentdf-standard"}},
		"cnf":          map[string]any{"jkt": jkt},
	})

	interceptor := connect.WithInterceptors(s.auth.ConnectUnaryServerInterceptor())

	fakeServer := &FakeAccessServiceServer{}

	mux := http.NewServeMux()
	path, handler := kasconnect.NewAccessServiceHandler(fakeServer, interceptor)
	mux.Handle(path, handler)

	server := memhttp.New(mux)
	defer server.Close()

	addingInterceptor := sdkauth.NewTokenAddingInterceptorWithClient(&FakeTokenSource{
		key:         dpopKey,
		accessToken: signedTok,
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
	auth, err := NewAuthenticator(context.Background(), config, logger.CreateTestLogger(),
		func(_ string, _ any) error { return nil },
	)
	s.Require().NoError(err)

	// CWT without a `cnf` claim — enforceDPoP=false above means the
	// middleware accepts it and proceeds with no DPoP key bound.
	bearer := s.mintCWT(map[string]any{"cid": "client1"})
	_, ctx, err := auth.checkToken(context.Background(), []string{"Bearer " + bearer}, receiverInfo{}, nil)
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

// mintCWT signs a CWT access token for these tests, using the suite's
// EC P-256 key and the kid that the fake IdP advertises in its COSE Key
// Set. `custom` overlays text-label claims on top of the standard
// iss/aud/sub/exp/iat claims (e.g. set "cid" for client-id propagation
// tests, or "cnf" for DPoP).
func (s *AuthSuite) mintCWT(custom map[string]any) string {
	claims := standardClaims(s.server.URL, "test", "user-1", time.Hour)
	return signCWT(s.T(), s.priv, s.kid, claims, custom)
}
