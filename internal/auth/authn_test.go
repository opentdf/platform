package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/kas"
	sdkauth "github.com/opentdf/platform/sdk/auth"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
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
	accessToken []string
	dpopKey     jwk.Key
	kas.UnimplementedAccessServiceServer
}

func (f *FakeAccessServiceServer) Info(ctx context.Context, _ *kas.InfoRequest) (*kas.InfoResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		f.accessToken = md.Get("authorization")
		f.dpopKey = GetJWKFromContext(ctx)
	}

	return &kas.InfoResponse{}, nil
}
func (f *FakeAccessServiceServer) PublicKey(context.Context, *kas.PublicKeyRequest) (*kas.PublicKeyResponse, error) {
	return &kas.PublicKeyResponse{}, status.Error(codes.Unauthenticated, "no public key for you")
}
func (f *FakeAccessServiceServer) LegacyPublicKey(context.Context, *kas.LegacyPublicKeyRequest) (*wrapperspb.StringValue, error) {
	return &wrapperspb.StringValue{}, nil
}
func (f *FakeAccessServiceServer) Rewrap(context.Context, *kas.RewrapRequest) (*kas.RewrapResponse, error) {
	return &kas.RewrapResponse{}, nil
}

type FakeTokenSource struct {
	key         jwk.Key
	accessToken string
}

func (fts *FakeTokenSource) AccessToken() (sdkauth.AccessToken, error) {
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
			_, err := w.Write([]byte(fmt.Sprintf(`{"jwks_uri": "%s/jwks"}`, s.server.URL)))
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

	auth, err := NewAuthenticator(AuthNConfig{
		Issuer:   s.server.URL,
		Audience: "test",
		Clients:  []string{"client1", "client2", "client3"},
	}, nil)

	s.Require().NoError(err)

	s.auth = auth
}

func (s *AuthSuite) TearDownTest() {
	s.server.Close()
}

func TestAuthSuite(t *testing.T) {
	suite.Run(t, new(AuthSuite))
}

func (s *AuthSuite) Test_CheckToken_When_JWT_Expired_Expect_Error() {
	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)))

	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	s.NotNil(signedTok)
	s.Require().NoError(err)

	_, _, err = s.auth.checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{})
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
	md := metadata.New(map[string]string{})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	_, err := s.auth.UnaryServerInterceptor(ctx, "test", &grpc.UnaryServerInfo{
		FullMethod: "/test",
	}, nil)
	s.Require().Error(err)
	s.ErrorIs(err, status.Error(codes.Unauthenticated, "missing authorization header"))
}

func (s *AuthSuite) Test_CheckToken_When_Authorization_Header_Invalid_Expect_Error() {
	_, _, err := s.auth.checkToken(context.Background(), []string{"BPOP "}, dpopInfo{})
	s.Require().Error(err)
	s.Equal("not of type bearer or dpop", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_Missing_Issuer_Expect_Error() {
	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))

	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	s.NotNil(signedTok)
	s.Require().NoError(err)

	_, _, err = s.auth.checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{})
	s.Require().Error(err)
	s.Equal("missing issuer", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_Invalid_Issuer_Value_Expect_Error() {
	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", "invalid"))

	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	s.NotNil(signedTok)
	s.Require().NoError(err)

	_, _, err = s.auth.checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{})
	s.Require().Error(err)
	s.Equal("invalid issuer", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_Audience_Missing_Expect_Error() {
	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", s.server.URL))
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	s.NotNil(signedTok)
	s.Require().NoError(err)

	_, _, err = s.auth.checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{})
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

	_, _, err = s.auth.checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{})
	s.Require().Error(err)
	s.Equal("\"aud\" not satisfied", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_ClientID_Missing_Expect_Error() {
	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", s.server.URL))
	s.Require().NoError(tok.Set("aud", "test"))
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	s.NotNil(signedTok)
	s.Require().NoError(err)

	_, _, err = s.auth.checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{})
	s.Require().Error(err)
	s.Equal("client id required", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_ClientID_Invalid_Expect_Error() {
	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", s.server.URL))
	s.Require().NoError(tok.Set("aud", "test"))
	s.Require().NoError(tok.Set("client_id", "invalid"))
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	s.NotNil(signedTok)
	s.Require().NoError(err)

	_, _, err = s.auth.checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{})
	s.Require().Error(err)
	s.Equal("invalid client id", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_CID_Invalid_Expect_Error() {
	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", s.server.URL))
	s.Require().NoError(tok.Set("aud", "test"))
	s.Require().NoError(tok.Set("cid", "invalid"))
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	s.NotNil(signedTok)
	s.Require().NoError(err)

	_, _, err = s.auth.checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{})
	s.Require().Error(err)
	s.Equal("invalid client id", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_CID_Invalid_INT_Expect_Error() {
	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", s.server.URL))
	s.Require().NoError(tok.Set("aud", "test"))
	s.Require().NoError(tok.Set("cid", 1))
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	s.NotNil(signedTok)
	s.Require().NoError(err)

	_, _, err = s.auth.checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{})
	s.Require().Error(err)
	s.Equal("invalid client id", err.Error())
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

	_, _, err = s.auth.checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{})
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
		{dpopPublic, dpopKey, signedTok, jwa.RS256, "dpop+jwt", "POST", "/a/path", "", time.Now().Add(time.Hour * -100), "the DPoP JWT has expired"},
		{dpopKey, dpopKey, signedTok, jwa.RS256, "dpop+jwt", "POST", "/a/path", "", time.Now(), "cannot use a private key for DPoP"},
		{dpopPublic, dpopKey, signedTok, jwa.RS256, "a weird type", "POST", "/a/path", "", time.Now(), "invalid typ on DPoP JWT: a weird type"},
		{dpopPublic, otherKey, signedTok, jwa.RS256, "dpop+jwt", "POST", "/a/path", "", time.Now(), "failed to verify signature on DPoP JWT"},
		{dpopPublic, dpopKey, signedTok, jwa.RS256, "dpop+jwt", "POST", "/a/different/path", "", time.Now(), "incorrect `htu` claim in DPoP JWT"},
		{dpopPublic, dpopKey, signedTok, jwa.RS256, "dpop+jwt", "POSTERS", "/a/path", "", time.Now(), "incorrect `htm` claim in DPoP JWT"},
		{dpopPublic, dpopKey, signedTok, jwa.RS256, "dpop+jwt", "POST", "/a/path", "bad ath", time.Now(), "incorrect `ath` claim in DPoP JWT"},
		{otherKeyPublic, dpopKey, signedTok, jwa.RS256, "dpop+jwt", "POST", "/a/path", "", time.Now(),
			"the `jkt` from the DPoP JWT didn't match the thumbprint from the access token"},
		{dpopPublic, dpopKey, signedTokWithNoCNF, jwa.RS256, "dpop+jwt", "POST", "/a/path", "", time.Now(),
			"missing `cnf` claim in access token"},
	}

	for _, testCase := range testCases {
		dpopToken := makeDPoPToken(s.T(), testCase)
		_, _, err = s.auth.checkToken(
			context.Background(),
			[]string{fmt.Sprintf("DPoP %s", string(testCase.accessToken))},
			dpopInfo{
				headers: []string{dpopToken},
				path:    "/a/path",
				method:  "POST",
			},
		)

		s.Require().Error(err)
		s.Equal(testCase.errorMessage, err.Error())
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
	s.Require().NoError(tok.Set("cid", "client2"))
	s.Require().NoError(tok.Set("realm_access", map[string][]string{"roles": {"opentdf-readonly"}}))
	thumbprint, err := dpopKey.Thumbprint(crypto.SHA256)
	s.Require().NoError(err)
	cnf := map[string]string{"jkt": base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(thumbprint)}
	s.Require().NoError(tok.Set("cnf", cnf))
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))
	s.Require().NoError(err)

	buffer := 1024 * 1024
	listener := bufconn.Listen(buffer)

	server := grpc.NewServer(grpc.UnaryInterceptor(s.auth.UnaryServerInterceptor))
	defer server.Stop()

	fakeServer := &FakeAccessServiceServer{}
	kas.RegisterAccessServiceServer(server, fakeServer)
	go func() {
		err := server.Serve(listener)
		if err != nil {
			panic(err)
		}
	}()

	addingInterceptor := sdkauth.NewTokenAddingInterceptor(&FakeTokenSource{
		key:         dpopKey,
		accessToken: string(signedTok),
	})

	conn, _ := grpc.DialContext(context.Background(), "", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock(), grpc.WithUnaryInterceptor(addingInterceptor.AddCredentials))

	client := kas.NewAccessServiceClient(conn)

	_, err = client.Info(context.Background(), &kas.InfoRequest{})
	s.Require().NoError(err)
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
	s.Require().NoError(tok.Set("realm_access", map[string][]string{"roles": {"opentdf-readonly"}}))
	thumbprint, err := dpopKey.Thumbprint(crypto.SHA256)
	s.Require().NoError(err)
	cnf := map[string]string{"jkt": base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(thumbprint)}
	s.Require().NoError(tok.Set("cnf", cnf))
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))
	s.Require().NoError(err)

	jwkChan := make(chan jwk.Key, 1)
	timeout := make(chan string, 1)
	go func() {
		time.Sleep(5 * time.Second)
		timeout <- ""
	}()
	server := httptest.NewServer(s.auth.MuxHandler(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		jwkChan <- GetJWKFromContext(req.Context())
	})))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/attributes", nil)

	addingInterceptor := sdkauth.NewTokenAddingInterceptor(&FakeTokenSource{
		key:         dpopKey,
		accessToken: string(signedTok),
	})
	s.Require().NoError(err)
	req.Header.Set("authorization", fmt.Sprintf("Bearer %s", signedTok))
	dpopTok, err := addingInterceptor.GetDPoPToken("/attributes", "GET", string(signedTok))
	s.Require().NoError(err)
	req.Header.Set("DPoP", dpopTok)

	client := http.Client{}
	_, err = client.Do(req)
	s.Require().NoError(err)
	var dpopKeyFromRequest jwk.Key
	select {
	case k := <-jwkChan:
		dpopKeyFromRequest = k
	case <-timeout:
		s.Require().FailNow("timed out waiting for call to complete")
	}

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
