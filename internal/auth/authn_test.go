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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type AuthSuite struct {
	suite.Suite
	server            *httptest.Server
	key               jwk.Key
	auth              *authentication
	accessTokenSource FakeAccessTokenSource
}

type FakeAccessTokenSource struct {
	dPOPKey     jwk.Key
	accessToken string
}

func (fake FakeAccessTokenSource) AccessToken() (AccessToken, error) {
	return AccessToken(fake.accessToken), nil
}
func (fake FakeAccessTokenSource) DecryptWithDPoPKey(encrypted []byte) ([]byte, error) {
	return nil, nil
}
func (fake FakeAccessTokenSource) MakeToken(tokenMaker func(jwk.Key) ([]byte, error)) ([]byte, error) {
	return tokenMaker(fake.dPOPKey)
}
func (fake FakeAccessTokenSource) DPOPPublicKeyPEM() string {
	return "this is the PEM"
}
func (fake FakeAccessTokenSource) RefreshAccessToken() error {
	return errors.New("can't refresh this one")
}

func (s *AuthSuite) SetupTest() {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		slog.Error("failed to generate RSA private key", slog.String("error", err.Error()))
		return
	}

	pubKeyJWK, err := jwk.FromRaw(privKey.PublicKey)
	if err != nil {
		slog.Error("failed to create jwk.Key from RSA public key", slog.String("error", err.Error()))
		return
	}
	pubKeyJWK.Set(jws.KeyIDKey, "test")
	pubKeyJWK.Set(jwk.AlgorithmKey, jwa.RS256)

	// Create a new set with rsa public key
	set := jwk.NewSet()
	if err := set.AddKey(pubKeyJWK); err != nil {
		slog.Error("failed to add RSA public key to jwk.Set", slog.String("error", err.Error()))
		return
	}

	key, err := jwk.FromRaw(privKey)
	if err != nil {
		slog.Error("failed to create jwk.Key from RSA private key", slog.String("error", err.Error()))
		return
	}
	key.Set(jws.KeyIDKey, "test")

	s.key = key

	privDPoPKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		slog.Error("failed to generate RSA private key", slog.String("error", err.Error()))
		return
	}
	privDPoPJWK, err := jwk.FromRaw(privDPoPKey)
	if err != nil {
		slog.Error("failed to create jwk.Key from RSA public key", slog.String("error", err.Error()))
		return
	}
	privDPoPJWK.Set(jwk.AlgorithmKey, jwa.RS256)
	s.accessTokenSource = FakeAccessTokenSource{
		dPOPKey: privDPoPJWK,
	}

	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Write([]byte(fmt.Sprintf(`{"jwks_uri": "%s/jwks"}`, s.server.URL)))
			return
		}
		if r.URL.Path == "/jwks" {
			json.NewEncoder(w).Encode(set)
			return
		}
	}))

	auth, err := NewAuthenticator(AuthNConfig{
		Issuer:   s.server.URL,
		Audience: "test",
		Clients:  []string{"client1", "client2", "client3"},
	})

	assert.Nil(s.T(), err)

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
	tok.Set(jwt.ExpirationKey, time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC))

	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	assert.NotNil(s.T(), signedTok)
	assert.Nil(s.T(), err)

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{}, *s.auth)
	assert.NotNil(s.T(), err)
	assert.Equal(s.T(), "\"exp\" not satisfied", err.Error())
}

func (s *AuthSuite) Test_VerifyTokenHandler_When_Authorization_Header_Missing_Expect_Error() {
	handler := s.auth.VerifyTokenHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(s.T(), http.StatusUnauthorized, rec.Code)
	assert.Equal(s.T(), "missing authorization header\n", rec.Body.String())
}

func (s *AuthSuite) Test_VerifyTokenInterceptor_When_Authorization_Header_Missing_Expect_Error() {
	md := metadata.New(map[string]string{})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	_, err := s.auth.VerifyTokenInterceptor(ctx, "test", &grpc.UnaryServerInfo{
		FullMethod: "/test",
	}, nil)
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, status.Error(codes.Unauthenticated, "missing authorization header"))
}

func (s *AuthSuite) Test_CheckToken_When_Authorization_Header_Invalid_Expect_Error() {
	err := checkToken(context.Background(), []string{"BPOP "}, dpopInfo{}, *s.auth)
	assert.NotNil(s.T(), err)
	assert.Equal(s.T(), "not of type bearer or dpop", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_Missing_Issuer_Expect_Error() {
	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))

	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	assert.NotNil(s.T(), signedTok)
	assert.Nil(s.T(), err)

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{}, *s.auth)
	assert.NotNil(s.T(), err)
	assert.Equal(s.T(), "missing issuer", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_Invalid_Issuer_Value_Expect_Error() {
	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	tok.Set("iss", "invalid")

	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	assert.NotNil(s.T(), signedTok)
	assert.Nil(s.T(), err)

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{}, *s.auth)
	assert.NotNil(s.T(), err)
	assert.Equal(s.T(), "invalid issuer", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_Invalid_Issuer_INT_Value_Expect_Error() {
	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	tok.Set("iss", 1)

	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	assert.NotNil(s.T(), signedTok)
	assert.Nil(s.T(), err)

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{}, *s.auth)
	assert.NotNil(s.T(), err)
	assert.Equal(s.T(), "missing issuer", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_Audience_Missing_Expect_Error() {
	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	tok.Set("iss", s.server.URL)
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	assert.NotNil(s.T(), signedTok)
	assert.Nil(s.T(), err)

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{}, *s.auth)
	assert.NotNil(s.T(), err)
	assert.Equal(s.T(), "claim \"aud\" not found", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_Audience_Invalid_Expect_Error() {
	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	tok.Set("iss", s.server.URL)
	tok.Set("aud", "invalid")
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	assert.NotNil(s.T(), signedTok)
	assert.Nil(s.T(), err)

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{}, *s.auth)
	assert.NotNil(s.T(), err)
	assert.Equal(s.T(), "\"aud\" not satisfied", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_ClientID_Missing_Expect_Error() {
	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	tok.Set("iss", s.server.URL)
	tok.Set("aud", "test")
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	assert.NotNil(s.T(), signedTok)
	assert.Nil(s.T(), err)

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{}, *s.auth)
	assert.NotNil(s.T(), err)
	assert.Equal(s.T(), "client id required", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_ClientID_Invalid_Expect_Error() {
	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	tok.Set("iss", s.server.URL)
	tok.Set("aud", "test")
	tok.Set("client_id", "invalid")
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	assert.NotNil(s.T(), signedTok)
	assert.Nil(s.T(), err)

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{}, *s.auth)
	assert.NotNil(s.T(), err)
	assert.Equal(s.T(), "invalid client id", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_CID_Invalid_Expect_Error() {
	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	tok.Set("iss", s.server.URL)
	tok.Set("aud", "test")
	tok.Set("cid", "invalid")
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	assert.NotNil(s.T(), signedTok)
	assert.Nil(s.T(), err)

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{}, *s.auth)
	assert.NotNil(s.T(), err)
	assert.Equal(s.T(), "invalid client id", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_CID_Invalid_INT_Expect_Error() {
	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	tok.Set("iss", s.server.URL)
	tok.Set("aud", "test")
	tok.Set("cid", 1)
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	assert.NotNil(s.T(), signedTok)
	assert.Nil(s.T(), err)

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{}, *s.auth)
	assert.NotNil(s.T(), err)
	assert.Equal(s.T(), "invalid client id", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_Valid_Expect_No_Error() {
	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	tok.Set("iss", s.server.URL)
	tok.Set("aud", "test")
	tok.Set("client_id", "client1")
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	assert.NotNil(s.T(), signedTok)
	assert.Nil(s.T(), err)

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, dpopInfo{}, *s.auth)
	assert.Nil(s.T(), err)
}

func (s *AuthSuite) Test_CheckValidDPoPToken_FromTokenInterceptor_Expect_No_Error() {
	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	tok.Set("iss", s.server.URL)
	tok.Set("aud", "test")
	tok.Set("cid", "client2")
	pk, err := s.accessTokenSource.dPOPKey.PublicKey()
	assert.NoError(s.T(), err)
	thumbprint, err := pk.Thumbprint(crypto.SHA256)
	assert.NoError(s.T(), err)
	cnf := map[string]string{"jkt": base64.URLEncoding.EncodeToString(thumbprint)}
	tok.Set("cnf", cnf)
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	assert.NotNil(s.T(), signedTok)
	assert.Nil(s.T(), err)

	tokenAddingInterceptor := tokenAddingInterceptor{
		tokenSource: s.accessTokenSource,
	}

	dpop, err := tokenAddingInterceptor.getDPoPToken("/a/path", string(signedTok))
	assert.NoError(s.T(), err, "failed to create dpop token")
	dpopInfo := dpopInfo{
		headers: []string{dpop},
		path:    "/a/path",
		method:  "POST",
	}

	err = checkToken(context.Background(), []string{fmt.Sprintf("DPoP %s", string(signedTok))}, dpopInfo, *s.auth)
	assert.Nil(s.T(), err)
}

func (s *AuthSuite) Test_CheckDPoPTokenMissingCNF_Expect_Error() {
	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	tok.Set("iss", s.server.URL)
	tok.Set("aud", "test")
	tok.Set("cid", "client2")
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	assert.NotNil(s.T(), signedTok)
	assert.Nil(s.T(), err)

	tokenAddingInterceptor := tokenAddingInterceptor{
		tokenSource: s.accessTokenSource,
	}

	dpop, err := tokenAddingInterceptor.getDPoPToken("/a/path", string(signedTok))
	assert.NoError(s.T(), err, "failed to create dpop token")
	dpopInfo := dpopInfo{
		headers: []string{dpop},
		path:    "/a/path",
		method:  "POST",
	}

	err = checkToken(context.Background(), []string{fmt.Sprintf("DPoP %s", string(signedTok))}, dpopInfo, *s.auth)
	assert.Equal(s.T(), "missing `cnf` claim in access token", err.Error())
}

func (s *AuthSuite) Test_CheckDPoPTokenInvalidJKT_Expect_Error() {
	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	tok.Set("iss", s.server.URL)
	tok.Set("aud", "test")
	tok.Set("cid", "client2")
	cnf := map[string]string{"jkt": "a bad jkt"}
	tok.Set("cnf", cnf)
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	assert.NotNil(s.T(), signedTok)
	assert.Nil(s.T(), err)

	tokenAddingInterceptor := tokenAddingInterceptor{
		tokenSource: s.accessTokenSource,
	}

	dpop, err := tokenAddingInterceptor.getDPoPToken("/a/path", string(signedTok))
	assert.NoError(s.T(), err, "failed to create dpop token")
	dpopInfo := dpopInfo{
		headers: []string{dpop},
		path:    "/a/path",
		method:  "POST",
	}

	err = checkToken(context.Background(), []string{fmt.Sprintf("DPoP %s", string(signedTok))}, dpopInfo, *s.auth)
	assert.Equal(s.T(), "the `jkt` from the DPoP JWT didn't match the thumbprint from the access token", err.Error())
}

type dpopTestCase struct {
	key              jwk.Key
	actualSigningKey jwk.Key
	alg              jwa.SignatureAlgorithm
	typ              string
	htm              string
	htu              string
	ath              string
	iat              time.Time
	errorMesssage    string
}

func (s *AuthSuite) TestInvalid_DPOP_Cases() {
	dpopRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		slog.Error("failed to generate RSA private key", slog.String("error", err.Error()))
		return
	}
	dpopKey, err := jwk.FromRaw(dpopRaw)
	if err != nil {
		slog.Error("failed to create jwk.Key from RSA public key", slog.String("error", err.Error()))
		return
	}
	dpopKey.Set(jwk.AlgorithmKey, jwa.RS256)

	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	tok.Set("iss", s.server.URL)
	tok.Set("aud", "test")
	tok.Set("cid", "client2")
	dpopPublic, err := dpopKey.PublicKey()
	assert.NoError(s.T(), err)
	thumbprint, err := dpopKey.Thumbprint(crypto.SHA256)
	assert.NoError(s.T(), err)
	cnf := map[string]string{"jkt": base64.URLEncoding.EncodeToString(thumbprint)}
	tok.Set("cnf", cnf)
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	assert.NotNil(s.T(), signedTok)
	assert.Nil(s.T(), err)

	otherKeyRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		slog.Error("failed to generate RSA private key", slog.String("error", err.Error()))
		return
	}
	otherKey, err := jwk.FromRaw(otherKeyRaw)
	if err != nil {
		slog.Error("failed to create jwk.Key from RSA public key", slog.String("error", err.Error()))
		return
	}
	otherKey.Set(jwk.AlgorithmKey, jwa.RS256)

	testCases := []dpopTestCase{
		{dpopPublic, dpopKey, jwa.RS256, "dpop+jwt", "POST", "/a/path", "", time.Now(), ""},
		{dpopPublic, dpopKey, jwa.RS256, "dpop+jwt", "POST", "/a/path", "", time.Now().Add(time.Hour * -100), "the DPoP JWT has expired"},
		{dpopKey, dpopKey, jwa.RS256, "dpop+jwt", "POST", "/a/path", "", time.Now(), "cannot use a private key for DPoP"},
		{dpopPublic, dpopKey, jwa.RS256, "a weird type", "POST", "/a/path", "", time.Now(), "invalid typ on DPoP JWT: a weird type"},
		{dpopPublic, otherKey, jwa.RS256, "dpop+jwt", "POST", "/a/path", "", time.Now(), "failed to verify signature on DPoP JWT"},
		{dpopPublic, dpopKey, jwa.RS256, "dpop+jwt", "POST", "/a/different/path", "", time.Now(), "incorrect `htu` claim in DPoP JWT"},
		{dpopPublic, dpopKey, jwa.RS256, "dpop+jwt", "POSTERS", "/a/path", "", time.Now(), "incorrect `htm` claim in DPoP JWT"},
		{dpopPublic, dpopKey, jwa.RS256, "dpop+jwt", "POST", "/a/path", "bad ath", time.Now(), "incorrect `ath` claim in DPoP JWT"},
	}

	for _, testCase := range testCases {
		dpopToken := makeDPoPToken(s.T(), string(signedTok), testCase)
		dpopInfo := dpopInfo{
			headers: []string{dpopToken},
			path:    "/a/path",
			method:  "POST",
		}

		err = checkToken(context.Background(), []string{fmt.Sprintf("DPoP %s", string(signedTok))}, dpopInfo, *s.auth)

		if testCase.errorMesssage == "" {
			assert.Nil(s.T(), err)
		} else {
			assert.NotNil(s.T(), err)
			assert.Equal(s.T(), testCase.errorMesssage, err.Error())
		}
	}
}

func makeDPoPToken(t *testing.T, accessToken string, tc dpopTestCase) string {

	jtiBytes := make([]byte, JTILength)
	_, err := rand.Read(jtiBytes)
	if err != nil {
		t.Fatalf("error creating jti for dpop jwt: %v", err)
	}

	headers := jws.NewHeaders()
	err = headers.Set(jws.JWKKey, tc.key)
	if err != nil {
		t.Fatalf("error setting the key on the DPOP token: %v", err)
	}
	err = headers.Set(jws.TypeKey, tc.typ)
	if err != nil {
		t.Fatalf("error setting the type on the DPOP token: %v", err)
	}
	err = headers.Set(jws.AlgorithmKey, tc.alg)
	if err != nil {
		t.Fatalf("error setting the algorithm on the DPOP token: %v", err)
	}

	var ath string
	if tc.ath == "" {
		h := sha256.New()
		h.Write([]byte(accessToken))
		ath = base64.URLEncoding.EncodeToString(h.Sum(nil))
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
