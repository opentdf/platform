package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
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
	server *httptest.Server
	key    jwk.Key
	auth   *authentication
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

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, *s.auth)
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
	err := checkToken(context.Background(), []string{"BPOP "}, *s.auth)
	assert.NotNil(s.T(), err)
	assert.Equal(s.T(), "not of type bearer or dpop", err.Error())
}

func (s *AuthSuite) Test_CheckToken_When_Missing_Issuer_Expect_Error() {
	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))

	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	assert.NotNil(s.T(), signedTok)
	assert.Nil(s.T(), err)

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, *s.auth)
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

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, *s.auth)
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

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, *s.auth)
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

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, *s.auth)
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

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, *s.auth)
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

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, *s.auth)
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

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, *s.auth)
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

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, *s.auth)
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

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, *s.auth)
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

	err = checkToken(context.Background(), []string{fmt.Sprintf("Bearer %s", string(signedTok))}, *s.auth)
	assert.Nil(s.T(), err)
}

func (s *AuthSuite) Test_CheckToken_When_Valid_CID_Expect_No_Error() {
	tok := jwt.New()
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	tok.Set("iss", s.server.URL)
	tok.Set("aud", "test")
	tok.Set("cid", "client2")
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))

	assert.NotNil(s.T(), signedTok)
	assert.Nil(s.T(), err)

	err = checkToken(context.Background(), []string{fmt.Sprintf("DPoP %s", string(signedTok))}, *s.auth)
	assert.Nil(s.T(), err)
}
