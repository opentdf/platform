package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	sdkauth "github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDPoPNonceManager(t *testing.T) {
	t.Run("nonce generation", func(t *testing.T) {
		nm := newDPoPNonceManager(true, 5*time.Minute)
		nonce1 := nm.getCurrentNonce()
		assert.NotEmpty(t, nonce1)
		assert.Len(t, nonce1, 32) // 16 bytes hex encoded = 32 chars
	})

	t.Run("nonce rotation", func(t *testing.T) {
		nm := newDPoPNonceManager(true, 100*time.Millisecond)
		nonce1 := nm.getCurrentNonce()

		time.Sleep(150 * time.Millisecond)

		nonce2 := nm.getCurrentNonce()
		assert.NotEqual(t, nonce1, nonce2, "nonce should rotate after expiration")
	})

	t.Run("nonce validation window", func(t *testing.T) {
		nm := newDPoPNonceManager(true, 5*time.Minute)
		currentNonce := nm.getCurrentNonce()

		assert.True(t, nm.validateNonce(currentNonce))

		// Rotate to create a previous nonce; both current and previous must be accepted
		// to tolerate in-flight requests that received the old nonce just before rotation.
		nm.rotate()
		newNonce := nm.getCurrentNonce()

		assert.True(t, nm.validateNonce(newNonce), "current nonce should validate")
		assert.True(t, nm.validateNonce(currentNonce), "previous nonce should validate")

		// After a second rotation the original nonce is evicted.
		nm.rotate()
		assert.False(t, nm.validateNonce(currentNonce), "nonce older than previous should not validate")
	})

	t.Run("empty nonce rejected when required", func(t *testing.T) {
		nm := newDPoPNonceManager(true, 5*time.Minute)
		assert.False(t, nm.validateNonce(""), "empty nonce must not match initial empty previousNonce")
	})

	t.Run("disabled nonces", func(t *testing.T) {
		nm := newDPoPNonceManager(false, 5*time.Minute)
		assert.True(t, nm.validateNonce("any-random-nonce"))
		assert.True(t, nm.validateNonce(""))
	})
}

func TestDPoPNonceError(t *testing.T) {
	t.Run("nonce error message", func(t *testing.T) {
		err := &DPoPNonceError{Message: "test error"}
		assert.Equal(t, "test error", err.Error())
	})

	t.Run("nonce error detection via errors.As", func(t *testing.T) {
		var err error = &DPoPNonceError{Message: "test"}
		var nonceErr *DPoPNonceError
		require.ErrorAs(t, err, &nonceErr)
		assert.Equal(t, "test", nonceErr.Message)
	})

	t.Run("malformed error message", func(t *testing.T) {
		err := &DPoPNonceMalformedError{Message: "bad nonce"}
		assert.Equal(t, "bad nonce", err.Error())
	})

	t.Run("malformed error detection via errors.As", func(t *testing.T) {
		var err error = &DPoPNonceMalformedError{Message: "bad nonce"}
		var malformedErr *DPoPNonceMalformedError
		require.ErrorAs(t, err, &malformedErr)
	})

	t.Run("malformed error does not match DPoPNonceError", func(t *testing.T) {
		// Critical: DPoPNonceMalformedError must NOT match DPoPNonceError so handlers
		// treat it as a hard rejection rather than issuing a nonce challenge.
		var err error = &DPoPNonceMalformedError{Message: "bad nonce"}
		var nonceErr *DPoPNonceError
		assert.NotErrorAs(t, err, &nonceErr)
	})
}

func TestDPoPAlgorithmRestrictions(t *testing.T) {
	testCases := []struct {
		alg     jwa.SignatureAlgorithm
		allowed bool
	}{
		{jwa.RS256, true},
		{jwa.RS384, true},
		{jwa.RS512, true},
		{jwa.ES256, true},
		{jwa.ES384, true},
		{jwa.ES512, true},
		{jwa.PS256, true},
		{jwa.PS384, true},
		{jwa.PS512, true},
		{jwa.HS256, false},
		{jwa.NoSignature, false},
	}

	for _, tc := range testCases {
		t.Run(tc.alg.String(), func(t *testing.T) {
			_, exists := allowedSignatureAlgorithms[tc.alg]
			assert.Equal(t, tc.allowed, exists)
		})
	}
}

// newAuthWithNonce creates an Authentication using the suite's OIDC server with RequireNonce=true.
func (s *AuthSuite) newAuthWithNonce() *Authentication {
	auth, err := NewAuthenticator(
		context.Background(),
		Config{
			AuthNConfig: AuthNConfig{
				EnforceDPoP: true,
				Issuer:      s.server.URL,
				Audience:    "test",
				DPoPSkew:    time.Hour,
				TokenSkew:   time.Minute,
				DPoP: DPoPConfig{
					RequireNonce:    true,
					NonceExpiration: 5 * time.Minute,
					StrictHTU:       false,
				},
			},
		},
		logger.CreateTestLogger(),
		func(_ string, _ any) error { return nil },
	)
	s.Require().NoError(err)
	return auth
}

// makeDPoPBoundAccessToken creates an access token with cnf.jkt bound to dpopKey,
// signed by the suite's OIDC key.
func (s *AuthSuite) makeDPoPBoundAccessToken(dpopKey jwk.Key) []byte {
	thumbprint, err := dpopKey.Thumbprint(crypto.SHA256)
	s.Require().NoError(err)
	jkt := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(thumbprint)

	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", s.server.URL))
	s.Require().NoError(tok.Set("aud", "test"))
	s.Require().NoError(tok.Set("cid", "client-nonce-test"))
	s.Require().NoError(tok.Set("cnf", map[string]string{"jkt": jkt}))

	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))
	s.Require().NoError(err)
	return signedTok
}

// makeDPoPProof builds a signed DPoP proof. nonceVal may be nil (omit nonce), a string,
// or any other type (to produce a malformed nonce claim for testing).
func makeDPoPProof(t *testing.T, tc dpopTestCase, nonceVal any) string {
	t.Helper()
	jtiBytes := make([]byte, sdkauth.JTILength)
	_, err := rand.Read(jtiBytes)
	require.NoError(t, err)

	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.JWKKey, tc.key))
	require.NoError(t, headers.Set(jws.TypeKey, tc.typ))
	require.NoError(t, headers.Set(jws.AlgorithmKey, tc.alg))

	h := sha256.New()
	h.Write(tc.accessToken)
	ath := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h.Sum(nil))

	b := jwt.NewBuilder().
		Claim("htu", tc.htu).
		Claim("htm", tc.htm).
		Claim("ath", ath).
		Claim("jti", base64.StdEncoding.EncodeToString(jtiBytes)).
		IssuedAt(time.Now())

	if nonceVal != nil {
		b = b.Claim("nonce", nonceVal)
	}

	dpopTok, err := b.Build()
	require.NoError(t, err)

	signedToken, err := jwt.Sign(dpopTok, jwt.WithKey(tc.actualSigningKey.Algorithm(), tc.actualSigningKey, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return string(signedToken)
}

func (s *AuthSuite) newDPoPKeyAndAccessToken() (jwk.Key, jwk.Key, []byte) {
	dpopKeyRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	dpopKey, err := jwk.FromRaw(dpopKeyRaw)
	s.Require().NoError(err)
	s.Require().NoError(dpopKey.Set(jwk.AlgorithmKey, jwa.RS256))
	dpopPublic, err := dpopKey.PublicKey()
	s.Require().NoError(err)
	signedTok := s.makeDPoPBoundAccessToken(dpopKey)
	return dpopKey, dpopPublic, signedTok
}

func (s *AuthSuite) TestDPoP_MissingNonce_Returns_DPoPNonceError() {
	auth := s.newAuthWithNonce()
	dpopKey, dpopPublic, signedTok := s.newDPoPKeyAndAccessToken()

	dpopToken := makeDPoPProof(s.T(), dpopTestCase{
		key: dpopPublic, actualSigningKey: dpopKey, accessToken: signedTok,
		alg: jwa.RS256, typ: dpopJWTType, htm: http.MethodPost, htu: "/a/path",
	}, nil) // no nonce claim

	_, _, err := auth.checkToken(
		context.Background(),
		[]string{"DPoP " + string(signedTok)},
		receiverInfo{u: []string{"/a/path"}, m: []string{http.MethodPost}},
		[]string{dpopToken},
	)

	var nonceErr *DPoPNonceError
	s.Require().ErrorAs(err, &nonceErr, "missing nonce must return DPoPNonceError so handlers issue a challenge")
}

func (s *AuthSuite) TestDPoP_ValidNonce_Succeeds() {
	auth := s.newAuthWithNonce()
	dpopKey, dpopPublic, signedTok := s.newDPoPKeyAndAccessToken()

	nonce := auth.dpopNonceManager.getCurrentNonce()

	dpopToken := makeDPoPProof(s.T(), dpopTestCase{
		key: dpopPublic, actualSigningKey: dpopKey, accessToken: signedTok,
		alg: jwa.RS256, typ: dpopJWTType, htm: http.MethodPost, htu: "/a/path",
	}, nonce)

	_, _, err := auth.checkToken(
		context.Background(),
		[]string{"DPoP " + string(signedTok)},
		receiverInfo{u: []string{"/a/path"}, m: []string{http.MethodPost}},
		[]string{dpopToken},
	)

	s.Require().NoError(err, "correct nonce should pass validation")
}

func (s *AuthSuite) TestDPoP_MalformedNonce_Returns_DPoPNonceMalformedError() {
	auth := s.newAuthWithNonce()
	dpopKey, dpopPublic, signedTok := s.newDPoPKeyAndAccessToken()

	// Integer nonce triggers the type-assertion failure in validateDPoP.
	dpopToken := makeDPoPProof(s.T(), dpopTestCase{
		key: dpopPublic, actualSigningKey: dpopKey, accessToken: signedTok,
		alg: jwa.RS256, typ: dpopJWTType, htm: http.MethodPost, htu: "/a/path",
	}, 42)

	_, _, err := auth.checkToken(
		context.Background(),
		[]string{"DPoP " + string(signedTok)},
		receiverInfo{u: []string{"/a/path"}, m: []string{http.MethodPost}},
		[]string{dpopToken},
	)

	var malformedErr *DPoPNonceMalformedError
	s.Require().ErrorAs(err, &malformedErr, "non-string nonce must return DPoPNonceMalformedError, not a retryable DPoPNonceError")

	// Confirm it does NOT match DPoPNonceError, so handlers hard-reject rather than issue a challenge.
	var nonceErr *DPoPNonceError
	s.Require().NotErrorAs(err, &nonceErr)
}

func (s *AuthSuite) TestDPoP_WrongNonce_Returns_DPoPNonceError() {
	auth := s.newAuthWithNonce()
	dpopKey, dpopPublic, signedTok := s.newDPoPKeyAndAccessToken()

	dpopToken := makeDPoPProof(s.T(), dpopTestCase{
		key: dpopPublic, actualSigningKey: dpopKey, accessToken: signedTok,
		alg: jwa.RS256, typ: dpopJWTType, htm: http.MethodPost, htu: "/a/path",
	}, "not-the-right-nonce")

	_, _, err := auth.checkToken(
		context.Background(),
		[]string{"DPoP " + string(signedTok)},
		receiverInfo{u: []string{"/a/path"}, m: []string{http.MethodPost}},
		[]string{dpopToken},
	)

	var nonceErr *DPoPNonceError
	s.Require().ErrorAs(err, &nonceErr, "wrong nonce must return DPoPNonceError so handlers issue a fresh challenge")
}
