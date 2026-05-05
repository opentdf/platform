package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tokenVerifierFixture struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	keyID      string
}

func newTokenVerifierFixture(t *testing.T) *tokenVerifierFixture {
	return newTokenVerifierFixtureWithOptions(t, true)
}

func newTokenVerifierFixtureWithOptions(t *testing.T, includeAlgorithm bool) *tokenVerifierFixture {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	publicKeyJWK, err := jwk.FromRaw(privateKey.PublicKey)
	require.NoError(t, err)
	require.NoError(t, publicKeyJWK.Set(jws.KeyIDKey, "test-key"))
	if includeAlgorithm {
		require.NoError(t, publicKeyJWK.Set(jwk.AlgorithmKey, jwa.RS256))
	}

	keySet := jwk.NewSet()
	require.NoError(t, keySet.AddKey(publicKeyJWK))

	fixture := &tokenVerifierFixture{
		privateKey: privateKey,
		keyID:      "test-key",
	}

	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case DiscoveryPath, "/alias" + DiscoveryPath:
			if err := json.NewEncoder(w).Encode(map[string]string{
				"issuer":   fixture.server.URL,
				"jwks_uri": fixture.server.URL + "/jwks",
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		case "/jwks":
			if err := json.NewEncoder(w).Encode(keySet); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		default:
			http.NotFound(w, r)
		}
	}))

	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *tokenVerifierFixture) signToken(t *testing.T, issuer, audience string, signer *rsa.PrivateKey) string {
	t.Helper()

	token := jwt.New()
	now := time.Now()

	require.NoError(t, token.Set(jwt.SubjectKey, "user-123"))
	require.NoError(t, token.Set(jwt.IssuedAtKey, now))
	require.NoError(t, token.Set(jwt.ExpirationKey, now.Add(time.Hour)))
	require.NoError(t, token.Set(jwt.IssuerKey, issuer))
	require.NoError(t, token.Set(jwt.AudienceKey, audience))

	key, err := jwk.FromRaw(signer)
	require.NoError(t, err)

	keyID := f.keyID
	if signer != f.privateKey {
		keyID = "other-key"
	}

	require.NoError(t, key.Set(jws.KeyIDKey, keyID))
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.RS256))

	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, key))
	require.NoError(t, err)

	return string(signedToken)
}

func TestNewTokenVerifier_UsesDiscoveredIssuer(t *testing.T) {
	fixture := newTokenVerifierFixture(t)

	verifier, err := NewTokenVerifier(t.Context(), AuthNConfig{
		Issuer:       fixture.server.URL + "/alias",
		Audience:     "test-audience",
		CacheRefresh: "15m",
		TokenSkew:    time.Minute,
	}, logger.CreateTestLogger())
	require.NoError(t, err)

	assert.Equal(t, fixture.server.URL, verifier.oidcConfiguration.Issuer)

	token := fixture.signToken(t, fixture.server.URL, "test-audience", fixture.privateKey)
	verifiedToken, err := verifier.VerifyAccessToken(t.Context(), token)
	require.NoError(t, err)
	assert.Equal(t, "user-123", verifiedToken.Subject())
}

func TestTokenVerifier_VerifyAccessToken(t *testing.T) {
	fixture := newTokenVerifierFixture(t)

	verifier, err := NewTokenVerifier(t.Context(), AuthNConfig{
		Issuer:       fixture.server.URL,
		Audience:     "test-audience",
		CacheRefresh: "15m",
		TokenSkew:    time.Minute,
	}, logger.CreateTestLogger())
	require.NoError(t, err)

	t.Run("valid token", func(t *testing.T) {
		token := fixture.signToken(t, fixture.server.URL, "test-audience", fixture.privateKey)

		verifiedToken, err := verifier.VerifyAccessToken(t.Context(), token)
		require.NoError(t, err)
		assert.Equal(t, "user-123", verifiedToken.Subject())
	})

	t.Run("invalid audience", func(t *testing.T) {
		token := fixture.signToken(t, fixture.server.URL, "wrong-audience", fixture.privateKey)

		_, err := verifier.VerifyAccessToken(t.Context(), token)
		require.Error(t, err)
		assert.ErrorContains(t, err, "\"aud\"")
	})

	t.Run("invalid signature", func(t *testing.T) {
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		token := fixture.signToken(t, fixture.server.URL, "test-audience", otherKey)

		_, err = verifier.VerifyAccessToken(t.Context(), token)
		require.Error(t, err)
	})

	t.Run("valid token with JWKS key missing alg", func(t *testing.T) {
		missingAlgFixture := newTokenVerifierFixtureWithOptions(t, false)

		missingAlgVerifier, err := NewTokenVerifier(t.Context(), AuthNConfig{
			Issuer:       missingAlgFixture.server.URL,
			Audience:     "test-audience",
			CacheRefresh: "15m",
			TokenSkew:    time.Minute,
		}, logger.CreateTestLogger())
		require.NoError(t, err)

		token := missingAlgFixture.signToken(t, missingAlgFixture.server.URL, "test-audience", missingAlgFixture.privateKey)

		verifiedToken, err := missingAlgVerifier.VerifyAccessToken(t.Context(), token)
		require.NoError(t, err)
		assert.Equal(t, "user-123", verifiedToken.Subject())
	})
}

func TestTokenVerifier_NilHandling(t *testing.T) {
	authn := &Authentication{}
	assert.Nil(t, authn.AccessTokenVerifier())

	var verifier *TokenVerifier
	_, err := verifier.VerifyAccessToken(t.Context(), "token")
	require.ErrorIs(t, err, errNilTokenVerifier)
}
