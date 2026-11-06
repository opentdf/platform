package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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
	privateKey, publicKeyJWK := newTokenVerifierKeyPair(t)
	require.NoError(t, publicKeyJWK.Set(jwk.AlgorithmKey, jwa.RS256))

	return newTokenVerifierFixtureWithPublicKey(t, privateKey, publicKeyJWK)
}

func newTokenVerifierFixtureWithoutPublicKeyAlgorithm(t *testing.T) *tokenVerifierFixture {
	privateKey, publicKeyJWK := newTokenVerifierKeyPair(t)
	require.NoError(t, publicKeyJWK.Remove(jwk.AlgorithmKey))
	_, hasAlgorithm := publicKeyJWK.Get(jwk.AlgorithmKey)
	require.False(t, hasAlgorithm)

	return newTokenVerifierFixtureWithPublicKey(t, privateKey, publicKeyJWK)
}

func newTokenVerifierKeyPair(t *testing.T) (*rsa.PrivateKey, jwk.Key) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	publicKeyJWK, err := jwk.FromRaw(privateKey.PublicKey)
	require.NoError(t, err)
	require.NoError(t, publicKeyJWK.Set(jws.KeyIDKey, "test-key"))

	return privateKey, publicKeyJWK
}

func newTokenVerifierFixtureWithPublicKey(t *testing.T, privateKey *rsa.PrivateKey, publicKeyJWK jwk.Key) *tokenVerifierFixture {
	t.Helper()

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

	now := time.Now()
	return f.signClaims(t, map[string]any{
		jwt.SubjectKey:    "user-123",
		jwt.IssuedAtKey:   now,
		jwt.ExpirationKey: now.Add(time.Hour),
		jwt.IssuerKey:     issuer,
		jwt.AudienceKey:   audience,
	}, signer)
}

func (f *tokenVerifierFixture) signClaims(t *testing.T, claims map[string]any, signer *rsa.PrivateKey) string {
	t.Helper()

	keyID := f.keyID
	if signer != f.privateKey {
		keyID = "other-key"
	}
	return signClaimsWithKeyID(t, claims, signer, keyID)
}

func signClaimsWithKeyID(t *testing.T, claims map[string]any, signer *rsa.PrivateKey, keyID string) string {
	t.Helper()

	token := jwt.New()
	for name, value := range claims {
		require.NoError(t, token.Set(name, value))
	}

	key, err := jwk.FromRaw(signer)
	require.NoError(t, err)

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
		missingAlgFixture := newTokenVerifierFixtureWithoutPublicKeyAlgorithm(t)

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

// newLoggingTokenVerifier returns a verifier for fixture whose log output is
// captured. Records emitted while constructing the verifier are discarded.
func newLoggingTokenVerifier(t *testing.T, fixture *tokenVerifierFixture, audience string) (*TokenVerifier, *bytes.Buffer) {
	t.Helper()

	var logs bytes.Buffer
	verifier, err := NewTokenVerifier(t.Context(), AuthNConfig{
		Issuer:       fixture.server.URL,
		Audience:     audience,
		CacheRefresh: "15m",
		TokenSkew:    time.Minute,
	}, &logger.Logger{Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	require.NoError(t, err)

	logs.Reset()
	return verifier, &logs
}

func warnRecords(t *testing.T, logs *bytes.Buffer) []map[string]any {
	t.Helper()

	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		if record[slog.LevelKey] == slog.LevelWarn.String() {
			records = append(records, record)
		}
	}
	return records
}

func TestTokenVerifier_VerifyAccessToken_LogsActionableFailure(t *testing.T) {
	fixture := newTokenVerifierFixture(t)
	verifier, logs := newLoggingTokenVerifier(t, fixture, "test-audience")

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Every token-derived value carries "INJECTED" so the test can prove none
	// of it reaches the remediation text. sub and email must never be logged.
	now := time.Now()
	claims := func(overrides map[string]any) map[string]any {
		c := map[string]any{
			jwt.SubjectKey:    "user-123",
			"email":           "user@example.com",
			jwt.IssuerKey:     fixture.server.URL,
			jwt.AudienceKey:   []string{"test-audience"},
			"azp":             "INJECTED-client",
			jwt.IssuedAtKey:   now,
			jwt.ExpirationKey: now.Add(time.Hour),
		}
		for name, value := range overrides {
			if value == nil {
				delete(c, name)
				continue
			}
			c[name] = value
		}
		return c
	}

	tests := []struct {
		name             string
		token            string
		wantMsg          string
		wantAttrs        map[string]any
		remediationNames []string
		remediationOmits []string
	}{
		{
			name:    "audience mismatch",
			token:   fixture.signClaims(t, claims(map[string]any{jwt.AudienceKey: []string{"INJECTED-aud"}}), fixture.privateKey),
			wantMsg: "access token audience mismatch",
			wantAttrs: map[string]any{
				"expected_audience": "test-audience",
				"token_aud":         []any{"INJECTED-aud"},
				"token_azp":         "INJECTED-client",
			},
			remediationNames: []string{"server.auth.audience", "OPENTDF_SERVER_AUTH_AUDIENCE", "Audience protocol mapper"},
			remediationOmits: []string{"ID token"},
		},
		{
			name:    "audience missing",
			token:   fixture.signClaims(t, claims(map[string]any{jwt.AudienceKey: nil}), fixture.privateKey),
			wantMsg: "access token audience mismatch",
			wantAttrs: map[string]any{
				"expected_audience": "test-audience",
				"token_azp":         "INJECTED-client",
			},
			remediationNames: []string{"server.auth.audience", "OPENTDF_SERVER_AUTH_AUDIENCE"},
		},
		{
			name:    "audience is the requesting client ID",
			token:   fixture.signClaims(t, claims(map[string]any{jwt.AudienceKey: []string{"INJECTED-client"}}), fixture.privateKey),
			wantMsg: "access token audience mismatch",
			wantAttrs: map[string]any{
				"expected_audience": "test-audience",
				"token_aud":         []any{"INJECTED-client"},
				"token_azp":         "INJECTED-client",
			},
			remediationNames: []string{"ID token", "server.auth.audience", "Audience protocol mapper"},
		},
		{
			name:    "issuer mismatch",
			token:   fixture.signClaims(t, claims(map[string]any{jwt.IssuerKey: "https://INJECTED.example.com"}), fixture.privateKey),
			wantMsg: "access token issuer mismatch",
			wantAttrs: map[string]any{
				"expected_issuer": fixture.server.URL,
				"token_iss":       "https://INJECTED.example.com",
			},
			remediationNames: []string{"server.auth.issuer", "OPENTDF_SERVER_AUTH_ISSUER"},
		},
		{
			name: "expired",
			token: fixture.signClaims(t, claims(map[string]any{
				jwt.IssuedAtKey:   now.Add(-3 * time.Hour),
				jwt.ExpirationKey: now.Add(-2 * time.Hour),
			}), fixture.privateKey),
			wantMsg:          "access token expired",
			wantAttrs:        map[string]any{"allowed_skew": "1m0s"},
			remediationNames: []string{"server.auth.skew", "NTP"},
		},
		{
			name:             "not yet valid",
			token:            fixture.signClaims(t, claims(map[string]any{jwt.NotBeforeKey: now.Add(2 * time.Hour)}), fixture.privateKey),
			wantMsg:          "access token not yet valid",
			wantAttrs:        map[string]any{"allowed_skew": "1m0s"},
			remediationNames: []string{"server.auth.skew", "NTP"},
		},
		{
			name:    "signature not verified",
			token:   fixture.signClaims(t, claims(nil), otherKey),
			wantMsg: "access token signature not verified",
			wantAttrs: map[string]any{
				"expected_issuer": fixture.server.URL,
				"token_kid":       "other-key",
				"token_alg":       "RS256",
			},
			remediationNames: []string{"server.auth.issuer", "server.auth.cache_refresh_interval"},
		},
		{
			name:    "malformed",
			token:   "INJECTED-not-a-jwt",
			wantMsg: "access token malformed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs.Reset()

			_, err := verifier.VerifyAccessToken(t.Context(), tc.token)
			require.Error(t, err)

			records := warnRecords(t, logs)
			require.Len(t, records, 1, "each failure logs exactly one WARN record")
			record := records[0]

			assert.Equal(t, tc.wantMsg, record[slog.MessageKey])
			for name, want := range tc.wantAttrs {
				assert.Equal(t, want, record[name], "attribute %s", name)
			}

			remediation, ok := record["remediation"].(string)
			require.True(t, ok, "remediation attribute is a string")
			assert.Contains(t, remediation, "'Troubleshooting access token errors'", "remediation names the troubleshooting section")
			assert.Contains(t, remediation, "bundled", "remediation points to the documentation shipped with the deployment")
			assert.NotContains(t, remediation, "docs/Configuring.md", "downstream deployments do not have this repository's paths")
			assert.NotContains(t, remediation, "https://", "docs are not referenced by a version-pinned URL")
			for _, name := range tc.remediationNames {
				assert.Contains(t, remediation, name)
			}
			for _, omitted := range tc.remediationOmits {
				assert.NotContains(t, remediation, omitted)
			}
			assert.NotContains(t, remediation, "INJECTED", "remediation is built from server configuration only")

			output := logs.String()
			assert.NotContains(t, output, tc.token, "the raw token is never logged")
			assert.NotContains(t, output, "user-123", "sub is never logged")
			assert.NotContains(t, output, "user@example.com", "email is never logged")
		})
	}
}

func TestTokenVerifier_VerifyAccessToken_TruncatesLoggedClaims(t *testing.T) {
	fixture := newTokenVerifierFixture(t)
	verifier, logs := newLoggingTokenVerifier(t, fixture, "test-audience")

	audiences := make([]string, 50)
	for i := range audiences {
		audiences[i] = fmt.Sprintf("aud-%d", i)
	}
	now := time.Now()
	token := fixture.signClaims(t, map[string]any{
		jwt.IssuerKey:     fixture.server.URL,
		jwt.AudienceKey:   audiences,
		"azp":             strings.Repeat("a", 5000),
		jwt.IssuedAtKey:   now,
		jwt.ExpirationKey: now.Add(time.Hour),
	}, fixture.privateKey)

	_, err := verifier.VerifyAccessToken(t.Context(), token)
	require.Error(t, err)

	records := warnRecords(t, logs)
	require.Len(t, records, 1)

	azp, ok := records[0]["token_azp"].(string)
	require.True(t, ok)
	assert.LessOrEqual(t, len(azp), 300, "long claim values are truncated")
	assert.True(t, strings.HasPrefix(azp, "aaaa"))

	aud, ok := records[0]["token_aud"].([]any)
	require.True(t, ok)
	assert.LessOrEqual(t, len(aud), 10, "the number of logged audiences is capped")
	assert.Equal(t, "aud-0", aud[0])
}

func TestTokenVerifier_VerifyAccessToken_TruncatesTokenDerivedErrorText(t *testing.T) {
	fixture := newTokenVerifierFixture(t)
	verifier, logs := newLoggingTokenVerifier(t, fixture, "test-audience")

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// jwx quotes an unknown kid in its key lookup error, so the err attribute
	// carries caller-controlled text.
	now := time.Now()
	token := signClaimsWithKeyID(t, map[string]any{
		jwt.IssuerKey:     fixture.server.URL,
		jwt.AudienceKey:   []string{"test-audience"},
		jwt.IssuedAtKey:   now,
		jwt.ExpirationKey: now.Add(time.Hour),
	}, otherKey, strings.Repeat("k", 5000))

	_, err = verifier.VerifyAccessToken(t.Context(), token)
	require.Error(t, err)

	records := warnRecords(t, logs)
	require.Len(t, records, 1)
	assert.Equal(t, "access token signature not verified", records[0][slog.MessageKey])

	errText, ok := records[0]["err"].(string)
	require.True(t, ok)
	assert.LessOrEqual(t, len(errText), 300, "token-derived text in err is truncated")
	assert.Contains(t, errText, "failed to find key with key ID", "err keeps the leading diagnostic detail")

	kid, ok := records[0]["token_kid"].(string)
	require.True(t, ok)
	assert.LessOrEqual(t, len(kid), 300)
}

func TestTokenVerifier_VerifyAccessToken_WarnsOnceWhenAudienceIsRequestingClient(t *testing.T) {
	fixture := newTokenVerifierFixture(t)
	verifier, logs := newLoggingTokenVerifier(t, fixture, "opentdf-sdk")

	now := time.Now()
	token := fixture.signClaims(t, map[string]any{
		jwt.SubjectKey:    "user-123",
		jwt.IssuerKey:     fixture.server.URL,
		jwt.AudienceKey:   []string{"opentdf-sdk"},
		"azp":             "opentdf-sdk",
		jwt.IssuedAtKey:   now,
		jwt.ExpirationKey: now.Add(time.Hour),
	}, fixture.privateKey)

	for range 3 {
		_, err := verifier.VerifyAccessToken(t.Context(), token)
		require.NoError(t, err)
	}

	records := warnRecords(t, logs)
	require.Len(t, records, 1, "the warning is logged once, not per request")
	assert.Equal(t, "access token audience is the requesting client ID", records[0][slog.MessageKey])
	assert.Equal(t, "opentdf-sdk", records[0]["expected_audience"])

	remediation, ok := records[0]["remediation"].(string)
	require.True(t, ok)
	assert.Contains(t, remediation, "ID token")
	assert.Contains(t, remediation, "server.auth.audience")
}

func TestTokenVerifier_VerifyAccessToken_NoWarningWhenAudienceIsDistinctAPI(t *testing.T) {
	fixture := newTokenVerifierFixture(t)
	// Microsoft Entra ID v2 access tokens carry the API app registration's
	// client ID as aud, which differs from the calling client's azp.
	verifier, logs := newLoggingTokenVerifier(t, fixture, "11111111-1111-1111-1111-111111111111")

	now := time.Now()
	token := fixture.signClaims(t, map[string]any{
		jwt.IssuerKey:     fixture.server.URL,
		jwt.AudienceKey:   []string{"11111111-1111-1111-1111-111111111111"},
		"azp":             "22222222-2222-2222-2222-222222222222",
		jwt.IssuedAtKey:   now,
		jwt.ExpirationKey: now.Add(time.Hour),
	}, fixture.privateKey)

	_, err := verifier.VerifyAccessToken(t.Context(), token)
	require.NoError(t, err)
	assert.Empty(t, warnRecords(t, logs))
}
