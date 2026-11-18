package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/creasty/defaults"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

// TestNewOpenTDFServer_DPoPBoundTokenUnderBearer drives a full server with a
// DPoP-bound access token (cnf.jkt) and a valid DPoP proof, varying only the
// Authorization scheme and server.auth.dpop.strict_scheme (DSPX-3573).
func TestNewOpenTDFServer_DPoPBoundTokenUnderBearer(t *testing.T) {
	const procedure = "/test.v1.TestService/Method"

	tests := []struct {
		name         string
		strictScheme bool
		scheme       string
		wantStatus   int
	}{
		{"default accepts Bearer with a warning", false, "Bearer", http.StatusOK},
		{"strict_scheme rejects Bearer", true, "Bearer", http.StatusUnauthorized},
		{"strict_scheme accepts DPoP", true, "DPoP", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oidc, signingKey := newSigningOIDCServer(t)
			policyCfg := authz.PolicyConfig{}
			require.NoError(t, defaults.Set(&policyCfg))
			cfg := Config{
				WellKnownConfigRegister: func(string, any) error { return nil },
				Auth: auth.Config{
					Enabled: true,
					AuthNConfig: auth.AuthNConfig{
						Issuer:    oidc.URL,
						Audience:  "test",
						Policy:    policyCfg,
						DPoPSkew:  time.Hour,
						TokenSkew: time.Minute,
						DPoP:      auth.DPoPConfig{StrictScheme: tt.strictScheme},
					},
				},
			}
			srv, err := NewOpenTDFServer(cfg, logger.CreateTestLogger(), nil)
			require.NoError(t, err)

			var called atomic.Bool
			srv.ConnectRPC.Mux.Handle("/test.v1.TestService/", connect.NewUnaryHandler(
				procedure,
				func(context.Context, *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
					called.Store(true)
					return connect.NewResponse(&emptypb.Empty{}), nil
				},
				srv.ConnectRPC.Interceptors...,
			))

			dpopKey := newRSAJWK(t)
			accessToken := mintDPoPBoundAccessToken(t, oidc.URL, signingKey, dpopKey)

			req := httptest.NewRequest(http.MethodPost, procedure, bytes.NewReader(nil))
			req.Header.Set("Content-Type", "application/proto")
			req.Header.Set("Authorization", tt.scheme+" "+accessToken)
			req.Header.Set("DPoP", mintDPoPProof(t, dpopKey, accessToken, procedure))
			rr := httptest.NewRecorder()
			srv.HTTPServer.Handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.wantStatus, rr.Code, rr.Body.String())
			assert.Equal(t, tt.wantStatus == http.StatusOK, called.Load())
			if tt.wantStatus == http.StatusUnauthorized {
				assert.Equal(t,
					`DPoP error="invalid_token", error_description="DPoP-bound access token requires the DPoP authorization scheme"`,
					rr.Header().Get("WWW-Authenticate"))
				assert.NotContains(t, rr.Body.String(), accessToken)
			}
		})
	}
}

// newSigningOIDCServer serves OIDC discovery and a key set holding the public
// half of the returned signing key, so tests can mint verifiable access tokens.
func newSigningOIDCServer(t *testing.T) (*httptest.Server, jwk.Key) {
	t.Helper()
	signingKey := newRSAJWK(t)
	require.NoError(t, signingKey.Set(jwk.KeyIDKey, "test"))
	pub, err := signingKey.PublicKey()
	require.NoError(t, err)
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, srv.URL, srv.URL+"/jwks")
		case "/jwks":
			_ = json.NewEncoder(w).Encode(set)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, signingKey
}

func newRSAJWK(t *testing.T) jwk.Key {
	t.Helper()
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key, err := jwk.FromRaw(raw)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.RS256))
	return key
}

// mintDPoPBoundAccessToken issues an admin access token bound (cnf.jkt) to dpopKey.
func mintDPoPBoundAccessToken(t *testing.T, issuer string, signingKey, dpopKey jwk.Key) string {
	t.Helper()
	thumbprint, err := dpopKey.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	tok := jwt.New()
	require.NoError(t, tok.Set(jwt.IssuerKey, issuer))
	require.NoError(t, tok.Set(jwt.AudienceKey, "test"))
	require.NoError(t, tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	require.NoError(t, tok.Set("azp", "dpop-scheme-test"))
	require.NoError(t, tok.Set("realm_access", map[string][]string{"roles": {"opentdf-admin"}}))
	require.NoError(t, tok.Set("cnf", map[string]string{"jkt": base64.RawURLEncoding.EncodeToString(thumbprint)}))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, signingKey))
	require.NoError(t, err)
	return string(signed)
}

// mintDPoPProof signs a valid DPoP proof for a POST to htu, bound to accessToken.
func mintDPoPProof(t *testing.T, dpopKey jwk.Key, accessToken, htu string) string {
	t.Helper()
	pub, err := dpopKey.PublicKey()
	require.NoError(t, err)
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.JWKKey, pub))
	require.NoError(t, headers.Set(jws.TypeKey, "dpop+jwt"))
	require.NoError(t, headers.Set(jws.AlgorithmKey, jwa.RS256))
	ath := sha256.Sum256([]byte(accessToken))
	proof, err := jwt.NewBuilder().
		JwtID(rand.Text()).
		Claim("htm", http.MethodPost).
		Claim("htu", htu).
		Claim("ath", base64.RawURLEncoding.EncodeToString(ath[:])).
		IssuedAt(time.Now()).
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(proof, jwt.WithKey(jwa.RS256, dpopKey, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return string(signed)
}
