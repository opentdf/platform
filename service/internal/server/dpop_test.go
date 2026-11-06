package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/creasty/defaults"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	sdkauth "github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/logger"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/types/known/emptypb"
)

const taggingProcedure = "/tagging.pdp.v2.TaggingPDPService/Tag"

// The SDK signer accepts an explicit target URI, allowing this maintenance
// branch to reproduce the full-URL proofs produced by newer SDK transports.
type dpopTokenSource struct {
	key   jwk.Key
	token string
}

func (s dpopTokenSource) AccessToken(context.Context, *http.Client) (sdkauth.AccessToken, error) {
	return sdkauth.AccessToken(s.token), nil
}

func (s dpopTokenSource) MakeToken(sign func(jwk.Key) ([]byte, error)) ([]byte, error) {
	return sign(s.key)
}

func TestConnectDPoPFullURL(t *testing.T) {
	keyRaw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.FromRaw(keyRaw)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.ES256))
	require.NoError(t, key.Set(jwk.KeyIDKey, "dpop-test"))
	publicKey, err := key.PublicKey()
	require.NoError(t, err)
	keys := jwk.NewSet()
	require.NoError(t, keys.AddKey(publicKey))

	var issuerURL string
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			_ = json.NewEncoder(w).Encode(keys)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuerURL, "jwks_uri": issuerURL + "/jwks"})
	}))
	issuerURL = issuer.URL
	t.Cleanup(issuer.Close)

	thumbprint, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	signAccessToken := func(bound bool, role string) string {
		t.Helper()
		builder := jwt.NewBuilder().Issuer(issuer.URL).Audience([]string{"dpop-test"}).
			Subject("runtime-client").Expiration(time.Now().Add(time.Hour)).
			Claim("azp", "runtime-client").Claim("realm_access", map[string][]string{"roles": {role}})
		if bound {
			builder = builder.Claim("cnf", map[string]string{"jkt": base64.RawURLEncoding.EncodeToString(thumbprint)})
		}
		token, err := builder.Build()
		require.NoError(t, err)
		signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, key))
		require.NoError(t, err)
		return string(signed)
	}
	boundToken := signAccessToken(true, "opentdf-admin")
	bearerToken := signAccessToken(false, "opentdf-admin")
	forbiddenToken := signAccessToken(true, "opentdf-standard")
	log := logger.CreateTestLogger()
	config := Config{Auth: auth.Config{
		Enabled: true,
		AuthNConfig: auth.AuthNConfig{
			// Bound tokens must require a proof even when bearer clients are allowed.
			EnforceDPoP: false, Issuer: issuer.URL, Audience: "dpop-test",
			DPoPSkew: time.Minute, TokenSkew: time.Minute,
			Policy: auth.PolicyConfig{ClientIDClaim: "azp"},
		},
	}}
	require.NoError(t, defaults.Set(&config.Auth))
	authenticator, err := auth.NewAuthenticator(t.Context(), config.Auth, log, func(string, any) error { return nil })
	require.NoError(t, err)
	rpc, err := newConnectRPC(config, authenticator, log)
	require.NoError(t, err)
	rpc.Mux.Handle(taggingProcedure, connect.NewUnaryHandler(taggingProcedure,
		func(ctx context.Context, _ *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			if clientID, _ := ctxAuth.GetClientIDFromContext(ctx, true); clientID != "runtime-client" {
				return nil, connect.NewError(connect.CodeInternal, errors.New("unexpected client id"))
			}
			return connect.NewResponse(&emptypb.Empty{}), nil
		}, rpc.Interceptors...))
	production, err := newHTTPServer(config, rpc.Mux, http.NotFoundHandler(), authenticator, log)
	require.NoError(t, err)
	backend := httptest.NewServer(production.Handler)
	t.Cleanup(backend.Close)

	request := func(t *testing.T, client *http.Client, target, host, htu, token string, proof, forgedHeaders bool, status int) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target+taggingProcedure, strings.NewReader("{}"))
		require.NoError(t, err)
		if host != "" {
			req.Host = host
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Connect-Protocol-Version", "1")
		scheme := "Bearer "
		if proof {
			scheme = "DPoP "
			signer := sdkauth.NewTokenAddingInterceptorWithClient(dpopTokenSource{key: key, token: token}, client)
			dpop, err := signer.GetDPoPToken(htu, http.MethodPost, token)
			require.NoError(t, err)
			req.Header.Set("DPoP", dpop)
		}
		req.Header.Set("Authorization", scheme+token)
		if forgedHeaders {
			req.Header.Set("Origin", "https://other.example.test")
			req.Header.Set("X-Forwarded-Host", "other.example.test")
			req.Header.Set("Forwarded", "proto=https;host=other.example.test")
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, resp.Body.Close())
		require.NoError(t, err)
		require.Equal(t, status, resp.StatusCode, "%s", body)
	}

	for _, tt := range []struct {
		name, host, htu, token string
		proof, forgedHeaders   bool
		status                 int
	}{
		{"full URL", "", backend.URL + taggingProcedure, boundToken, true, false, http.StatusOK},
		{"legacy path", "", taggingProcedure, boundToken, true, false, http.StatusOK},
		{"https default port", "api.example.test:443", "https://API.EXAMPLE.TEST" + taggingProcedure, boundToken, true, false, http.StatusOK},
		{"http default port", "api.example.test:80", "http://api.example.test" + taggingProcedure, boundToken, true, false, http.StatusOK},
		{"nondefault public port", "api.example.test:8443", "https://api.example.test:8443" + taggingProcedure, boundToken, true, false, http.StatusOK},
		{"wrong host", "", "https://other.example.test" + taggingProcedure, boundToken, true, false, http.StatusUnauthorized},
		{"wrong host with forged headers", "", "https://other.example.test" + taggingProcedure, boundToken, true, true, http.StatusUnauthorized},
		{"missing nondefault port", "api.example.test:8443", "https://api.example.test" + taggingProcedure, boundToken, true, false, http.StatusUnauthorized},
		{"wrong path", "", backend.URL + "/other.Service/Tag", boundToken, true, false, http.StatusUnauthorized},
		{"missing bound proof", "", "", boundToken, false, false, http.StatusUnauthorized},
		{"bearer control", "", "", bearerToken, false, false, http.StatusOK},
		{"authorization still required", "", backend.URL + taggingProcedure, forbiddenToken, true, false, http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request(t, backend.Client(), backend.URL, tt.host, tt.htu, tt.token, tt.proof, tt.forgedHeaders, tt.status)
		})
	}

	t.Run("HTTP2 authority", func(t *testing.T) {
		transport := &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		}
		t.Cleanup(transport.CloseIdleConnections)
		request(t, &http.Client{Transport: transport}, backend.URL, "", backend.URL+taggingProcedure, boundToken, true, false, http.StatusOK)
	})

	t.Run("direct TLS", func(t *testing.T) {
		// Exercise the production TLS routing branch with an ephemeral certificate.
		certTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		cert, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &keyRaw.PublicKey, keyRaw)
		require.NoError(t, err)
		privateKey, err := x509.MarshalPKCS8PrivateKey(keyRaw)
		require.NoError(t, err)
		tlsConfig := config
		tlsConfig.TLS = TLSConfig{Enabled: true, Cert: filepath.Join(t.TempDir(), "cert.pem"), Key: filepath.Join(t.TempDir(), "key.pem")}
		require.NoError(t, os.WriteFile(tlsConfig.TLS.Cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0o600))
		require.NoError(t, os.WriteFile(tlsConfig.TLS.Key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}), 0o600))
		server, err := newHTTPServer(tlsConfig, rpc.Mux, http.NotFoundHandler(), authenticator, log)
		require.NoError(t, err)
		secure := httptest.NewUnstartedServer(server.Handler)
		secure.TLS = server.TLSConfig
		secure.StartTLS()
		t.Cleanup(secure.Close)
		request(t, secure.Client(), secure.URL, "", secure.URL+taggingProcedure, boundToken, true, false, http.StatusOK)
	})

	for _, preserveHost := range []bool{true, false} {
		name, status := "TLS termination preserves Host", http.StatusOK
		if !preserveHost {
			name, status = "TLS termination rewrites Host", http.StatusUnauthorized
		}
		t.Run(name, func(t *testing.T) {
			target, err := url.Parse(backend.URL)
			require.NoError(t, err)
			proxy := httputil.NewSingleHostReverseProxy(target)
			if !preserveHost {
				director := proxy.Director
				proxy.Director = func(req *http.Request) {
					director(req)
					req.Host = target.Host
				}
			}
			frontend := httptest.NewTLSServer(proxy)
			t.Cleanup(frontend.Close)
			request(t, frontend.Client(), frontend.URL, "", frontend.URL+taggingProcedure, boundToken, true, false, status)
		})
	}
}
