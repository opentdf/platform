package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/creasty/defaults"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/kas"
	internalauthz "github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDPoPConfig_NormalizedTrustedOrigins(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		want    []string
		wantErr bool
	}{
		{name: "unset", in: nil, want: nil},
		{name: "https default port and case normalized", in: []string{"HTTPS://Platform.Example.COM:443/"}, want: []string{"https://platform.example.com"}},
		{name: "http non-default port kept", in: []string{"http://localhost:8080"}, want: []string{"http://localhost:8080"}},
		{name: "ipv6 literal", in: []string{"https://[::1]:8443"}, want: []string{"https://[::1]:8443"}},
		{name: "whitespace, empty entries and duplicates ignored", in: []string{" https://a.example ", "", "https://a.example:443", "https://b.example"}, want: []string{"https://a.example", "https://b.example"}},
		{name: "missing scheme", in: []string{"platform.example.com"}, wantErr: true},
		{name: "unsupported scheme", in: []string{"wss://platform.example.com"}, wantErr: true},
		{name: "missing host", in: []string{"https://"}, wantErr: true},
		{name: "port without host", in: []string{"https://:443"}, wantErr: true},
		{name: "path", in: []string{"https://platform.example.com/kas"}, wantErr: true},
		{name: "query", in: []string{"https://platform.example.com?x=1"}, wantErr: true},
		{name: "fragment", in: []string{"https://platform.example.com#x"}, wantErr: true},
		{name: "user info", in: []string{"https://user@platform.example.com"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DPoPConfig{TrustedOrigins: tt.in}
			got, err := cfg.normalizedTrustedOrigins()
			if tt.wantErr {
				require.Error(t, err)
				require.Error(t, cfg.Validate())
				return
			}
			require.NoError(t, err)
			require.NoError(t, cfg.Validate())
			assert.Equal(t, tt.want, got)
		})
	}
}

// newAuthWithDPoPConfig builds an authenticator against the suite's test IdP
// with the given DPoP settings.
func (s *AuthSuite) newAuthWithDPoPConfig(dpop DPoPConfig) *Authentication {
	policyCfg := internalauthz.PolicyConfig{ClientIDClaim: "cid"}
	s.Require().NoError(defaults.Set(&policyCfg))
	a, err := NewAuthenticator(
		s.T().Context(),
		Config{AuthNConfig: AuthNConfig{
			Issuer:    s.server.URL,
			Audience:  "test",
			DPoPSkew:  time.Hour,
			TokenSkew: time.Minute,
			Policy:    policyCfg,
			DPoP:      dpop,
		}},
		logger.CreateTestLogger(),
		func(_ string, _ any) error { return nil },
	)
	s.Require().NoError(err)
	return a
}

// dpopBoundCredential is an access token bound to a fresh DPoP key.
type dpopBoundCredential struct {
	key         jwk.Key
	accessToken []byte
}

func (s *AuthSuite) newDPoPBoundCredential() dpopBoundCredential {
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	key, err := jwk.FromRaw(raw)
	s.Require().NoError(err)
	s.Require().NoError(key.Set(jwk.AlgorithmKey, jwa.RS256))
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	s.Require().NoError(err)

	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", s.server.URL))
	s.Require().NoError(tok.Set("aud", "test"))
	s.Require().NoError(tok.Set("cid", "client-trusted-origins"))
	s.Require().NoError(tok.Set("cnf", map[string]string{
		"jkt": base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(thumbprint),
	}))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))
	s.Require().NoError(err)
	return dpopBoundCredential{key: key, accessToken: signed}
}

// proof mints a DPoP proof for htm/htu with a fresh jti.
func (s *AuthSuite) proof(c dpopBoundCredential, htm, htu string) string {
	pub, err := c.key.PublicKey()
	s.Require().NoError(err)
	return makeDPoPToken(s.T(), dpopTestCase{
		key:              pub,
		actualSigningKey: c.key,
		accessToken:      c.accessToken,
		alg:              jwa.RS256,
		typ:              dpopJWTType,
		htm:              htm,
		htu:              htu,
	})
}

var errStopAfterCapture = errors.New("stop after capturing receiver info")

// connectReceiverInfo returns the receiverInfo the Connect interceptor builds
// for a request to procedure carrying the given Host header.
func (s *AuthSuite) connectReceiverInfo(a *Authentication, procedure, host string) receiverInfo {
	var ri receiverInfo
	a._testCheckTokenFunc = func(_ context.Context, _ []string, got receiverInfo, _ []string) (jwt.Token, context.Context, error) {
		ri = got
		return nil, nil, errStopAfterCapture
	}
	defer func() { a._testCheckTokenFunc = nil }()

	req := &authnTestRequest{
		Request:    connect.NewRequest(&kas.RewrapRequest{}),
		procedure:  procedure,
		httpMethod: http.MethodPost,
	}
	req.Header().Set("Authorization", "DPoP token")
	req.Header().Set("Host", host)
	next := func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
		return connect.NewResponse(&kas.RewrapResponse{}), nil
	}
	_, err := a.ConnectAuthNInterceptor().WrapUnary(next)(s.T().Context(), req)
	s.Require().Error(err)
	return ri
}

// muxReceiverInfo returns the receiverInfo the HTTP handler builds for req.
func (s *AuthSuite) muxReceiverInfo(a *Authentication, req *http.Request) receiverInfo {
	var ri receiverInfo
	a._testCheckTokenFunc = func(_ context.Context, _ []string, got receiverInfo, _ []string) (jwt.Token, context.Context, error) {
		ri = got
		return nil, nil, errStopAfterCapture
	}
	defer func() { a._testCheckTokenFunc = nil }()

	req.Header.Set("Authorization", "DPoP token")
	a.MuxHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)
	return ri
}

func (s *AuthSuite) checkProof(a *Authentication, c dpopBoundCredential, ri receiverInfo, proof string) error {
	_, _, err := a.checkToken(s.T().Context(), []string{"DPoP " + string(c.accessToken)}, ri, []string{proof})
	return err
}

const (
	trustedOrigin  = "https://platform.example.com"
	rewrapProcPath = "/kas.AccessService/Rewrap"
)

// With trusted origins configured, the Connect interceptor builds the expected
// htu from configuration: a proof for the public URL is accepted whatever Host
// the request arrives with (direct, or rewritten by a proxy), and a proof for
// any other origin is rejected even when the Host header names that origin.
func (s *AuthSuite) Test_ConnectAuthN_TrustedOrigins() {
	for _, strict := range []bool{true, false} {
		a := s.newAuthWithDPoPConfig(DPoPConfig{Enforce: true, StrictHTU: strict, TrustedOrigins: []string{trustedOrigin}})
		c := s.newDPoPBoundCredential()

		for _, tc := range []struct {
			name    string
			host    string
			htu     string
			wantErr bool
		}{
			{"direct", "platform.example.com", trustedOrigin + rewrapProcPath, false},
			{"behind proxy with rewritten host", "platform.internal:8080", trustedOrigin + rewrapProcPath, false},
			{"proof for other origin, host names that origin", "other.example.com", "https://other.example.com" + rewrapProcPath, true},
			{"proof for other origin, host is public origin", "platform.example.com", "https://other.example.com" + rewrapProcPath, true},
			{"proof for public host over http", "platform.example.com", "http://platform.example.com" + rewrapProcPath, true},
		} {
			s.Run(fmt.Sprintf("strict=%t/%s", strict, tc.name), func() {
				ri := s.connectReceiverInfo(a, rewrapProcPath, tc.host)
				s.Equal([]string{trustedOrigin + rewrapProcPath}, ri.u)
				err := s.checkProof(a, c, ri, s.proof(c, http.MethodPost, tc.htu))
				if tc.wantErr {
					s.Require().Error(err)
					var proofErr *DPoPProofError
					s.Require().ErrorAs(err, &proofErr)
					s.Contains(err.Error(), "htu")
					return
				}
				s.Require().NoError(err)
			})
		}
	}
}

// With trusted origins configured, the HTTP handler ignores the request's
// Host/TLS state (and the Origin header) when building the expected htu.
func (s *AuthSuite) Test_MuxHandler_TrustedOrigins() {
	a := s.newAuthWithDPoPConfig(DPoPConfig{
		Enforce:        true,
		StrictHTU:      true,
		TrustedOrigins: []string{trustedOrigin, "http://localhost:8080"},
	})
	c := s.newDPoPBoundCredential()
	const path = "/attributes/example/value"

	direct := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, trustedOrigin+path, nil)
		r.TLS = &tls.ConnectionState{}
		return r
	}
	proxied := func() *http.Request {
		// TLS terminated upstream; plain HTTP to an internal host name.
		return httptest.NewRequest(http.MethodGet, "http://platform.internal:8080"+path, nil)
	}
	withOrigin := func(origin string) func() *http.Request {
		return func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "https://other.example.com"+path, nil)
			r.TLS = &tls.ConnectionState{}
			r.Header.Set("Origin", origin)
			return r
		}
	}

	for _, tc := range []struct {
		name    string
		req     func() *http.Request
		htu     string
		wantErr bool
	}{
		{"direct", direct, trustedOrigin + path, false},
		{"behind proxy", proxied, trustedOrigin + path, false},
		{"second trusted origin", proxied, "http://localhost:8080" + path, false},
		{"browser origin header does not affect expected htu", withOrigin("https://app.example.com"), trustedOrigin + path, false},
		{"proof for other origin, host names that origin", withOrigin(""), "https://other.example.com" + path, true},
		{"proof for other origin, origin header names that origin", withOrigin("https://other.example.com"), "https://other.example.com" + path, true},
		{"proof for public origin, other path", direct, trustedOrigin + "/attributes/other", true},
	} {
		s.Run(tc.name, func() {
			ri := s.muxReceiverInfo(a, tc.req())
			s.ElementsMatch([]string{trustedOrigin + path, "http://localhost:8080" + path}, ri.u)
			err := s.checkProof(a, c, ri, s.proof(c, http.MethodGet, tc.htu))
			if tc.wantErr {
				s.Require().Error(err)
				s.Contains(err.Error(), "htu")
				return
			}
			s.Require().NoError(err)
		})
	}
}

// Without trusted origins, the expected htu continues to come from the request
// so existing deployments keep accepting proofs for the URL they are reached at.
func (s *AuthSuite) Test_DPoP_NoTrustedOriginsUsesRequestOrigin() {
	a := s.newAuthWithDPoPConfig(DPoPConfig{Enforce: true, StrictHTU: true})
	c := s.newDPoPBoundCredential()

	ri := s.connectReceiverInfo(a, rewrapProcPath, "platform.example.com")
	s.Equal([]string{"http://platform.example.com" + rewrapProcPath, trustedOrigin + rewrapProcPath}, ri.u)
	s.Require().NoError(s.checkProof(a, c, ri, s.proof(c, http.MethodPost, trustedOrigin+rewrapProcPath)))

	req := httptest.NewRequest(http.MethodGet, trustedOrigin+"/attributes/example/value", nil)
	req.TLS = &tls.ConnectionState{}
	ri = s.muxReceiverInfo(a, req)
	s.Equal([]string{trustedOrigin + "/attributes/example/value"}, ri.u)
	s.Require().NoError(s.checkProof(a, c, ri, s.proof(c, http.MethodGet, trustedOrigin+"/attributes/example/value")))
}

func (s *AuthSuite) Test_NewAuthenticator_RejectsInvalidTrustedOrigins() {
	_, err := NewAuthenticator(
		s.T().Context(),
		Config{AuthNConfig: AuthNConfig{
			Issuer:   s.server.URL,
			Audience: "test",
			DPoP:     DPoPConfig{TrustedOrigins: []string{"https://platform.example.com/kas"}},
		}},
		logger.CreateTestLogger(),
		func(_ string, _ any) error { return nil },
	)
	s.Require().ErrorContains(err, "trusted_origins")
}

func TestDPoPOrigins(t *testing.T) {
	a := Authentication{}
	assert.Equal(t, []string{"https://req.example"}, a.dpopOrigins("https://req.example"))
	a.dpopTrustedOrigins = []string{trustedOrigin}
	assert.Equal(t, []string{trustedOrigin}, a.dpopOrigins("https://req.example"))
}

// The HTTP handler never uses the Origin request header: it names the calling
// page, not this server. Without trusted origins the expected htu comes from
// the request Host and TLS state only.
func (s *AuthSuite) Test_MuxHandler_IgnoresOriginHeader() {
	a := s.newAuthWithDPoPConfig(DPoPConfig{Enforce: true, StrictHTU: false})
	c := s.newDPoPBoundCredential()
	const path = "/attributes/example/value"

	newReq := func(origin string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, trustedOrigin+path, nil)
		r.TLS = &tls.ConnectionState{}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		return r
	}

	withoutOrigin := s.muxReceiverInfo(a, newReq(""))
	s.Equal([]string{trustedOrigin + path}, withoutOrigin.u)

	for _, origin := range []string{"https://app.example.com", "https://other.example.com", "null"} {
		s.Run(origin, func() {
			ri := s.muxReceiverInfo(a, newReq(origin))
			s.Equal(withoutOrigin.u, ri.u, "Origin header must not change the expected htu")
			s.Require().NoError(s.checkProof(a, c, ri, s.proof(c, http.MethodGet, trustedOrigin+path)))
			err := s.checkProof(a, c, ri, s.proof(c, http.MethodGet, origin+path))
			s.Require().Error(err)
		})
	}
}
