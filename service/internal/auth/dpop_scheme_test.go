package auth

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/service/logger"
)

const (
	dpopSchemeTestPath = "/a/path"
	bearerSchemeWarn   = "DPoP-bound access token presented under Bearer Authorization scheme; per RFC 9449 §7.1 the DPoP scheme is required"
)

// newAuthDPoPScheme builds an authenticator with the given DPoP settings whose
// log output is captured in logs.
func (s *AuthSuite) newAuthDPoPScheme(enforce, strictScheme, requireNonce bool, logs *bytes.Buffer) *Authentication {
	auth, err := NewAuthenticator(
		s.T().Context(),
		Config{
			AuthNConfig: AuthNConfig{
				Issuer:    s.server.URL,
				Audience:  "test",
				DPoPSkew:  time.Hour,
				TokenSkew: time.Minute,
				DPoP: DPoPConfig{
					Enforce:         enforce,
					RequireNonce:    requireNonce,
					NonceExpiration: 5 * time.Minute,
					StrictScheme:    strictScheme,
				},
			},
		},
		&logger.Logger{Logger: slog.New(slog.NewJSONHandler(logs, nil))},
		func(_ string, _ any) error { return nil },
	)
	s.Require().NoError(err)
	return auth
}

// signDPoPProof mints a fresh (unique jti) proof for a POST to htu bound to accessToken.
func (s *AuthSuite) signDPoPProof(dpopKey, dpopPublic jwk.Key, accessToken []byte, htu string) string {
	return makeDPoPProof(s.T(), dpopTestCase{
		key: dpopPublic, actualSigningKey: dpopKey, accessToken: accessToken,
		alg: jwa.RS256, typ: dpopJWTType, htm: http.MethodPost, htu: htu,
	}, nil)
}

func (s *AuthSuite) checkTokenWithScheme(auth *Authentication, scheme string, accessToken []byte, proof string) error {
	var dpopHeader []string
	if proof != "" {
		dpopHeader = []string{proof}
	}
	_, _, err := auth.checkToken(
		s.T().Context(),
		[]string{scheme + " " + string(accessToken)},
		receiverInfo{u: []string{dpopSchemeTestPath}, m: []string{http.MethodPost}},
		dpopHeader,
	)
	return err
}

func (s *AuthSuite) assertBearerSchemeRejection(err error) {
	s.Require().Error(err)
	s.Require().ErrorIs(err, errDPoPBoundTokenUnderBearer)
	var proofErr *DPoPProofError
	s.Require().ErrorAs(err, &proofErr)
	s.Equal(dpopBearerSchemeChallenge, proofErr.challenge())
}

// By default a DPoP-bound token with a valid proof under Bearer is still accepted,
// with a warning (web-sdk compatibility). The warning text is matched by xtest.
func (s *AuthSuite) Test_CheckToken_BearerSchemeWithCNF_WarnsByDefault() {
	var logs bytes.Buffer
	auth := s.newAuthDPoPScheme(true, false, false, &logs)
	dpopKey, dpopPublic, signedTok := s.newDPoPKeyAndAccessToken()
	proof := s.signDPoPProof(dpopKey, dpopPublic, signedTok, dpopSchemeTestPath)

	err := s.checkTokenWithScheme(auth, "Bearer", signedTok, proof)

	s.Require().NoError(err)
	s.Contains(logs.String(), bearerSchemeWarn)
	s.NotContains(logs.String(), string(signedTok))
	s.NotContains(logs.String(), proof)
}

// With dpop.strict_scheme a DPoP-bound token under Bearer is rejected even with a
// valid proof, for both enforced and unenforced DPoP, without logging credentials.
func (s *AuthSuite) Test_CheckToken_BearerSchemeWithCNF_RejectedWhenStrict() {
	for _, enforce := range []bool{true, false} {
		s.Run(fmt.Sprintf("enforce=%t", enforce), func() {
			var logs bytes.Buffer
			auth := s.newAuthDPoPScheme(enforce, true, false, &logs)
			dpopKey, dpopPublic, signedTok := s.newDPoPKeyAndAccessToken()
			proof := s.signDPoPProof(dpopKey, dpopPublic, signedTok, dpopSchemeTestPath)

			err := s.checkTokenWithScheme(auth, "Bearer", signedTok, proof)

			s.assertBearerSchemeRejection(err)
			s.Contains(logs.String(), "rejected DPoP-bound access token presented under Bearer Authorization scheme")
			s.NotContains(logs.String(), bearerSchemeWarn, "reject mode must not also emit the warn-mode message")
			s.NotContains(logs.String(), string(signedTok))
			s.NotContains(logs.String(), proof)
		})
	}
}

// The scheme check fires before proof validation, so a missing proof yields the
// same scheme rejection rather than a proof error.
func (s *AuthSuite) Test_CheckToken_BearerSchemeWithCNF_NoProof_RejectedWhenStrict() {
	var logs bytes.Buffer
	auth := s.newAuthDPoPScheme(true, true, false, &logs)
	_, _, signedTok := s.newDPoPKeyAndAccessToken()

	s.assertBearerSchemeRejection(s.checkTokenWithScheme(auth, "Bearer", signedTok, ""))
}

// With require_nonce the scheme rejection wins over the use_dpop_nonce challenge:
// retrying with a nonce cannot make a Bearer presentation acceptable.
func (s *AuthSuite) Test_CheckToken_BearerSchemeWithCNF_RejectedBeforeNonceChallenge() {
	var logs bytes.Buffer
	auth := s.newAuthDPoPScheme(true, true, true, &logs)
	dpopKey, dpopPublic, signedTok := s.newDPoPKeyAndAccessToken()
	proof := s.signDPoPProof(dpopKey, dpopPublic, signedTok, dpopSchemeTestPath) // no nonce claim

	err := s.checkTokenWithScheme(auth, "Bearer", signedTok, proof)

	s.assertBearerSchemeRejection(err)
	var nonceErr *DPoPNonceError
	s.NotErrorAs(err, &nonceErr)
}

// strict_scheme leaves compliant requests alone: the DPoP scheme still succeeds,
// and an unbound token under Bearer is still governed only by dpop.enforce.
func (s *AuthSuite) Test_CheckToken_StrictScheme_AllowsCompliantRequests() {
	var logs bytes.Buffer
	auth := s.newAuthDPoPScheme(false, true, false, &logs)

	dpopKey, dpopPublic, signedTok := s.newDPoPKeyAndAccessToken()
	proof := s.signDPoPProof(dpopKey, dpopPublic, signedTok, dpopSchemeTestPath)
	s.Require().NoError(s.checkTokenWithScheme(auth, "DPoP", signedTok, proof), "DPoP scheme with a valid proof")

	unbound := s.makeUnboundAccessToken()
	s.Require().NoError(s.checkTokenWithScheme(auth, "Bearer", unbound, ""), "unbound Bearer token with DPoP not enforced")
	s.NotContains(logs.String(), "Bearer Authorization scheme")
}

// MuxHandler answers the strict-scheme rejection with 401 and the invalid_token
// DPoP challenge, and logs neither the token nor the proof.
func (s *AuthSuite) Test_MuxHandler_BearerSchemeWithCNF_RejectedWhenStrict() {
	for _, requireNonce := range []bool{false, true} {
		s.Run(fmt.Sprintf("require_nonce=%t", requireNonce), func() {
			var logs bytes.Buffer
			auth := s.newAuthDPoPScheme(true, true, requireNonce, &logs)
			dpopKey, dpopPublic, signedTok := s.newDPoPKeyAndAccessToken()
			req := httptest.NewRequest(http.MethodPost, "http://localhost:8080"+dpopSchemeTestPath, nil)
			proof := s.signDPoPProof(dpopKey, dpopPublic, signedTok, "http://localhost:8080"+dpopSchemeTestPath)
			req.Header.Set("Authorization", "Bearer "+string(signedTok))
			req.Header.Set("DPoP", proof)

			var called bool
			rec := httptest.NewRecorder()
			auth.MuxHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(rec, req)

			s.False(called)
			s.Equal(http.StatusUnauthorized, rec.Code)
			s.Equal(dpopBearerSchemeChallenge, rec.Header().Get("WWW-Authenticate"))
			if requireNonce {
				s.NotEmpty(rec.Header().Get("DPoP-Nonce"))
			} else {
				s.Empty(rec.Header().Get("DPoP-Nonce"))
			}
			s.NotContains(rec.Body.String(), string(signedTok))
			s.NotContains(logs.String(), string(signedTok))
			s.NotContains(logs.String(), proof)
		})
	}
}

// The Connect interceptor answers the strict-scheme rejection with
// CodeUnauthenticated and the invalid_token DPoP challenge.
func (s *AuthSuite) Test_ConnectAuthNInterceptor_BearerSchemeWithCNF_RejectedWhenStrict() {
	var logs bytes.Buffer
	auth := s.newAuthDPoPScheme(true, true, false, &logs)
	dpopKey, dpopPublic, signedTok := s.newDPoPKeyAndAccessToken()
	proof := s.signDPoPProof(dpopKey, dpopPublic, signedTok, dpopChallengeRoute)

	req := &authnTestRequest{
		Request:   connect.NewRequest(&kas.RewrapRequest{}),
		procedure: dpopChallengeRoute,
	}
	req.Header().Set("Authorization", "Bearer "+string(signedTok))
	req.Header().Set("DPoP", proof)
	var called bool
	next := func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
		called = true
		return connect.NewResponse(&kas.RewrapResponse{}), nil
	}

	_, err := auth.ConnectAuthNInterceptor().WrapUnary(next)(s.T().Context(), req)

	s.False(called)
	var connectErr *connect.Error
	s.Require().ErrorAs(err, &connectErr)
	s.Equal(connect.CodeUnauthenticated, connectErr.Code())
	s.Equal(dpopBearerSchemeChallenge, connectErr.Meta().Get("WWW-Authenticate"))
	s.NotContains(logs.String(), string(signedTok))
	s.NotContains(logs.String(), proof)
}

func (s *AuthSuite) Test_DPoPProofError_Challenge() {
	s.Equal(`DPoP error="invalid_dpop_proof"`, (&DPoPProofError{err: errDPoPBoundTokenUnderBearer}).challenge())
	s.Equal(dpopBearerSchemeChallenge, (&DPoPProofError{err: errDPoPBoundTokenUnderBearer, wwwAuthenticate: dpopBearerSchemeChallenge}).challenge())
}

// makeUnboundAccessToken creates a valid access token with no cnf claim.
func (s *AuthSuite) makeUnboundAccessToken() []byte {
	tok := jwt.New()
	s.Require().NoError(tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	s.Require().NoError(tok.Set("iss", s.server.URL))
	s.Require().NoError(tok.Set("aud", "test"))
	s.Require().NoError(tok.Set("cid", "client-unbound"))
	signedTok, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))
	s.Require().NoError(err)
	return signedTok
}
