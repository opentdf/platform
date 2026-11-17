package auth

import (
	"time"

	"github.com/opentdf/platform/service/logger"
	"google.golang.org/protobuf/types/known/structpb"
)

// newAuthRegisteringWellKnown builds an authenticator with the given DPoP
// settings and returns the well-known configuration it registered, after the
// structpb conversion the well-known service applies.
func (s *AuthSuite) newAuthRegisteringWellKnown(dpop DPoPConfig) map[string]any {
	registered := map[string]any{}
	_, err := NewAuthenticator(
		s.T().Context(),
		Config{AuthNConfig: AuthNConfig{
			Issuer:    s.server.URL,
			Audience:  "test",
			DPoPSkew:  time.Hour,
			TokenSkew: time.Minute,
			DPoP:      dpop,
		}},
		logger.CreateTestLogger(),
		func(namespace string, config any) error {
			registered[namespace] = config
			return nil
		},
	)
	s.Require().NoError(err)
	converted, err := structpb.NewStruct(registered)
	s.Require().NoError(err)
	return converted.AsMap()
}

// The well-known dpop block reports what the server enforces for every
// nonce and strict-htu setting, including the deprecated alias, and the existing top-level DPoP keys keep
// their values (DSPX-5635).
func (s *AuthSuite) Test_DPoP_WellKnownCapabilities() {
	for _, tc := range []struct {
		name           string
		requireNonce   bool
		strictHTU      bool
		strictHTUAlias bool // deprecated server.auth.dpop.strict_htu
	}{
		{"defaults", false, false, false},
		{"nonce required", true, false, false},
		{"strict htu", false, true, false},
		{"nonce required and strict htu", true, true, false},
		{"deprecated strict_htu alias", false, false, true},
	} {
		s.Run(tc.name, func() {
			wk := s.newAuthRegisteringWellKnown(DPoPConfig{
				Enforce:         true,
				RequireNonce:    tc.requireNonce,
				NonceExpiration: 5 * time.Minute,
				HTU:             DPoPHTUConfig{Strict: tc.strictHTU, Origins: []string{htuOrigin}},
				StrictHTU:       tc.strictHTUAlias,
			})

			algs, ok := wk["dpop_signing_alg_values_supported"].([]any)
			s.Require().True(ok, "dpop_signing_alg_values_supported is a list, got %T", wk["dpop_signing_alg_values_supported"])
			s.Contains(algs, "ES256")
			s.Contains(algs, "RS256")
			s.Equal(tc.requireNonce, wk["dpop_nonce_required"])

			block, ok := wk["dpop"].(map[string]any)
			s.Require().True(ok, "dpop block is an object, got %T", wk["dpop"])
			s.Equal(map[string]any{
				"rfc9449":                      true,
				"signing_alg_values_supported": algs,
				"nonce_required":               tc.requireNonce,
				"path_only_htu_accepted":       !tc.strictHTU && !tc.strictHTUAlias,
				"htu_origins":                  []any{htuOrigin},
				// Bearer-scheme DPoP-bound tokens are still accepted, so legacy
				// proofs are accepted even with strict htu.
				"legacy_accepted": true,
			}, block)
		})
	}
}
