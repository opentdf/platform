// Package auth — inbound bearer-token verification.
//
// The platform accepts CWT bearer tokens (RFC 8392, COSE_Sign1, ES256) issued
// by an IdP that publishes a COSE Key Set. The IdP advertises that key-set
// URL in its OIDC Discovery document under the custom field
// `arkavo_cose_keys_uri`; we re-use the same OIDC issuer/JWKS infrastructure
// for everything else (issuer alignment, audience matching, well-known
// registration) but route the actual signature verification through
// CWTVerifier rather than jwx.
//
// JWT bearer tokens are no longer accepted on inbound paths — this was a
// hard cutover (see ADRs / project memory). Outbound token *minting* by the
// Go SDK is a separate path and is not yet on CWT.
package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/opentdf/platform/service/logger"
)

// AccessTokenVerifier validates raw access tokens. The implementation is a
// CWT verifier today; the interface is preserved so call sites that hold
// the verifier (e.g. service/authorization/v2/rar.go) don't need to know
// which token format is in use.
type AccessTokenVerifier interface {
	VerifyAccessToken(ctx context.Context, tokenRaw string) (jwt.Token, error)
}

// newTokenVerifier discovers the IdP's OIDC config and the COSE Key Set URL
// it advertises, then builds a CWTVerifier. The returned OIDCConfiguration
// is handed back to NewAuthenticator so it can register the issuer + idp
// metadata in the wellknown service exactly as before.
//
// If the IdP's self-reported issuer differs from the configured one (common
// in dev where local hostnames diverge), the configured value is rewritten
// to the discovered one so subsequent iss-claim matching succeeds.
func newTokenVerifier(ctx context.Context, cfg AuthNConfig, log *logger.Logger) (*CWTVerifier, *OIDCConfiguration, AuthNConfig, error) {
	if err := cfg.validateAuthNConfig(log); err != nil {
		return nil, nil, cfg, err
	}

	oidcConfig, err := DiscoverOIDCConfiguration(ctx, cfg.Issuer, log)
	if err != nil {
		return nil, nil, cfg, err
	}
	if oidcConfig.CoseKeysURI == "" {
		return nil, nil, cfg, fmt.Errorf(
			"idp %s does not advertise arkavo_cose_keys_uri in its discovery document; "+
				"the platform requires CWT bearer tokens (see service/internal/auth/cwt_verifier.go)",
			cfg.Issuer,
		)
	}
	if oidcConfig.Issuer != cfg.Issuer {
		cfg.Issuer = oidcConfig.Issuer
	}

	cacheTTL := defaultCWTCacheTTL
	if cfg.CacheRefresh != "" {
		if d, perr := time.ParseDuration(cfg.CacheRefresh); perr == nil {
			cacheTTL = d
		}
	}

	v, err := NewCWTVerifier(ctx, CWTVerifierConfig{
		COSEKeysURL: oidcConfig.CoseKeysURI,
		Issuer:      cfg.Issuer,
		Audience:    cfg.Audience,
		CacheTTL:    cacheTTL,
	}, log)
	if err != nil {
		return nil, nil, cfg, err
	}
	return v, oidcConfig, cfg, nil
}

// AccessTokenVerifier returns the authenticator's shared access-token verifier.
func (a *Authentication) AccessTokenVerifier() AccessTokenVerifier {
	if a == nil || a.tokenVerifier == nil {
		return nil
	}
	return a.tokenVerifier
}
