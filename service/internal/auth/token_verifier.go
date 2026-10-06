package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/opentdf/platform/service/logger"
)

var errNilTokenVerifier = errors.New("access token verifier is not configured")

// AccessTokenVerifier validates raw access tokens.
type AccessTokenVerifier interface {
	VerifyAccessToken(ctx context.Context, tokenRaw string) (jwt.Token, error)
}

// TokenVerifier validates access tokens against the platform's configured IdP.
type TokenVerifier struct {
	cachedKeySet      jwk.Set
	oidcConfiguration AuthNConfig
	log               *logger.Logger

	selfAudienceWarning sync.Once
}

func newTokenVerifier(ctx context.Context, cfg AuthNConfig, log *logger.Logger) (*TokenVerifier, *OIDCConfiguration, error) {
	if err := cfg.validateAuthNConfig(log); err != nil {
		return nil, nil, err
	}

	cache := jwk.NewCache(ctx)

	oidcConfig, err := DiscoverOIDCConfiguration(ctx, cfg.Issuer, log)
	if err != nil {
		return nil, nil, err
	}

	if oidcConfig.Issuer != cfg.Issuer {
		cfg.Issuer = oidcConfig.Issuer
	}

	cacheInterval, err := time.ParseDuration(cfg.CacheRefresh)
	if err != nil {
		log.ErrorContext(ctx,
			"invalid cache_refresh_interval",
			slog.String("cache_refresh_interval", cfg.CacheRefresh),
			slog.Any("err", err),
		)
		cacheInterval = refreshInterval
	}

	if err := cache.Register(oidcConfig.JwksURI, jwk.WithMinRefreshInterval(cacheInterval)); err != nil {
		return nil, nil, err
	}

	if _, err := cache.Refresh(ctx, oidcConfig.JwksURI); err != nil {
		return nil, nil, err
	}

	return &TokenVerifier{
		cachedKeySet:      jwk.NewCachedSet(cache, oidcConfig.JwksURI),
		oidcConfiguration: cfg,
		log:               log,
	}, oidcConfig, nil
}

// NewTokenVerifier creates a reusable verifier backed by the IdP JWKS endpoint.
func NewTokenVerifier(ctx context.Context, cfg AuthNConfig, log *logger.Logger) (*TokenVerifier, error) {
	verifier, _, err := newTokenVerifier(ctx, cfg, log)
	return verifier, err
}

// AccessTokenVerifier returns the authenticator's shared access-token verifier.
func (a *Authentication) AccessTokenVerifier() AccessTokenVerifier {
	if a == nil || a.tokenVerifier == nil {
		return nil
	}

	return a.tokenVerifier
}

// VerifyAccessToken validates the provided raw JWT and returns the parsed token on success.
func (v *TokenVerifier) VerifyAccessToken(ctx context.Context, tokenRaw string) (jwt.Token, error) {
	if v == nil {
		return nil, errNilTokenVerifier
	}

	token, err := jwt.Parse([]byte(tokenRaw),
		jwt.WithKeySet(v.cachedKeySet, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.oidcConfiguration.Issuer),
		jwt.WithAudience(v.oidcConfiguration.Audience),
		jwt.WithAcceptableSkew(v.oidcConfiguration.TokenSkew),
	)
	if err != nil {
		v.logRejectedToken(ctx, tokenRaw, err)
		return nil, &accessTokenRejectedError{err: err}
	}

	v.warnIfAudienceIsRequestingClient(ctx, token)
	return token, nil
}

// accessTokenRejectedError marks an error returned by VerifyAccessToken. The
// verifier has already logged the reason and remediation, so callers should
// not log it again.
type accessTokenRejectedError struct {
	err error
}

func (e *accessTokenRejectedError) Error() string { return e.err.Error() }
func (e *accessTokenRejectedError) Unwrap() error { return e.err }

const (
	troubleshootingDocsRef = "'Troubleshooting access token errors' in the documentation bundled with your deployment"
	maxLoggedClaimLength   = 256
	maxLoggedAudiences     = 10
)

// logRejectedToken logs one WARN record describing why tokenRaw was rejected
// and where a deployer fixes it. The token failed verification, so its claims
// are untrusted: they are logged only as truncated attributes and never used
// in the remediation text, which is built from server configuration alone.
// The raw token and identity claims such as sub and email are never logged.
func (v *TokenVerifier) logRejectedToken(ctx context.Context, tokenRaw string, err error) {
	cfg := v.oidcConfiguration
	// jwx error text can quote token values such as an unknown kid.
	attrs := []any{slog.String("err", truncateClaim(err.Error()))}

	unverified, parseErr := jwt.ParseInsecure([]byte(tokenRaw))
	if parseErr != nil {
		v.log.WarnContext(ctx, "access token malformed", withRemediation(attrs,
			"The Authorization header does not contain a well-formed JWT access token. "+
				"Configure the client to send the JWT access token issued by the IdP; some IdPs issue opaque access tokens "+
				"unless the client requests an audience. See "+troubleshootingDocsRef+".")...)
		return
	}

	switch {
	case errors.Is(err, jwt.ErrInvalidAudience()):
		attrs = append(attrs, slog.String("expected_audience", cfg.Audience))
		if azp := tokenAZP(unverified); azp != "" {
			attrs = append(attrs, slog.String("token_azp", truncateClaim(azp)))
		}
		if aud := unverified.Audience(); len(aud) > 0 {
			attrs = append(attrs, slog.Any("token_aud", truncateAudiences(aud)))
		}
		remediation := fmt.Sprintf("The token's aud claim does not include the platform audience %q. Fix it in one place: "+
			"(1) IdP: add %q to the aud claim of access tokens issued to the calling client (token_azp); "+
			"in Keycloak, add an Audience protocol mapper to the client's scopes. "+
			"(2) Platform: if the expected audience is wrong, change server.auth.audience (env OPENTDF_SERVER_AUTH_AUDIENCE). See %s.",
			cfg.Audience, cfg.Audience, troubleshootingDocsRef)
		if audienceContainsAZP(unverified) {
			remediation = fmt.Sprintf("The token's aud claim contains the calling client's own ID (token_azp) instead of the platform audience %q. "+
				"Fix this in the IdP, not the platform: add %q to the aud claim of access tokens issued to that client "+
				"(Keycloak: add an Audience protocol mapper to the client's scopes). Do not set server.auth.audience to the client ID. "+
				"If the client is sending an ID token, change it to send the access token instead. See %s.",
				cfg.Audience, cfg.Audience, troubleshootingDocsRef)
		}
		v.log.WarnContext(ctx, "access token audience mismatch", withRemediation(attrs, remediation)...)
	case errors.Is(err, jwt.ErrInvalidIssuer()):
		attrs = append(attrs,
			slog.String("expected_issuer", cfg.Issuer),
			slog.String("token_iss", truncateClaim(unverified.Issuer())),
		)
		v.log.WarnContext(ctx, "access token issuer mismatch", withRemediation(attrs, fmt.Sprintf(
			"The token's iss claim does not match the issuer %q advertised by the IdP's discovery document. "+
				"(1) Platform: set server.auth.issuer (env OPENTDF_SERVER_AUTH_ISSUER) to exactly the issuer in the IdP's discovery document. "+
				"(2) IdP: if clients and the platform reach the IdP through different hostnames, configure a single public hostname "+
				"for the IdP (Keycloak: KC_HOSTNAME) so every token carries the same iss. See %s.",
			cfg.Issuer, troubleshootingDocsRef))...)
	case errors.Is(err, jwt.ErrTokenExpired()):
		attrs = append(attrs,
			slog.Time("token_exp", unverified.Expiration()),
			slog.Time("server_time", time.Now()),
			slog.String("allowed_skew", cfg.TokenSkew.String()),
		)
		v.log.WarnContext(ctx, "access token expired", withRemediation(attrs, fmt.Sprintf(
			"The token expired more than the allowed clock skew (%s) ago. "+
				"(1) Client: obtain a fresh access token instead of reusing an old one. "+
				"(2) Hosts: if freshly issued tokens are rejected, the platform's and the IdP's clocks disagree; synchronize both with NTP. "+
				"The tolerance is server.auth.skew. See %s.",
			cfg.TokenSkew, troubleshootingDocsRef))...)
	case errors.Is(err, jwt.ErrTokenNotYetValid()), errors.Is(err, jwt.ErrInvalidIssuedAt()):
		attrs = append(attrs,
			slog.Time("token_nbf", unverified.NotBefore()),
			slog.Time("token_iat", unverified.IssuedAt()),
			slog.Time("server_time", time.Now()),
			slog.String("allowed_skew", cfg.TokenSkew.String()),
		)
		v.log.WarnContext(ctx, "access token not yet valid", withRemediation(attrs, fmt.Sprintf(
			"The token's nbf or iat time is later than the platform's clock by more than the allowed skew (%s). "+
				"The platform's and the IdP's clocks disagree; synchronize both with NTP. The tolerance is server.auth.skew. See %s.",
			cfg.TokenSkew, troubleshootingDocsRef))...)
	case !jwt.IsValidationError(err):
		attrs = append(attrs, slog.String("expected_issuer", cfg.Issuer))
		attrs = append(attrs, signatureHeaderAttrs(tokenRaw)...)
		v.log.WarnContext(ctx, "access token signature not verified", withRemediation(attrs, fmt.Sprintf(
			"The token's signature could not be verified with the signing keys published by the issuer %q. "+
				"(1) Client: the token may come from a different IdP or realm than server.auth.issuer; obtain it from the configured issuer. "+
				"(2) Platform: if the IdP recently rotated its signing keys, the cached key set refreshes every "+
				"server.auth.cache_refresh_interval. See %s.",
			cfg.Issuer, troubleshootingDocsRef))...)
	default:
		v.log.WarnContext(ctx, "access token rejected", withRemediation(attrs,
			"The err attribute names the claim that failed validation. See "+troubleshootingDocsRef+".")...)
	}
}

func withRemediation(attrs []any, remediation string) []any {
	return append(attrs, slog.String("remediation", remediation))
}

// warnIfAudienceIsRequestingClient logs once when a token validates only
// because the configured audience equals the requesting client's ID. ID tokens
// carry the client ID as aud, so such a deployment also accepts ID tokens as
// access tokens.
func (v *TokenVerifier) warnIfAudienceIsRequestingClient(ctx context.Context, token jwt.Token) {
	if azp := tokenAZP(token); azp == "" || azp != v.oidcConfiguration.Audience {
		return
	}
	v.selfAudienceWarning.Do(func() {
		v.log.WarnContext(ctx, "access token audience is the requesting client ID",
			slog.String("expected_audience", v.oidcConfiguration.Audience),
			slog.String("remediation", "server.auth.audience equals the ID of the client requesting tokens, "+
				"so ID tokens issued to that client are also accepted as access tokens. "+
				"Configure the IdP to add the platform's own audience to access tokens (Keycloak: Audience protocol mapper), "+
				"then set server.auth.audience (env OPENTDF_SERVER_AUTH_AUDIENCE) to that value. See "+troubleshootingDocsRef+"."),
		)
	})
}

func tokenAZP(token jwt.Token) string {
	azp, ok := token.Get("azp")
	if !ok {
		return ""
	}
	s, _ := azp.(string)
	return s
}

func audienceContainsAZP(token jwt.Token) bool {
	azp := tokenAZP(token)
	return azp != "" && slices.Contains(token.Audience(), azp)
}

func signatureHeaderAttrs(tokenRaw string) []any {
	msg, err := jws.ParseString(tokenRaw)
	if err != nil || len(msg.Signatures()) == 0 {
		return nil
	}
	headers := msg.Signatures()[0].ProtectedHeaders()
	return []any{
		slog.String("token_kid", truncateClaim(headers.KeyID())),
		slog.String("token_alg", truncateClaim(headers.Algorithm().String())),
	}
}

func truncateClaim(s string) string {
	if len(s) <= maxLoggedClaimLength {
		return s
	}
	return s[:maxLoggedClaimLength] + "...(truncated)"
}

func truncateAudiences(aud []string) []string {
	if len(aud) > maxLoggedAudiences {
		aud = aud[:maxLoggedAudiences]
	}
	out := make([]string, len(aud))
	for i, a := range aud {
		out[i] = truncateClaim(a)
	}
	return out
}
