package auth

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jwx-go/jwkfetch/v4"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"

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
}

func newTokenVerifier(ctx context.Context, cfg AuthNConfig, log *logger.Logger) (*TokenVerifier, *OIDCConfiguration, error) {
	if err := cfg.validateAuthNConfig(log); err != nil {
		return nil, nil, err
	}

	cache, err := jwkfetch.NewCache(ctx, httprc.NewClient())
	if err != nil {
		return nil, nil, err
	}

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

	if err := cache.Register(ctx, oidcConfig.JwksURI, jwkfetch.WithMinInterval(cacheInterval)); err != nil {
		return nil, nil, err
	}

	if _, err := cache.Refresh(ctx, oidcConfig.JwksURI); err != nil {
		return nil, nil, err
	}

	cachedKeySet, err := cache.CachedSet(oidcConfig.JwksURI)
	if err != nil {
		return nil, nil, err
	}

	return &TokenVerifier{
		cachedKeySet:      cachedKeySet,
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
		v.log.WarnContext(ctx, "failed to validate auth token", slog.Any("err", err))
		return nil, err
	}

	return token, nil
}
