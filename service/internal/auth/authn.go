package auth

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/bmatcuk/doublestar"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"google.golang.org/grpc/metadata"

	"github.com/opentdf/platform/service/pkg/oidc"

	sdkAudit "github.com/opentdf/platform/sdk/audit"
	"github.com/opentdf/platform/service/logger"

	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
)

// Package-level errors
var (
	// Set of allowed public endpoints that do not require authentication
	allowedPublicEndpoints = [...]string{
		// Well Known Configuration Endpoints
		"/wellknownconfiguration.WellKnownService/GetWellKnownConfiguration",
		"/.well-known/opentdf-configuration",
		// KAS Public Key Endpoints
		"/kas.AccessService/PublicKey",
		"/kas.AccessService/LegacyPublicKey",
		"/kas.AccessService/Info",
		"/kas/kas_public_key",
		"/kas/v2/kas_public_key",
		// HealthZ
		"/healthz",
		"/grpc.health.v1.Health/Check",
	}
	// Routes which require reauthorization for IPC
	ipcReauthRoutes = [...]string{
		"/kas.AccessService/Rewrap",
	}
	// only asymmetric algorithms and no 'none'
	allowedSignatureAlgorithms = map[jwa.SignatureAlgorithm]bool{ //nolint:exhaustive // only asymmetric algorithms
		jwa.RS256: true,
		jwa.RS384: true,
		jwa.RS512: true,
		jwa.ES256: true,
		jwa.ES384: true,
		jwa.ES512: true,
		jwa.PS256: true,
		jwa.PS384: true,
		jwa.PS512: true,
	}

	// ErrNoDPoPSkipCheck is returned when DPoP checking is intentionally skipped (e.g., for Bearer tokens)
	ErrNoDPoPSkipCheck = errors.New("dpop check skipped")
)

const (
	refreshInterval           = 15 * time.Minute
	clientVerificationTimeout = 30 * time.Second
	ActionRead                = "read"
	ActionWrite               = "write"
	ActionDelete              = "delete"
	ActionUnsafe              = "unsafe"
	ActionOther               = "other"

	AuthHeaderBearer = "Bearer "
	AuthHeaderDPoP   = "DPoP "
)

// Authentication holds a jwks cache and information about the openid configuration
type Authentication struct {
	// config holds the configuration for the authenticator
	config *Config
	// enforceDPoP indicates whether DPoP is enforced
	enforceDPoP bool
	// keySet holds a cached key set
	cachedKeySet jwk.Set
	// openidConfigurations holds the openid configuration for the issuer
	oidcConfiguration AuthNConfig
	oidcDiscovery     *oidc.DiscoveryConfiguration
	// Casbin enforcer
	enforcer *Enforcer
	// Public Routes HTTP & gRPC
	publicRoutes []string
	// IPC Reauthorization Routes
	ipcReauthRoutes []string
	// Custom Logger
	logger *logger.Logger

	// UserInfoCache holds the userinfo cache
	userInfoCache *oidc.UserInfoCache

	// Used for testing
	_testCheckTokenFunc func(ctx context.Context, token jwt.Token, tokenRaw string, dpopInfo receiverInfo, dpopHeader []string) (jwk.Key, error)
}

// Creates new authN which is used to verify tokens for a set of given issuers
func NewAuthenticator(ctx context.Context, cfg *Config, logger *logger.Logger, wellknownRegistration func(namespace string, config any) error, oidcConfig *oidc.DiscoveryConfiguration, userInfoCache *oidc.UserInfoCache) (*Authentication, error) {
	a := &Authentication{
		config:            cfg,
		enforceDPoP:       cfg.EnforceDPoP,
		logger:            logger,
		oidcConfiguration: cfg.AuthNConfig,
		oidcDiscovery:     oidcConfig,
		userInfoCache:     userInfoCache,
	}

	// validate the configuration
	if err := cfg.validateAuthNConfig(a.logger); err != nil {
		return nil, err
	}

	// If userinfo enrichment is enabled, validate the client credentials with the IdP
	if cfg.EnrichUserInfo {
		logger.Info("validating client credentials with IdP", slog.String("issuer", oidcConfig.Issuer), slog.String("client_id", cfg.ClientID), slog.Bool("tls_no_verify", cfg.AuthNConfig.TLSNoVerify))
		if err := oidc.ValidateClientCredentials(ctx, oidcConfig, cfg.ClientID, cfg.ClientScopes, []byte(cfg.ClientPrivateKey), cfg.AuthNConfig.TLSNoVerify, clientVerificationTimeout, nil, ""); err != nil {
			logger.Error("failed to validate client credentials with IdP", slog.String("error", err.Error()))
			return nil, fmt.Errorf("client credentials validation failed: %w", err)
		}
		logger.Info("client credentials validation successful")
	}

	cache := jwk.NewCache(ctx)

	// If the issuer is different from the one in the configuration, update the configuration
	// This could happen if we are hitting an internal endpoint. Example we might point to https://keycloak.opentdf.svc/realms/opentdf
	// but the external facing issuer is https://keycloak.opentdf.local/realms/opentdf
	if oidcConfig.Issuer != cfg.Issuer {
		cfg.Issuer = oidcConfig.Issuer
	}

	cacheInterval, err := time.ParseDuration(cfg.CacheRefresh)
	if err != nil {
		logger.ErrorContext(ctx, fmt.Sprintf("Invalid cache_refresh_interval [%s]", cfg.CacheRefresh), "err", err)
		cacheInterval = refreshInterval
	}

	// Register the jwks_uri with the cache
	if err := cache.Register(oidcConfig.JwksURI, jwk.WithMinRefreshInterval(cacheInterval)); err != nil {
		return nil, err
	}

	casbinConfig := CasbinConfig{
		PolicyConfig: cfg.Policy,
	}
	logger.Info("initializing casbin enforcer")
	if a.enforcer, err = NewCasbinEnforcer(casbinConfig, a.logger); err != nil {
		return nil, fmt.Errorf("failed to initialize casbin enforcer: %w", err)
	}

	// Need to refresh the cache to verify jwks is available
	_, err = cache.Refresh(ctx, oidcConfig.JwksURI)
	if err != nil {
		return nil, err
	}

	// Set the cache
	a.cachedKeySet = jwk.NewCachedSet(cache, oidcConfig.JwksURI)

	// Combine public routes
	a.publicRoutes = append(a.publicRoutes, cfg.PublicRoutes...)
	a.publicRoutes = append(a.publicRoutes, allowedPublicEndpoints[:]...)

	// Combine IPC reauthorization routes
	a.ipcReauthRoutes = append(ipcReauthRoutes[:], cfg.IPCReauthRoutes...)

	// Try an register oidc issuer to wellknown service but don't return an error if it fails
	if err := wellknownRegistration("platform_issuer", cfg.Issuer); err != nil {
		logger.Warn("failed to register platform issuer", slog.String("error", err.Error()))
	}

	var oidcConfigMap map[string]any

	// Create a map of the oidc configuration
	oidcConfigBytes, err := json.Marshal(oidcConfig)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(oidcConfigBytes, &oidcConfigMap); err != nil {
		return nil, err
	}

	if err := wellknownRegistration("idp", oidcConfigMap); err != nil {
		logger.Warn("failed to register platform idp information", slog.String("error", err.Error()))
	}

	return a, nil
}

type receiverInfo struct {
	// Acceptable URIs of the request
	u []string
	// Allowed HTTP methods of the request
	m []string
}

func normalizeURL(o string, u *url.URL) string {
	// Currently this does not do a full normatlization
	ou, err := url.Parse(o)
	if err != nil {
		return u.String()
	}
	ou.Path = u.Path
	return ou.String()
}

// verifyTokenHandler is a http handler that verifies the token
func (a Authentication) MuxHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slices.ContainsFunc(a.publicRoutes, a.isPublicRoute(r.URL.Path)) { //nolint:contextcheck // There is no way to pass a context here
			handler.ServeHTTP(w, r)
			return
		}

		dp := r.Header.Values("Dpop")

		// Verify the token
		header := r.Header["Authorization"]
		if len(header) < 1 {
			http.Error(w, "missing authorization header", http.StatusUnauthorized)
			return
		}
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = r.Host
			if r.TLS != nil {
				origin = "https://" + strings.TrimSuffix(origin, ":443")
			} else {
				origin = "http://" + strings.TrimSuffix(origin, ":80")
			}
		}

		token, tokenRaw, tokenType, err := a.parseTokenFromHeader(r.Header)
		if err != nil {
			slog.WarnContext(r.Context(), "failed to parse token", "error", err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		key, err := a.checkToken(r.Context(), token, tokenRaw, tokenType, receiverInfo{
			u: []string{normalizeURL(origin, r.URL)},
			m: []string{r.Method},
		}, dp)
		if err != nil && !errors.Is(err, ErrNoDPoPSkipCheck) {
			slog.WarnContext(r.Context(), "unauthenticated", "error", err, "dpop", dp, "authorization", header)
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		// Fetch userinfo, only exchange token if needed
		userInfoRaw, err := a.GetUserInfoWithExchange(r.Context(), token.Issuer(), token.Subject(), tokenRaw)
		if err != nil {
			slog.WarnContext(r.Context(), "unauthenticated", "error", err, "dpop", dp, "authorization", header)
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		nextCtx := ctxAuth.ContextWithAuthNInfo(r.Context(), key, token, tokenRaw, userInfoRaw)
		md, ok := metadata.FromIncomingContext(nextCtx)
		if !ok {
			md = metadata.New(nil)
		}
		md.Append("access_token", tokenRaw)
		nextCtx = metadata.NewIncomingContext(nextCtx, md)

		// Check if the token is allowed to access the resource
		var action string
		switch r.Method {
		case http.MethodGet:
			action = ActionRead
		case http.MethodPost, http.MethodPut, http.MethodPatch:
			action = ActionWrite
		case http.MethodDelete:
			action = ActionDelete
		default:
			action = ActionUnsafe
		}
		if !a.enforcer.Enforce(token, userInfoRaw, r.URL.Path, action) {
			a.logger.WarnContext(r.Context(), "permission denied", slog.String("azp", token.Subject()))
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}

		r = r.WithContext(nextCtx)
		handler.ServeHTTP(w, r)
	})
}

// IPCReauthInterceptor is a grpc interceptor that verifies the token in the metadata
// and reauthorizes the token if the route is in the list
func (a Authentication) IPCUnaryServerInterceptor() connect.UnaryInterceptorFunc {
	interceptor := func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(
			ctx context.Context,
			req connect.AnyRequest,
		) (connect.AnyResponse, error) {
			nextCtx, err := a.ipcReauthCheck(ctx, req.Spec().Procedure, req.Header())
			if err != nil {
				return nil, err
			}
			return next(nextCtx, req)
		})
	}
	return connect.UnaryInterceptorFunc(interceptor)
}

// getAction returns the action based on the rpc name
func getAction(method string) string {
	switch {
	case strings.HasPrefix(method, "List") || strings.HasPrefix(method, "Get"):
		return ActionRead
	case strings.HasPrefix(method, "Create") || strings.HasPrefix(method, "Update") || strings.HasPrefix(method, "Assign"):
		return ActionWrite
	case strings.HasPrefix(method, "Delete") || strings.HasPrefix(method, "Remove") || strings.HasPrefix(method, "Deactivate"):
		return ActionDelete
	case strings.HasPrefix(method, "Unsafe"):
		return ActionUnsafe
	}
	return ActionOther
}

// GetUserInfoWithExchange fetches userinfo, exchanging the token if needed.
func (a *Authentication) GetUserInfoWithExchange(ctx context.Context, tokenIssuer, tokenSubject, tokenRaw string) ([]byte, error) {
	// If userinfo enrichment is disabled, return empty userinfo
	if !a.oidcConfiguration.EnrichUserInfo {
		a.logger.Debug("userinfo enrichment is disabled, skipping token exchange", slog.String("sub", tokenSubject))
		return []byte{}, nil
	}

	// Try to get userinfo from cache with the original token
	_, userInfoRaw, err := a.userInfoCache.GetFromCache(ctx, tokenIssuer, tokenSubject)
	if err == nil {
		return userInfoRaw, nil
	}

	// Only exchange the token if the userinfo is not in cache
	exchangedToken, dpopJWK, err := oidc.ExchangeToken(
		ctx,
		a.oidcDiscovery,
		a.oidcConfiguration.ClientID,
		[]byte(a.config.ClientPrivateKey),
		tokenRaw,
		[]string{a.oidcConfiguration.Audience},
		[]string{"openid", "profile", "email"},
	)
	if err != nil {
		a.logger.Error("failed to exchange token", slog.String("sub", tokenSubject), slog.String("error", err.Error()))
		return []byte{}, errors.New("failed to exchange token")
	}

	// Fetch userinfo with the exchanged token
	_, userInfoRaw, err = a.userInfoCache.Get(ctx, tokenIssuer, tokenSubject, exchangedToken, dpopJWK)
	if err != nil {
		return nil, errors.New("unauthenticated")
	}
	return userInfoRaw, nil
}

type TokenType int

const (
	TokenTypeUnknown TokenType = iota
	TokenTypeBearer
	TokenTypeDPoP
)

func (t TokenType) String() string {
	switch t {
	case TokenTypeBearer:
		return "Bearer"
	case TokenTypeDPoP:
		return "DPoP"
	case TokenTypeUnknown:
	default:
		return "Unknown"
	}
	return "Unknown"
}

func (a Authentication) parseTokenFromHeader(header http.Header) (jwt.Token, string, TokenType, error) {
	authHeader := header["Authorization"]
	if len(authHeader) < 1 {
		return nil, "", TokenTypeUnknown, errors.New("missing authorization header")
	}

	var tokenRaw string
	var tokenType TokenType
	headerVal := authHeader[0]
	headerValLower := strings.ToLower(headerVal)
	switch {
	case strings.HasPrefix(headerValLower, strings.ToLower(AuthHeaderDPoP)):
		tokenRaw = headerVal[len(AuthHeaderDPoP):]
		tokenType = TokenTypeDPoP
	case strings.HasPrefix(headerValLower, strings.ToLower(AuthHeaderBearer)):
		tokenRaw = headerVal[len(AuthHeaderBearer):]
		tokenType = TokenTypeBearer
	default:
		a.logger.Warn("failed to validate authentication header: not of type bearer or dpop", slog.String("header", headerVal))
		return nil, "", TokenTypeUnknown, errors.New("not of type bearer or dpop")
	}

	token, err := jwt.Parse([]byte(tokenRaw),
		jwt.WithKeySet(a.cachedKeySet),
		jwt.WithValidate(true),
		jwt.WithIssuer(a.oidcConfiguration.Issuer),
		jwt.WithAudience(a.oidcConfiguration.Audience),
		jwt.WithAcceptableSkew(a.oidcConfiguration.TokenSkew),
	)
	if err != nil {
		a.logger.Warn("failed to validate auth token", slog.String("err", err.Error()), slog.String("issuer", a.oidcConfiguration.Issuer), slog.String("audience", a.oidcConfiguration.Audience))
		return nil, "", TokenTypeUnknown, err
	}

	return token, tokenRaw, tokenType, nil
}

// checkToken is a helper function to verify the token.
func (a *Authentication) checkToken(ctx context.Context, token jwt.Token, tokenRaw string, tokenType TokenType, dpopInfo receiverInfo, dpopHeader []string) (jwk.Key, error) {
	// Use the test function if it is set
	if a._testCheckTokenFunc != nil {
		// For test, pass tokenType as an extra arg if needed (backward compatible)
		return a._testCheckTokenFunc(ctx, token, tokenRaw, dpopInfo, dpopHeader)
	}

	if token == nil {
		// If the token is nil but the prefix is correct, it's likely a parse/validation error
		return nil, errors.New("invalid or missing token: token is nil (possible parse/validation error)")
	}

	// Get actor ID (sub) from unverified token for audit and add to context
	// Only set the actor ID if it is not already defined
	existingActorID := ctx.Value(sdkAudit.ActorIDContextKey)
	if existingActorID == nil {
		// We create the context with the actor ID but don't use it since it's not needed
		// in this method's scope. The actor ID is added for audit purposes.
		_ = token.Subject()
	}

	// Use tokenType for logic
	if tokenType == TokenTypeBearer {
		if a.enforceDPoP {
			return nil, errors.New("dpop required but not provided")
		}
		// For Bearer tokens, skip DPoP validation entirely
		return nil, ErrNoDPoPSkipCheck
	}

	// Check for cnf claim in the DPoP token
	if _, tokenHasCNF := token.Get("cnf"); !tokenHasCNF {
		if !a.enforceDPoP {
			// If DPoP is not enforced and the token does not have a cnf claim, allow it (legacy or non-DPoP case)
			return nil, ErrNoDPoPSkipCheck
		}
		return nil, errors.New("missing `cnf` claim in DPoP access token")
	}

	// Validate the DPoP token
	key, err := a.validateDPoP(token, tokenRaw, dpopInfo, dpopHeader)
	if err != nil {
		a.logger.Warn("failed to validate dpop", slog.String("token", tokenRaw), slog.Any("err", err))
		return nil, err
	}
	return key, nil
}

func (a Authentication) validateDPoP(accessToken jwt.Token, accessTokenRaw string, dpopInfo receiverInfo, headers []string) (jwk.Key, error) {
	if len(headers) != 1 {
		return nil, fmt.Errorf("got %d dpop headers, should have 1", len(headers))
	}
	dpopHeader := headers[0]

	cnf, ok := accessToken.Get("cnf")
	if !ok {
		return nil, errors.New("missing `cnf` claim in access token")
	}

	cnfDict, ok := cnf.(map[string]interface{})
	if !ok {
		return nil, errors.New("got `cnf` in an invalid format")
	}

	jktI, ok := cnfDict["jkt"]
	if !ok {
		return nil, errors.New("missing `jkt` field in `cnf` claim. only thumbprint JWK confirmation is supported")
	}

	jkt, ok := jktI.(string)
	if !ok {
		return nil, fmt.Errorf("invalid `jkt` field in `cnf` claim: %v. the value must be a JWK thumbprint", jkt)
	}

	dpop, err := jws.Parse([]byte(dpopHeader))
	if err != nil {
		return nil, errors.New("invalid DPoP JWT")
	}
	if len(dpop.Signatures()) != 1 {
		return nil, fmt.Errorf("expected one signature on DPoP JWT, got %d", len(dpop.Signatures()))
	}
	sig := dpop.Signatures()[0]
	protectedHeaders := sig.ProtectedHeaders()
	if protectedHeaders.Type() != "dpop+jwt" {
		return nil, fmt.Errorf("invalid typ on DPoP JWT: %v", protectedHeaders.Type())
	}

	if _, exists := allowedSignatureAlgorithms[protectedHeaders.Algorithm()]; !exists {
		return nil, fmt.Errorf("unsupported algorithm specified: %v", protectedHeaders.Algorithm())
	}

	dpopKey := protectedHeaders.JWK()
	if dpopKey == nil {
		return nil, errors.New("JWK missing in DPoP JWT")
	}

	isPrivate, err := jwk.IsPrivateKey(dpopKey)
	if err != nil {
		return nil, fmt.Errorf("invalid DPoP key field: %w", err)
	}

	if isPrivate {
		return nil, errors.New("cannot use a private key for DPoP")
	}

	thumbprint, err := dpopKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("couldn't compute thumbprint for key in `jwk` in DPoP JWT: %w", err)
	}

	thumbprintStr := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(thumbprint)
	if thumbprintStr != jkt {
		return nil, fmt.Errorf("the `jkt` from the DPoP JWT didn't match the thumbprint from the access token; cnf.jkt=[%v], computed=[%v]", jkt, thumbprintStr)
	}

	// at this point we have the right key because its thumbprint matches the `jkt` claim
	// in the validated access token
	dpopToken, err := jwt.Parse([]byte(dpopHeader), jwt.WithKey(protectedHeaders.Algorithm(), dpopKey))
	if err != nil {
		return nil, fmt.Errorf("failed to verify signature on DPoP JWT: %w", err)
	}

	issuedAt := dpopToken.IssuedAt()
	if issuedAt.IsZero() {
		return nil, errors.New("missing `iat` claim in the DPoP JWT")
	}

	if issuedAt.Add(a.oidcConfiguration.DPoPSkew).Before(time.Now()) {
		return nil, errors.New("the DPoP JWT has expired")
	}

	htma, ok := dpopToken.Get("htm")
	if !ok {
		return nil, errors.New("`htm` claim missing in DPoP JWT")
	}
	htm, ok := htma.(string)
	if !ok {
		return nil, errors.New("`htm` claim invalid format in DPoP JWT")
	}

	if !slices.Contains(dpopInfo.m, htm) {
		return nil, fmt.Errorf("incorrect `htm` claim in DPoP JWT; received [%v], but should match [%v]", htm, dpopInfo.m)
	}

	htua, ok := dpopToken.Get("htu")
	if !ok {
		return nil, errors.New("`htu` claim missing in DPoP JWT")
	}
	htu, ok := htua.(string)
	if !ok {
		return nil, errors.New("`htu` claim invalid format in DPoP JWT")
	}

	if !slices.Contains(dpopInfo.u, htu) {
		return nil, fmt.Errorf("incorrect `htu` claim in DPoP JWT; received [%v], but should match [%v]", htu, dpopInfo.u)
	}

	ath, ok := dpopToken.Get("ath")
	if !ok {
		return nil, errors.New("missing `ath` claim in DPoP JWT")
	}

	h := sha256.New()
	h.Write([]byte(accessTokenRaw))
	if ath != base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h.Sum(nil)) {
		return nil, errors.New("incorrect `ath` claim in DPoP JWT")
	}
	return dpopKey, nil
}

func (a Authentication) isPublicRoute(path string) func(string) bool {
	return func(route string) bool {
		matched, err := doublestar.Match(route, path)
		if err != nil {
			a.logger.Warn("error matching route", slog.String("route", route), slog.String("path", path), slog.String("error", err.Error()))
			return false
		}
		a.logger.Trace("matching route", slog.String("route", route), slog.String("path", path), slog.Bool("matched", matched))
		return matched
	}
}

func (a Authentication) lookupOrigins(header http.Header) []string {
	result := make([]string, 0)
	for _, m := range []string{"Grpcgateway-Origin", "Grpcgateway-Referer", "Origin"} {
		origins := header.Values(m)
		if len(origins) == 0 {
			continue
		}
		for _, o := range origins {
			if strings.HasSuffix(o, ":443") {
				o = "https://" + strings.TrimPrefix(strings.TrimSuffix(o, ":443"), "https://")
			} else {
				o = strings.TrimSuffix(o, ":80")
			}
			result = append(result, o)
		}
	}
	return result
}

var goodPaths = regexp.MustCompile(`^[\w/-]{1,128}$`)

func (a Authentication) lookupGatewayPaths(ctx context.Context, procedure string, header http.Header) []string {
	origins := a.lookupOrigins(header)
	if len(origins) == 0 {
		return nil
	}

	var paths []string
	switch procedure {
	case "/kas.AccessService/Rewrap":
		paths = append(paths, "/kas/v2/rewrap")
	default:
		patterns := header["Pattern"]
		if len(patterns) == 0 {
			a.logger.InfoContext(ctx, "underspecified grpc gateway path; no pattern header", slog.Any("origin", origins), slog.String("procedure", procedure))
			paths = allowedPublicEndpoints[:]
		} else {
			a.logger.InfoContext(ctx, "underspecified grpc gateway path; patterns found", slog.Any("origin", origins), slog.String("procedure", procedure), slog.Any("patterns", patterns))
		}
		for _, pattern := range patterns {
			if matched := goodPaths.MatchString(pattern); matched {
				paths = append(paths, pattern)
			}
		}
		if len(paths) != len(patterns) {
			a.logger.WarnContext(ctx, "invalid grpc gateway path; ignoring one or more invalid patterns", slog.Any("origin", origins), slog.String("procedure", procedure), slog.Any("patterns", patterns))
		}
	}

	u := make([]string, 0, len(origins)*len(paths))
	for _, o := range origins {
		for _, p := range paths {
			u = append(u, normalizeURL(o, &url.URL{Path: p}))
		}
	}
	return u
}

func (a Authentication) ipcReauthCheck(ctx context.Context, path string, header http.Header) (context.Context, error) {
	for _, route := range a.ipcReauthRoutes {
		reqPath := path
		if reqPath == route {
			token, tokenRaw, tokenType, err := a.parseTokenFromHeader(header)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthenticated"))
			}

			u := []string{path}
			u = append(u, a.lookupGatewayPaths(ctx, path, header)...)

			// Validate the token and create a JWT token
			key, err := a.checkToken(ctx, token, tokenRaw, tokenType, receiverInfo{
				u: u,
				m: []string{http.MethodPost},
			}, header["Dpop"])
			if err != nil && !errors.Is(err, ErrNoDPoPSkipCheck) {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthenticated"))
			}

			// Fetch userinfo, only exchange token if needed
			userInfoRaw, err := a.GetUserInfoWithExchange(ctx, token.Issuer(), token.Subject(), tokenRaw)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, err)
			}

			// Return the next context with the token
			return ctxAuth.ContextWithAuthNInfo(ctx, key, token, tokenRaw, userInfoRaw), nil
		}
	}
	return ctx, nil
}
