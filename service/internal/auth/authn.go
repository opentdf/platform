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

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"google.golang.org/grpc/metadata"

	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
)

var (
	// Set of allowed public endpoints that do not require authentication
	allowedPublicEndpoints = [...]string{
		// Well Known Configuration Endpoints
		"/wellknownconfiguration.WellKnownService/GetWellKnownConfiguration",
		"/.well-known/opentdf-configuration",
		// KAS Public Key Endpoints
		"/kas.AccessService/PublicKey",
		"/kas.AccessService/LegacyPublicKey",
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

	// Exported error variables for client ID processing
	ErrClientIDClaimNotConfigured = errors.New("no client ID claim configured")
	ErrClientIDClaimNotFound      = errors.New("client ID claim not found")
	ErrClientIDClaimNotString     = errors.New("client ID claim is not a string")

	canonicalIPCHeaderClientID    = http.CanonicalHeaderKey("x-ipc-auth-client-id")
	canonicalIPCHeaderAccessToken = http.CanonicalHeaderKey("x-ipc-access-token")
)

const (
	refreshInterval = 15 * time.Minute
	ActionRead      = "read"
	ActionWrite     = "write"
	ActionDelete    = "delete"
	ActionUnsafe    = "unsafe"
	ActionOther     = "other"
)

// Authentication holds a jwks cache and information about the openid configuration
type Authentication struct {
	enforceDPoP bool
	// keySet holds a cached key set
	cachedKeySet jwk.Set
	// openidConfigurations holds the openid configuration for the issuer
	oidcConfiguration AuthNConfig
	// Casbin enforcer
	enforcer *Enforcer
	// Public Routes HTTP & gRPC
	publicRoutes []string
	// IPC Reauthorization Routes
	ipcReauthRoutes []string
	// Custom Logger
	logger *logger.Logger

	// Used for testing
	_testCheckTokenFunc func(ctx context.Context, authHeader []string, dpopInfo receiverInfo, dpopHeader []string) (jwt.Token, context.Context, error)
}

// Creates new authN which is used to verify tokens for a set of given issuers
func NewAuthenticator(ctx context.Context, cfg Config, logger *logger.Logger, wellknownRegistration func(namespace string, config any) error) (*Authentication, error) {
	a := &Authentication{
		enforceDPoP: cfg.EnforceDPoP,
		logger:      logger,
	}

	// validate the configuration
	if err := cfg.validateAuthNConfig(a.logger); err != nil {
		return nil, err
	}

	cache := jwk.NewCache(ctx)

	// Build new cache
	// Discover OIDC Configuration
	oidcConfig, err := DiscoverOIDCConfiguration(ctx, cfg.Issuer, a.logger)
	if err != nil {
		return nil, err
	}

	// If the issuer is different from the one in the configuration, update the configuration
	// This could happen if we are hitting an internal endpoint. Example we might point to https://keycloak.opentdf.svc/realms/opentdf
	// but the external facing issuer is https://keycloak.opentdf.local/realms/opentdf
	if oidcConfig.Issuer != cfg.Issuer {
		cfg.Issuer = oidcConfig.Issuer
	}

	cacheInterval, err := time.ParseDuration(cfg.CacheRefresh)
	if err != nil {
		logger.ErrorContext(ctx,
			"invalid cache_refresh_interval",
			slog.String("cache_refresh_interval", cfg.CacheRefresh),
			slog.Any("err", err),
		)
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

	a.oidcConfiguration = cfg.AuthNConfig

	// Try an register oidc issuer to wellknown service but don't return an error if it fails
	if err := wellknownRegistration("platform_issuer", cfg.Issuer); err != nil {
		logger.Warn("failed to register platform issuer", slog.Any("error", err))
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
		logger.Warn("failed to register platform idp information", slog.Any("error", err))
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
		log := a.logger

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
		accessTok, ctx, err := a.checkToken(r.Context(), header, receiverInfo{
			u: []string{normalizeURL(origin, r.URL)},
			m: []string{r.Method},
		}, dp)
		if err != nil {
			log.WarnContext(ctx,
				"unauthenticated",
				slog.Any("error", err),
				slog.Any("dpop", dp),
			)
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		clientID, err := a.getClientIDFromToken(ctx, accessTok)
		if err != nil {
			log.WarnContext(
				ctx,
				"could not determine client ID from token",
				slog.Any("err", err),
			)
		} else {
			log = log.
				With("client_id", clientID).
				With("configured_client_id_claim_name", a.oidcConfiguration.Policy.ClientIDClaim)
			ctx = ctxAuth.EnrichIncomingContextMetadataWithAuthn(ctx, log, clientID)
		}

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
		if allow, err := a.enforcer.Enforce(accessTok, r.URL.Path, action); err != nil {
			if err.Error() == "permission denied" {
				log.WarnContext(
					ctx,
					"permission denied",
					slog.String("azp", accessTok.Subject()),
					slog.Any("error", err),
				)
				http.Error(w, "permission denied", http.StatusForbidden)
				return
			}
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		} else if !allow {
			log.WarnContext(
				ctx,
				"permission denied",
				slog.String("azp", accessTok.Subject()),
			)
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}

		r = r.WithContext(ctx)
		handler.ServeHTTP(w, r)
	})
}

// UnaryServerInterceptor is a grpc interceptor that verifies the token in the metadata
func (a Authentication) ConnectUnaryServerInterceptor() connect.UnaryInterceptorFunc {
	interceptor := func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(
			ctx context.Context,
			req connect.AnyRequest,
		) (connect.AnyResponse, error) {
			// if the token is already in the context, skip the interceptor
			if ctxAuth.GetAccessTokenFromContext(ctx, a.logger) != nil {
				return next(ctx, req)
			}

			log := a.logger

			ri := receiverInfo{
				u: []string{req.Spec().Procedure},
				m: []string{http.MethodPost},
			}

			ri.u = append(ri.u, a.lookupGatewayPaths(ctx, req.Spec().Procedure, req.Header())...)

			// Interceptor Logic
			// Allow health checks and other public routes to pass through
			if slices.ContainsFunc(a.publicRoutes, a.isPublicRoute(req.Spec().Procedure)) { //nolint:contextcheck // There is no way to pass a context here
				return next(ctx, req)
			}

			header := req.Header()["Authorization"]
			if len(header) < 1 {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing authorization header"))
			}

			// parse the rpc method
			p := strings.Split(req.Spec().Procedure, "/")
			resource := p[1] + "/" + p[2]
			action := getAction(p[2])

			token, ctxWithJWK, err := a.checkToken(
				ctx,
				header,
				ri,
				req.Header()["Dpop"],
			)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthenticated"))
			}

			clientID, err := a.getClientIDFromToken(ctxWithJWK, token)
			if err != nil {
				log.WarnContext(
					ctxWithJWK,
					"could not determine client ID from token",
					slog.Any("err", err),
				)
			} else {
				log = log.
					With("client_id", clientID).
					With("configured_client_id_claim_name", a.oidcConfiguration.Policy.ClientIDClaim)
				ctxWithJWK = ctxAuth.EnrichIncomingContextMetadataWithAuthn(ctxWithJWK, log, clientID)
			}

			// Check if the token is allowed to access the resource
			if allowed, err := a.enforcer.Enforce(token, resource, action); err != nil {
				if err.Error() == "permission denied" {
					log.WarnContext(
						ctxWithJWK,
						"permission denied",
						slog.String("azp", token.Subject()),
						slog.Any("error", err),
					)
					return nil, connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
				}
				return nil, err
			} else if !allowed {
				log.WarnContext(ctxWithJWK, "permission denied", slog.String("azp", token.Subject()))
				return nil, connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
			}

			return next(ctxWithJWK, req)
		})
	}
	return connect.UnaryInterceptorFunc(interceptor)
}

// IPCMetadataClientInterceptor transfers gRPC outgoing metadata to Connect request headers for IPC calls
func IPCMetadataClientInterceptor(log *logger.Logger) connect.UnaryInterceptorFunc {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(
			ctx context.Context,
			req connect.AnyRequest,
		) (connect.AnyResponse, error) {
			// Only apply to outgoing client requests
			if !req.Spec().IsClient {
				return next(ctx, req)
			}

			incoming := true
			clientID, err := ctxAuth.GetClientIDFromContext(ctx, incoming)
			if err != nil {
				// metadata will not always be found over IPC - log other errors
				if !errors.Is(err, ctxAuth.ErrNoMetadataFound) {
					log.ErrorContext(ctx, "IPCMetadataClientInterceptor", slog.Any("error", err))
				}
			} else {
				req.Header().Add(canonicalIPCHeaderClientID, clientID)
			}

			authToken := ctxAuth.GetRawAccessTokenFromContext(ctx, log)
			if authToken != "" {
				req.Header().Add(canonicalIPCHeaderAccessToken, authToken)
			}

			return next(ctx, req)
		})
	})
}

// IPCUnaryServerInterceptor is a grpc interceptor that:
// 1. verifies the token in the metadata
// 2. reauthorizes the token if the route is in the list
// 3. translates known IPC Connect request headers back to context metadata for downstream consumers
func (a Authentication) IPCUnaryServerInterceptor() connect.UnaryInterceptorFunc {
	interceptor := func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(
			ctx context.Context,
			req connect.AnyRequest,
		) (connect.AnyResponse, error) {
			incomingMD, hasIncoming := metadata.FromIncomingContext(ctx)

			// Transfer metadata from headers to context for IPC calls due to Connect/IPC limitations
			md := metadata.New(map[string]string{})
			if clientID := req.Header().Get(canonicalIPCHeaderClientID); clientID != "" {
				md.Set(ctxAuth.ClientIDKey, clientID)
			}
			if authToken := req.Header().Get(canonicalIPCHeaderAccessToken); authToken != "" {
				md.Set(ctxAuth.AccessTokenKey, authToken)
			}
			if hasIncoming {
				md = metadata.Join(md, incomingMD.Copy())
			}
			ctx = metadata.NewIncomingContext(ctx, md)

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

// checkToken is a helper function to verify the token.
func (a *Authentication) checkToken(ctx context.Context, authHeader []string, dpopInfo receiverInfo, dpopHeader []string) (jwt.Token, context.Context, error) {
	// Use the test function if it is set
	if a._testCheckTokenFunc != nil {
		return a._testCheckTokenFunc(ctx, authHeader, dpopInfo, dpopHeader)
	}

	var tokenRaw string

	// If we don't get a DPoP/Bearer token type, we can't proceed
	switch {
	case strings.HasPrefix(authHeader[0], "DPoP "):
		tokenRaw = strings.TrimPrefix(authHeader[0], "DPoP ")
	case strings.HasPrefix(authHeader[0], "Bearer "):
		tokenRaw = strings.TrimPrefix(authHeader[0], "Bearer ")
	default:
		a.logger.WarnContext(ctx, "failed to validate authentication header: not of type bearer or dpop", slog.String("header", authHeader[0]))
		return nil, nil, errors.New("not of type bearer or dpop")
	}

	// Now we verify the token signature
	accessToken, err := jwt.Parse([]byte(tokenRaw),
		jwt.WithKeySet(a.cachedKeySet),
		jwt.WithValidate(true),
		jwt.WithIssuer(a.oidcConfiguration.Issuer),
		jwt.WithAudience(a.oidcConfiguration.Audience),
		jwt.WithAcceptableSkew(a.oidcConfiguration.TokenSkew),
	)
	if err != nil {
		a.logger.Warn("failed to validate auth token", slog.Any("err", err))
		return nil, nil, err
	}

	// Get actor ID (sub) from unverified token for audit and add to context
	// Only set the actor ID if it is not already defined
	existingActorID := audit.GetAuditDataFromContext(ctx).ActorID
	if existingActorID == "" {
		actorID := accessToken.Subject()
		ctx = audit.ContextWithActorID(ctx, actorID)
	}

	_, tokenHasCNF := accessToken.Get("cnf")
	if !tokenHasCNF && !a.enforceDPoP {
		// this condition is not quite tight because it's possible that the `cnf` claim may
		// come from token introspection
		ctx = ctxAuth.ContextWithAuthNInfo(ctx, nil, accessToken, tokenRaw)
		return accessToken, ctx, nil
	}
	dpopKey, err := a.validateDPoP(accessToken, tokenRaw, dpopInfo, dpopHeader)
	if err != nil {
		a.logger.Warn("failed to validate dpop", slog.Any("err", err))
		return nil, nil, err
	}
	ctx = ctxAuth.ContextWithAuthNInfo(ctx, dpopKey, accessToken, tokenRaw)
	return accessToken, ctx, nil
}

func (a Authentication) validateDPoP(accessToken jwt.Token, acessTokenRaw string, dpopInfo receiverInfo, headers []string) (jwk.Key, error) {
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
	h.Write([]byte(acessTokenRaw))
	if ath != base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h.Sum(nil)) {
		return nil, errors.New("incorrect `ath` claim in DPoP JWT")
	}
	return dpopKey, nil
}

func (a Authentication) isPublicRoute(path string) func(string) bool {
	return func(route string) bool {
		matched, err := doublestar.Match(route, path)
		if err != nil {
			a.logger.Warn("error matching route",
				slog.String("route", route),
				slog.String("path", path),
				slog.Any("error", err),
			)
			return false
		}
		a.logger.Trace("matching route",
			slog.String("route", route),
			slog.String("path", path),
			slog.Bool("matched", matched),
		)
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
			a.logger.InfoContext(ctx,
				"underspecified grpc gateway path; no pattern header",
				slog.Any("origin", origins),
				slog.String("procedure", procedure),
			)
			paths = allowedPublicEndpoints[:]
		} else {
			a.logger.InfoContext(ctx,
				"underspecified grpc gateway path; patterns found",
				slog.Any("origin", origins),
				slog.String("procedure", procedure),
				slog.Any("patterns", patterns),
			)
		}
		for _, pattern := range patterns {
			if matched := goodPaths.MatchString(pattern); matched {
				paths = append(paths, pattern)
			}
		}
		if len(paths) != len(patterns) {
			a.logger.WarnContext(ctx,
				"invalid grpc gateway path; ignoring one or more invalid patterns",
				slog.Any("origin", origins),
				slog.String("procedure", procedure),
				slog.Any("patterns", patterns),
			)
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
			// Extract the token from the request
			authHeader := header["Authorization"]
			if len(authHeader) < 1 {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing authorization header"))
			}

			u := []string{path}
			u = append(u, a.lookupGatewayPaths(ctx, path, header)...)

			// Validate the token and create a JWT token
			token, ctxWithJWK, err := a.checkToken(ctx, authHeader, receiverInfo{
				u: u,
				m: []string{http.MethodPost},
			}, header["Dpop"])
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthenticated"))
			}

			// Return the next context with the token
			clientID, err := a.getClientIDFromToken(ctxWithJWK, token)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthenticated"))
			}
			return ctxAuth.EnrichIncomingContextMetadataWithAuthn(ctxWithJWK, a.logger, clientID), nil
		}
	}
	return ctx, nil
}

// getClientIDFromToken returns the client ID from the token if found (dot notation)
func (a *Authentication) getClientIDFromToken(ctx context.Context, tok jwt.Token) (string, error) {
	clientIDClaim := a.oidcConfiguration.Policy.ClientIDClaim
	if clientIDClaim == "" {
		return "", ErrClientIDClaimNotConfigured
	}
	claimsMap, err := tok.AsMap(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to parse token as a map and find claim at [%s]: %w", clientIDClaim, err)
	}
	found := dotNotation(claimsMap, clientIDClaim)
	if found == nil {
		return "", fmt.Errorf("%w at [%s]", ErrClientIDClaimNotFound, clientIDClaim)
	}
	clientID, isString := found.(string)
	if !isString {
		return "", fmt.Errorf("%w at [%s]", ErrClientIDClaimNotString, clientIDClaim)
	}
	return clientID, nil
}
