package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	"github.com/opentdf/platform/service/pkg/authz"
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
	dpopJWTType     = "dpop+jwt"
	dpopNonceBytes  = 16
	ActionRead      = "read"
	ActionWrite     = "write"
	ActionDelete    = "delete"
	ActionUnsafe    = "unsafe"
	ActionOther     = "other"
)

// Authentication holds a jwks cache and information about the openid configuration
type Authentication struct {
	enforceDPoP bool
	// tokenVerifier validates access tokens against the configured IdP.
	tokenVerifier *TokenVerifier
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
	// DPoP nonce management
	dpopNonceManager *dpopNonceManager

	// Used for testing
	_testCheckTokenFunc func(ctx context.Context, authHeader []string, dpopInfo receiverInfo, dpopHeader []string) (jwt.Token, context.Context, error)
}

// dpopNonceManager manages server-issued DPoP nonces per RFC 9449 §8
type nonceState struct {
	currentNonce  string
	previousNonce string
	rotatedAt     time.Time
}

type dpopNonceManager struct {
	state        atomic.Pointer[nonceState]
	mu           sync.Mutex // serializes rotation only
	expiration   time.Duration
	requireNonce bool
}

func newDPoPNonceManager(requireNonce bool, expiration time.Duration) *dpopNonceManager {
	nm := &dpopNonceManager{
		requireNonce: requireNonce,
		expiration:   expiration,
	}
	nm.state.Store(&nonceState{})
	if requireNonce {
		nm.rotate()
	}
	return nm
}

func (nm *dpopNonceManager) storeRotated(s *nonceState) {
	nonce := make([]byte, dpopNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		panic(fmt.Sprintf("failed to generate nonce: %v", err))
	}
	nm.state.Store(&nonceState{
		previousNonce: s.currentNonce,
		currentNonce:  hex.EncodeToString(nonce),
		rotatedAt:     time.Now(),
	})
}

func (nm *dpopNonceManager) rotate() {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.storeRotated(nm.state.Load())
}

func (nm *dpopNonceManager) getCurrentNonce() string {
	s := nm.state.Load()
	if time.Since(s.rotatedAt) <= nm.expiration {
		return s.currentNonce
	}

	nm.mu.Lock()
	defer nm.mu.Unlock()
	// Double-check after acquiring the lock to prevent concurrent double-rotation.
	s = nm.state.Load()
	if time.Since(s.rotatedAt) > nm.expiration {
		nm.storeRotated(s)
		s = nm.state.Load()
	}
	return s.currentNonce
}

func (nm *dpopNonceManager) validateNonce(nonce string) bool {
	if !nm.requireNonce {
		return true
	}
	s := nm.state.Load()
	return nonce != "" && (nonce == s.currentNonce || nonce == s.previousNonce)
}

// Creates new authN which is used to verify tokens for a set of given issuers
func NewAuthenticator(ctx context.Context, cfg Config, logger *logger.Logger, wellknownRegistration func(namespace string, config any) error) (*Authentication, error) {
	a := &Authentication{
		enforceDPoP:      cfg.EnforceDPoP,
		logger:           logger,
		dpopNonceManager: newDPoPNonceManager(cfg.DPoP.RequireNonce, cfg.DPoP.NonceExpiration),
	}

	tokenVerifier, oidcConfig, err := newTokenVerifier(ctx, cfg.AuthNConfig, a.logger)
	if err != nil {
		return nil, err
	}
	a.tokenVerifier = tokenVerifier

	roleProvider, err := resolveRoleProvider(ctx, cfg, logger)
	if err != nil {
		return nil, err
	}
	casbinConfig := CasbinConfig{
		PolicyConfig: cfg.Policy,
		RoleProvider: roleProvider,
	}
	logger.Info("initializing casbin enforcer")
	if a.enforcer, err = NewCasbinEnforcer(casbinConfig, a.logger); err != nil {
		return nil, fmt.Errorf("failed to initialize casbin enforcer: %w", err)
	}

	// Combine public routes
	a.publicRoutes = append(a.publicRoutes, cfg.PublicRoutes...)
	a.publicRoutes = append(a.publicRoutes, allowedPublicEndpoints[:]...)

	// Combine IPC reauthorization routes
	a.ipcReauthRoutes = append(ipcReauthRoutes[:], cfg.IPCReauthRoutes...)

	a.oidcConfiguration = tokenVerifier.oidcConfiguration

	// Try an register oidc issuer to wellknown service but don't return an error if it fails
	if err := wellknownRegistration("platform_issuer", a.oidcConfiguration.Issuer); err != nil {
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

	// Register DPoP support feature
	if err := wellknownRegistration("supports_dpop", true); err != nil {
		logger.Warn("failed to register dpop support", slog.Any("error", err))
	}

	// Register supported DPoP JWT signing algorithms (RFC 9449 §5.1 dpop_signing_alg_values_supported)
	// structpb.NewStruct rejects []string — convert to []any so each element goes through
	// structpb.NewValue's accepted-type list.
	supportedAlgsStr := make([]string, 0, len(allowedSignatureAlgorithms))
	for alg := range allowedSignatureAlgorithms {
		supportedAlgsStr = append(supportedAlgsStr, alg.String())
	}
	sort.Strings(supportedAlgsStr)
	supportedAlgs := make([]any, len(supportedAlgsStr))
	for i, s := range supportedAlgsStr {
		supportedAlgs[i] = s
	}
	if err := wellknownRegistration("dpop_signing_alg_values_supported", supportedAlgs); err != nil {
		logger.Warn("failed to register dpop supported alg values", slog.Any("error", err))
	}

	if err := wellknownRegistration("dpop_nonce_required", cfg.DPoP.RequireNonce); err != nil {
		logger.Warn("failed to register dpop nonce required", slog.Any("error", err))
	}

	return a, nil
}

type receiverInfo struct {
	// Acceptable URIs of the request
	u []string
	// Allowed HTTP methods of the request
	m []string
}

// DPoPNonceError indicates a missing or expired nonce that the client should retry with a fresh one.
type DPoPNonceError struct {
	Message string
}

func (e *DPoPNonceError) Error() string {
	return e.Message
}

// DPoPNonceMalformedError indicates the nonce claim was present but had an invalid type or format.
// Unlike DPoPNonceError, this is not retryable — the client sent a malformed proof.
type DPoPNonceMalformedError struct {
	Message string
}

func (e *DPoPNonceMalformedError) Error() string {
	return e.Message
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
		publicRoute := slices.ContainsFunc(a.publicRoutes, a.isPublicRoute(r.URL.Path)) //nolint:contextcheck // There is no way to pass a context here
		r = r.WithContext(ctxAuth.ContextWithPublicRoute(r.Context(), publicRoute))
		if publicRoute {
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
			// Check if this is a nonce error requiring a challenge
			var nonceErr *DPoPNonceError
			if errors.As(err, &nonceErr) {
				nonce := a.dpopNonceManager.getCurrentNonce()
				w.Header().Set("DPoP-Nonce", nonce)
				w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			log.WarnContext(ctx,
				"unauthenticated",
				slog.Any("error", err),
				slog.Any("dpop", dp),
			)
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		// Always send fresh nonce in successful responses when nonces are enabled
		if a.dpopNonceManager.requireNonce {
			w.Header().Set("DPoP-Nonce", a.dpopNonceManager.getCurrentNonce())
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
			ctx = authz.ContextWithClientID(ctx, clientID)
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
		roleReq := authz.RoleRequest{
			Issuer:   a.oidcConfiguration.Issuer,
			Resource: r.URL.Path,
			Action:   action,
		}
		ctx, err = a.enforcer.ContextWithClaims(ctx, accessTok, roleReq)
		if err != nil {
			log.WarnContext(r.Context(), "role provider error", slog.Any("error", err)) //nolint:contextcheck // request context is already derived with public route state above.
			if errors.Is(err, ErrPermissionDenied) {
				http.Error(w, "permission denied", http.StatusForbidden)
				return
			}
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if result, err := a.enforcer.Enforce(ctx, accessTok, roleReq); err != nil {
			if errors.Is(err, ErrPermissionDenied) {
				log.WarnContext(
					ctx,
					"permission denied",
					permissionDeniedLogAttrs(accessTok, result.CasbinAuthz, err)...,
				)
				http.Error(w, "permission denied", http.StatusForbidden)
				return
			}
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		} else if !result.Allowed {
			log.WarnContext(
				ctx,
				"permission denied",
				permissionDeniedLogAttrs(accessTok, result.CasbinAuthz, nil)...,
			)
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}

		r = r.WithContext(ctx)
		handler.ServeHTTP(w, r)
	})
}

// ConnectAuthNInterceptor authenticates Connect requests and enriches the
// request context with configured token claims needed by later middleware.
func (a Authentication) ConnectAuthNInterceptor() connect.UnaryInterceptorFunc {
	interceptor := func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(
			ctx context.Context,
			req connect.AnyRequest,
		) (connect.AnyResponse, error) {
			publicRoute := slices.ContainsFunc(a.publicRoutes, a.isPublicRoute(req.Spec().Procedure)) //nolint:contextcheck // There is no way to pass a context here
			ctx = ctxAuth.ContextWithPublicRoute(ctx, publicRoute)
			if publicRoute {
				return next(ctx, req)
			}

			log := a.logger

			ri := receiverInfo{
				u: []string{req.Spec().Procedure},
				m: []string{http.MethodPost},
			}

			header := req.Header()["Authorization"]
			if len(header) < 1 {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing authorization header"))
			}

			token, ctxWithJWK, err := a.checkToken(
				ctx,
				header,
				ri,
				req.Header()["Dpop"],
			)
			if err != nil {
				// Check if this is a nonce error requiring a challenge
				var nonceErr *DPoPNonceError
				if errors.As(err, &nonceErr) {
					nonce := a.dpopNonceManager.getCurrentNonce()
					connectErr := connect.NewError(connect.CodeUnauthenticated, errors.New("unauthenticated"))
					connectErr.Meta().Set("DPoP-Nonce", nonce)
					connectErr.Meta().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
					return nil, connectErr
				}
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthenticated"))
			}

			// Always send fresh nonce in successful responses when nonces are enabled.
			// Wrap next so the DPoP-Nonce header is set on the response, not the outgoing client context.
			if a.dpopNonceManager.requireNonce {
				originalNext := next
				next = func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
					res, err := originalNext(ctx, req)
					if err != nil {
						var connectErr *connect.Error
						if errors.As(err, &connectErr) {
							connectErr.Meta().Set("DPoP-Nonce", a.dpopNonceManager.getCurrentNonce())
						}
						return nil, err
					}
					res.Header().Set("DPoP-Nonce", a.dpopNonceManager.getCurrentNonce())
					return res, nil
				}
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
				ctxWithJWK = authz.ContextWithClientID(ctxWithJWK, clientID)
			}

			roleReq, err := roleRequestForConnectProcedure(a.oidcConfiguration.Issuer, req.Spec().Procedure)
			if err != nil {
				return nil, connect.NewError(connect.CodeInvalidArgument, err)
			}
			ctxWithJWK, err = a.enforcer.ContextWithClaims(ctxWithJWK, token, roleReq)
			if err != nil {
				log.WarnContext(ctxWithJWK, "role provider error", slog.Any("error", err))
				if errors.Is(err, ErrPermissionDenied) {
					return nil, connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
				}
				return nil, connect.NewError(connect.CodeInternal, errors.New("role provider error"))
			}
			return next(ctxWithJWK, req)
		})
	}
	return connect.UnaryInterceptorFunc(interceptor)
}

// ConnectAuthZInterceptor authorizes Connect requests using token and
// configured claims already stored in the request context.
func (a Authentication) ConnectAuthZInterceptor() connect.UnaryInterceptorFunc {
	interceptor := func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(
			ctx context.Context,
			req connect.AnyRequest,
		) (connect.AnyResponse, error) {
			if publicRoute, ok := ctxAuth.PublicRouteFromContext(ctx); ok && publicRoute {
				return next(ctx, req)
			}

			token := ctxAuth.GetAccessTokenFromContext(ctx, a.logger)
			if token == nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing access token in context"))
			}

			roleReq, err := roleRequestForConnectProcedure(a.oidcConfiguration.Issuer, req.Spec().Procedure)
			if err != nil {
				return nil, connect.NewError(connect.CodeInvalidArgument, err)
			}

			log := a.logger
			if result, err := a.enforcer.Enforce(ctx, token, roleReq); err != nil {
				if errors.Is(err, ErrPermissionDenied) {
					log.WarnContext(
						ctx,
						"permission denied",
						permissionDeniedLogAttrs(token, result.CasbinAuthz, err)...,
					)
					return nil, connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
				}
				return nil, err
			} else if !result.Allowed {
				log.WarnContext(ctx, "permission denied", permissionDeniedLogAttrs(token, result.CasbinAuthz, nil)...)
				return nil, connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
			}

			return next(ctx, req)
		})
	}
	return connect.UnaryInterceptorFunc(interceptor)
}

func permissionDeniedLogAttrs(token jwt.Token, casbinAuthz CasbinAuthzLog, err error) []any {
	attrs := []any{slog.String("azp", token.Subject())}

	if casbinAuthz.ConfiguredGroupsClaim != "" || casbinAuthz.SubjectGroups != nil {
		attrs = append(attrs, slog.Group("casbin_authz",
			slog.String("configured_groups_claim", casbinAuthz.ConfiguredGroupsClaim),
			slog.Any("subject_groups", casbinAuthz.SubjectGroups),
		))
	}

	if err != nil {
		attrs = append(attrs, slog.Any("error", err))
	}

	return attrs
}

func roleRequestForConnectProcedure(issuer, procedure string) (authz.RoleRequest, error) {
	parts := strings.Split(procedure, "/")
	if len(parts) < 3 || parts[1] == "" || parts[2] == "" {
		return authz.RoleRequest{}, fmt.Errorf("invalid connect procedure %q", procedure)
	}

	method := parts[2]
	return authz.RoleRequest{
		Issuer:   issuer,
		Resource: path.Join(parts[1], method),
		Action:   getAction(method),
	}, nil
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
				switch {
				case errors.Is(err, ctxAuth.ErrNoMetadataFound):
				case errors.Is(err, ctxAuth.ErrMissingClientID):
					// IPC calls may not propagate tokens/clients across service boundaries, which is not
					// necessarily an error case but is useful to know when debugging
					log.DebugContext(ctx, "IPCMetadataClientInterceptor", slog.Any("error", err))
				default:
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

	var (
		tokenRaw   string
		authScheme string
	)

	// If we don't get a DPoP/Bearer token type, we can't proceed
	switch {
	case strings.HasPrefix(authHeader[0], "DPoP "):
		tokenRaw = strings.TrimPrefix(authHeader[0], "DPoP ")
		authScheme = "DPoP"
	case strings.HasPrefix(authHeader[0], "Bearer "):
		tokenRaw = strings.TrimPrefix(authHeader[0], "Bearer ")
		authScheme = "Bearer"
	default:
		a.logger.WarnContext(ctx, "failed to validate authentication header: not of type bearer or dpop", slog.String("header", authHeader[0]))
		return nil, nil, errors.New("not of type bearer or dpop")
	}

	if a.tokenVerifier == nil {
		return nil, nil, errors.New("access token verifier is not configured")
	}

	accessToken, err := a.tokenVerifier.VerifyAccessToken(ctx, tokenRaw)
	if err != nil {
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
	if tokenHasCNF && authScheme == "Bearer" {
		// RFC 9449 §7.1: DPoP-bound access tokens MUST be presented under the "DPoP"
		// Authorization scheme. Warn for now to surface non-compliant SDKs; will be
		// promoted to a hard reject in a future release once all SDKs are compliant.
		a.logger.WarnContext(ctx, "DPoP-bound access token presented under Bearer Authorization scheme; per RFC 9449 §7.1 the DPoP scheme is required")
	}
	if !tokenHasCNF && !a.enforceDPoP {
		// this condition is not quite tight because it's possible that the `cnf` claim may
		// come from token introspection
		ctx = ctxAuth.ContextWithAuthNInfo(ctx, nil, accessToken, tokenRaw)
		return accessToken, ctx, nil
	}
	dpopKey, err := a.validateDPoP(accessToken, tokenRaw, dpopInfo, dpopHeader)
	if err != nil {
		var nonceErr *DPoPNonceError
		if errors.As(err, &nonceErr) {
			a.logger.DebugContext(ctx, "dpop nonce challenge issued", slog.String("reason", nonceErr.Message))
		} else {
			a.logger.Warn("failed to validate dpop", slog.Any("err", err))
		}
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

	cnfDict, ok := cnf.(map[string]any)
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
	if protectedHeaders.Type() != dpopJWTType {
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

	// Validate nonce if required
	if a.dpopNonceManager.requireNonce {
		nonceI, hasNonce := dpopToken.Get("nonce")
		if !hasNonce {
			return nil, &DPoPNonceError{Message: "missing `nonce` claim in DPoP JWT"}
		}
		nonce, nonceOk := nonceI.(string)
		if !nonceOk {
			return nil, &DPoPNonceMalformedError{Message: "`nonce` claim invalid format in DPoP JWT"}
		}
		if !a.dpopNonceManager.validateNonce(nonce) {
			return nil, &DPoPNonceError{Message: "invalid or expired `nonce` claim in DPoP JWT"}
		}
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

func (a Authentication) ipcReauthCheck(ctx context.Context, path string, header http.Header) (context.Context, error) {
	for _, route := range a.ipcReauthRoutes {
		reqPath := path
		if reqPath == route {
			// Extract the token from the request
			authHeader := header["Authorization"]
			if len(authHeader) < 1 {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing authorization header"))
			}

			// Validate the token and create a JWT token
			token, ctxWithJWK, err := a.checkToken(ctx, authHeader, receiverInfo{
				u: []string{path},
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
			ctxWithJWK = ctxAuth.EnrichIncomingContextMetadataWithAuthn(ctxWithJWK, a.logger, clientID)
			return authz.ContextWithClientID(ctxWithJWK, clientID), nil
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
