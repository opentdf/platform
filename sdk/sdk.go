package sdk

import (
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration/wellknownconfigurationconnect"
	"github.com/opentdf/platform/sdk/audit"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/httputil"
	"github.com/opentdf/platform/sdk/internal/zipstream"
	"github.com/opentdf/platform/sdk/sdkconnect"
	"github.com/xeipuuv/gojsonschema"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const (
	// Failure while connecting to a service.
	// Check your configuration and/or retry.
	ErrGrpcDialFailed      = Error("failed to dial grpc endpoint")
	ErrShutdownFailed      = Error("failed to shutdown sdk")
	ErrPlatformUnreachable = Error("platform unreachable or not responding")
	// ErrHealthCheckUnsupported is returned by SDK.IsHealthy when the SDK is configured
	// in IPC mode, which does not support the gRPC Health protocol.
	ErrHealthCheckUnsupported        = Error("health check not supported in IPC mode")
	ErrPlatformConfigFailed          = Error("failed to retrieve platform configuration")
	ErrPlatformEndpointMalformed     = Error("platform endpoint is malformed")
	ErrPlatformIssuerNotFound        = Error("issuer not found in well-known idp configuration")
	ErrPlatformAuthzEndpointNotFound = Error("authorization_endpoint not found in well-known idp configuration")
	ErrPlatformTokenEndpointNotFound = Error("token_endpoint not found in well-known idp configuration")
	ErrPlatformEndpointNotFound      = Error("platform_endpoint not found in well-known configuration")
	ErrAccessTokenInvalid            = Error("access token is invalid")
	ErrWellKnowConfigEmpty           = Error("well-known configuration is empty")
	ErrAttributeNotFound             = Error("attribute not found")
)

var (
	// Package-level logger for internal SDK functions
	packageLogger *slog.Logger
	loggerMutex   sync.RWMutex
)

type Error string

func (c Error) Error() string {
	return string(c)
}

// getLogger returns the package-level logger, defaulting to slog.Default() if not set to
// provide access to the logger in exported functions where signatures are unable to be altered
func getLogger() *slog.Logger {
	loggerMutex.RLock()
	defer loggerMutex.RUnlock()
	if packageLogger != nil {
		return packageLogger
	}
	return slog.Default()
}

// setPackageLogger sets the package-level logger for internal SDK functions
func setPackageLogger(logger *slog.Logger) {
	loggerMutex.Lock()
	defer loggerMutex.Unlock()
	packageLogger = logger
}

type SDK struct {
	config
	*kasKeyCache
	conn                    *ConnectRPCConnection
	tokenSource             auth.AccessTokenSource
	Actions                 sdkconnect.ActionServiceClient
	Attributes              sdkconnect.AttributesServiceClient
	Authorization           sdkconnect.AuthorizationServiceClient
	AuthorizationV2         sdkconnect.AuthorizationServiceClientV2
	EntityResoution         sdkconnect.EntityResolutionServiceClient
	EntityResolutionV2      sdkconnect.EntityResolutionServiceClientV2
	KeyAccessServerRegistry sdkconnect.KeyAccessServerRegistryServiceClient
	Namespaces              sdkconnect.NamespaceServiceClient
	Obligations             sdkconnect.ObligationsServiceClient
	RegisteredResources     sdkconnect.RegisteredResourcesServiceClient
	ResourceMapping         sdkconnect.ResourceMappingServiceClient
	SubjectMapping          sdkconnect.SubjectMappingServiceClient
	DynamicValueMapping     sdkconnect.DynamicValueMappingServiceClient
	Unsafe                  sdkconnect.UnsafeServiceClient
	KeyManagement           sdkconnect.KeyManagementServiceClient
	wellknownConfiguration  sdkconnect.WellKnownServiceClient
}

func New(platformEndpoint string, opts ...Option) (*SDK, error) {
	var (
		platformConn *ConnectRPCConnection // Connection to the platform
		ersConn      *ConnectRPCConnection // Connection to ERS (possibly remote)
		err          error
	)

	// Set default options
	cfg := &config{
		httpClient: httputil.SafeHTTPClientWithTLSConfig(&tls.Config{
			MinVersion: tls.VersionTLS12,
		}),
	}

	// Apply options
	for _, opt := range opts {
		opt(cfg)
	}

	// Set default logger if none provided
	if cfg.logger == nil {
		cfg.logger = slog.Default()
	}

	// Set package-level logger for internal functions
	setPackageLogger(cfg.logger)

	// If IPC is enabled, we need to have a core connection
	if cfg.ipc && cfg.coreConn == nil {
		return nil, errors.New("core connection is required for IPC mode")
	}

	// If KAS session key is not provided, generate a new one
	if cfg.kasSessionKey == nil {
		key, err := ocrypto.NewRSAKeyPair(tdf3KeySize)
		if err != nil {
			return nil, err
		}
		cfg.kasSessionKey = &key
	}

	// IF IPC is disabled we build a validated healthy connection to the platform
	if !cfg.ipc { //nolint:nestif // Most of checks are for errors
		if IsPlatformEndpointMalformed(platformEndpoint) {
			return nil, fmt.Errorf("%w [%v]", ErrPlatformEndpointMalformed, platformEndpoint)
		}
		if cfg.shouldValidatePlatformConnectivity {
			if cfg.coreConn != nil {
				err = validateHealthyPlatformConnection(cfg.coreConn.Endpoint, cfg.coreConn.Client, cfg.coreConn.Options)
				if err != nil {
					return nil, err
				}
			} else {
				err = validateHealthyPlatformConnection(platformEndpoint, cfg.httpClient, cfg.extraClientOptions)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	// If platformConfiguration is not provided, fetch it from the platform
	if cfg.PlatformConfiguration == nil && !cfg.ipc { //nolint:nestif // Most of checks are for errors
		var pcfg PlatformConfiguration
		var err error

		if cfg.coreConn != nil {
			pcfg, err = getPlatformConfiguration(cfg.coreConn) // Pick a connection until cfg.wellknownConn is removed
			if err != nil {
				return nil, errors.Join(ErrPlatformConfigFailed, err)
			}
		} else {
			pcfg, err = getPlatformConfiguration(&ConnectRPCConnection{Endpoint: platformEndpoint, Client: cfg.httpClient, Options: cfg.extraClientOptions})
			if err != nil {
				return nil, errors.Join(ErrPlatformConfigFailed, err)
			}
		}
		cfg.PlatformConfiguration = pcfg
		if cfg.tokenEndpoint == "" {
			cfg.tokenEndpoint, err = getTokenEndpoint(*cfg)
			if err != nil {
				return nil, err
			}
		}
	}
	if cfg.PlatformConfiguration != nil {
		cfg.PlatformConfiguration["platform_endpoint"] = platformEndpoint
	}

	var uci []connect.Interceptor

	// Add request ID interceptor
	uci = append(uci, audit.MetadataAddingConnectInterceptor())

	accessTokenSource, dpopKey, err := buildIDPTokenSource(cfg)
	if err != nil {
		return nil, err
	}

	// Wrap HTTP client with DPoP transport for resource requests. The DPoP key is
	// resolved once in buildIDPTokenSource and returned here so the transport signs
	// proofs with the same key the token source binds tokens to.
	httpClient := cfg.httpClient
	dpopHandledByTransport := false
	if accessTokenSource != nil && dpopKey != nil {
		httpClient, err = auth.NewDPoPHTTPClient(cfg.httpClient, dpopKey, accessTokenSource, cfg.tokenEndpoint)
		if err != nil {
			return nil, err
		}
		dpopHandledByTransport = true
	}

	// When the DPoP transport is active it sets both the Authorization and DPoP
	// headers (with a correctly normalized htu) and handles DPoP-Nonce retries, so
	// the credential interceptor would only overwrite those headers with a weaker
	// proof. Add the interceptor only when the transport is not handling DPoP.
	if accessTokenSource != nil && !dpopHandledByTransport {
		interceptor := auth.NewTokenAddingInterceptorWithClient(accessTokenSource, httpClient)
		uci = append(uci, interceptor.AddCredentialsConnect())
	}

	// If coreConn is provided, use it as the platform connection
	if cfg.coreConn != nil {
		platformConn = cfg.coreConn
	} else {
		platformConn = &ConnectRPCConnection{Endpoint: platformEndpoint, Client: httpClient, Options: append(cfg.extraClientOptions, connect.WithInterceptors(uci...))}
	}

	if cfg.entityResolutionConn != nil {
		ersConn = cfg.entityResolutionConn
	} else {
		ersConn = platformConn
	}

	return &SDK{
		config:                  *cfg,
		kasKeyCache:             newKasKeyCache(),
		conn:                    &ConnectRPCConnection{Client: platformConn.Client, Endpoint: platformConn.Endpoint, Options: platformConn.Options},
		tokenSource:             accessTokenSource,
		Actions:                 sdkconnect.NewActionServiceClientConnectWrapper(platformConn.Client, platformConn.Endpoint, platformConn.Options...),
		Attributes:              sdkconnect.NewAttributesServiceClientConnectWrapper(platformConn.Client, platformConn.Endpoint, platformConn.Options...),
		Namespaces:              sdkconnect.NewNamespaceServiceClientConnectWrapper(platformConn.Client, platformConn.Endpoint, platformConn.Options...),
		Obligations:             sdkconnect.NewObligationsServiceClientConnectWrapper(platformConn.Client, platformConn.Endpoint, platformConn.Options...),
		RegisteredResources:     sdkconnect.NewRegisteredResourcesServiceClientConnectWrapper(platformConn.Client, platformConn.Endpoint, platformConn.Options...),
		ResourceMapping:         sdkconnect.NewResourceMappingServiceClientConnectWrapper(platformConn.Client, platformConn.Endpoint, platformConn.Options...),
		SubjectMapping:          sdkconnect.NewSubjectMappingServiceClientConnectWrapper(platformConn.Client, platformConn.Endpoint, platformConn.Options...),
		DynamicValueMapping:     sdkconnect.NewDynamicValueMappingServiceClientConnectWrapper(platformConn.Client, platformConn.Endpoint, platformConn.Options...),
		Unsafe:                  sdkconnect.NewUnsafeServiceClientConnectWrapper(platformConn.Client, platformConn.Endpoint, platformConn.Options...),
		KeyAccessServerRegistry: sdkconnect.NewKeyAccessServerRegistryServiceClientConnectWrapper(platformConn.Client, platformConn.Endpoint, platformConn.Options...),
		Authorization:           sdkconnect.NewAuthorizationServiceClientConnectWrapper(platformConn.Client, platformConn.Endpoint, platformConn.Options...),
		AuthorizationV2:         sdkconnect.NewAuthorizationServiceClientV2ConnectWrapper(platformConn.Client, platformConn.Endpoint, platformConn.Options...),
		EntityResoution:         sdkconnect.NewEntityResolutionServiceClientConnectWrapper(ersConn.Client, ersConn.Endpoint, ersConn.Options...),
		EntityResolutionV2:      sdkconnect.NewEntityResolutionServiceClientV2ConnectWrapper(ersConn.Client, ersConn.Endpoint, ersConn.Options...),
		KeyManagement:           sdkconnect.NewKeyManagementServiceClientConnectWrapper(platformConn.Client, platformConn.Endpoint, platformConn.Options...),
		wellknownConfiguration:  sdkconnect.NewWellKnownServiceClientConnectWrapper(platformConn.Client, platformConn.Endpoint, platformConn.Options...),
	}, nil
}

func IsPlatformEndpointMalformed(e string) bool {
	u, err := url.ParseRequestURI(e)
	if err != nil || u.Hostname() == "" || strings.Contains(u.Hostname(), ":") {
		return true
	}
	return false
}

func getDPoPJWK(dpopKey *ocrypto.RsaKeyPair) (jwk.Key, error) {
	dpopPrivateKeyPEM, err := dpopKey.PrivateKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("error getting dpop private key: %w", err)
	}

	key, err := jwk.ParseKey([]byte(dpopPrivateKeyPEM), jwk.WithPEM(true))
	if err != nil {
		return nil, fmt.Errorf("error creating JWK: %w", err)
	}

	if err := key.Set(jwk.AlgorithmKey, "RS256"); err != nil {
		return nil, fmt.Errorf("error setting key algorithm: %w", err)
	}

	return key, nil
}

// NewDPoPValidationHTTPClient wraps base so its requests carry a DPoP proof signed
// with the key resolved from opts (the same WithDPoP* options passed to New). It is
// intended for token-endpoint calls made outside the SDK's own connection (e.g. a
// CLI pre-flight credential check): the proof binds the request via htu but carries
// no ath claim or Authorization header, and DPoP-Nonce challenges are retried.
//
// When no DPoP key is configured in opts a fresh ephemeral ES256 key is generated,
// mirroring the default the real SDK client applies in buildIDPTokenSource. This
// keeps the pre-flight validation token request consistent with the credentialed
// client so a DPoP-enforcing token endpoint accepts both; the throwaway validation
// token is never reused, so an ephemeral key is fine.
func NewDPoPValidationHTTPClient(base *http.Client, opts ...Option) (*http.Client, error) {
	c := &config{}
	for _, o := range opts {
		o(c)
	}
	key, err := resolveDPoPKey(c)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve DPoP key: %w", err)
	}
	if key == nil {
		key, err = generateDPoPKeyForAlg(ES256)
		if err != nil {
			return nil, fmt.Errorf("failed to generate default DPoP key: %w", err)
		}
	}
	return auth.NewDPoPHTTPClient(base, key, nil, "")
}

// buildIDPTokenSource builds the access token source and resolves the DPoP key
// once, returning it so the caller can give the DPoP transport the same key the
// token source binds to. The returned key is nil when DPoP is not in effect
// (no credentials, or no key configured for a custom token source).
func buildIDPTokenSource(c *config) (auth.AccessTokenSource, jwk.Key, error) {
	if c.customAccessTokenSource != nil {
		// A custom token source manages its own credentials, but a configured DPoP
		// key still drives the resource-request transport.
		dpopKey, err := resolveDPoPKey(c)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve DPoP key: %w", err)
		}
		return c.customAccessTokenSource, dpopKey, nil
	}

	// Surface a conflicting exchange configuration before the uncredentialed
	// fast-path below, so the misconfiguration is reported instead of silently
	// producing a nil (uncredentialed) token source.
	if c.certExchange != nil && c.tokenExchange != nil {
		return nil, nil, errors.New("cannot do both token exchange and certificate exchange")
	}

	// There are uses for uncredentialed clients (i.e. consuming the well-known configuration).
	if c.clientCredentials == nil && c.oauthAccessTokenSource == nil {
		// DPoP only takes effect once requests are credentialed. If the caller
		// explicitly configured a DPoP key but supplied no credentials, fail loudly
		// rather than silently returning an unbound client and downgrading the
		// caller's expected security posture.
		if c.dpopJWK != nil || len(c.dpopKeyPEM) > 0 || c.dpopAlgorithm != "" || c.dpopKey != nil {
			return nil, nil, errors.New("DPoP configured (WithDPoP*) but no client credentials or OAuth token source supplied")
		}
		return nil, nil, nil
	}

	dpopKey, err := resolveDPoPKey(c)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve DPoP key: %w", err)
	}

	// No DPoP key configured: auto-generate a default ephemeral ES256/P-256 key.
	if dpopKey == nil {
		dpopKey, err = generateDPoPKeyForAlg(ES256)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate default DPoP key: %w", err)
		}
	}

	ts, err := buildIDPTokenSourceFromJWK(c, dpopKey)
	if err != nil {
		return nil, nil, err
	}
	return ts, dpopKey, nil
}

func buildIDPTokenSourceFromJWK(c *config, key jwk.Key) (auth.AccessTokenSource, error) {
	switch {
	case c.oauthAccessTokenSource != nil:
		return newOAuthAccessTokenSourceFromJWK(c.oauthAccessTokenSource, c.scopes, key), nil
	case c.certExchange != nil:
		return newCertExchangeTokenSourceFromJWK(c.logger, *c.certExchange, *c.clientCredentials, c.tokenEndpoint, key)
	case c.tokenExchange != nil:
		return newIDPTokenExchangeTokenSourceFromJWK(c.logger, *c.tokenExchange, *c.clientCredentials, c.tokenEndpoint, c.scopes, key)
	default:
		return newIDPAccessTokenSourceFromJWK(*c.clientCredentials, c.tokenEndpoint, c.scopes, key)
	}
}

func (s SDK) Close() error {
	return nil
}

// Logger returns the configured slog.Logger for this SDK instance
func (s SDK) Logger() *slog.Logger {
	return s.logger
}

// Conn returns the underlying http connection
func (s SDK) Conn() *ConnectRPCConnection {
	return s.conn
}

// IsHealthy reports whether the platform's gRPC Health v1 endpoint is reachable and SERVING.
// The check honors ctx for deadline and cancellation; OTEL tracing works automatically when
// otelconnect.NewInterceptor is registered via WithExtraClientOptions at SDK construction.
//
// Returns:
//   - (true, nil) when the platform reports SERVING.
//   - (false, nil) when the platform is reachable but reports NOT_SERVING or UNKNOWN.
//   - (false, ErrHealthCheckUnsupported) when the SDK is configured in IPC mode.
//   - (false, error) wrapping ErrPlatformUnreachable on transport failure or ctx errors.
func (s SDK) IsHealthy(ctx context.Context) (bool, error) {
	if s.ipc || s.conn == nil {
		return false, ErrHealthCheckUnsupported
	}
	healthy, err := checkPlatformHealth(ctx, s.conn.Endpoint, s.conn.Client, s.conn.Options)
	if err != nil {
		return false, errors.Join(ErrPlatformUnreachable, err)
	}
	return healthy, nil
}

type TdfType string

const (
	Invalid  TdfType = "Invalid"
	Standard TdfType = "Standard"
)

// String returns the string representation of the applies to state.
func (t TdfType) String() string {
	return string(t)
}

// ZIP file Signature
var zipSignature = []byte{0x50, 0x4B, 0x03, 0x04}

// GetTdfType returns the type of TDF based on the reader.
// Reader is reset after the check.
func GetTdfType(reader io.ReadSeeker) TdfType {
	numBytes := 4
	buffer := make([]byte, numBytes)
	n, err := reader.Read(buffer)
	if err != nil {
		return Invalid
	}

	// Reset the reader to its original position
	_, err = reader.Seek(0, io.SeekStart)
	if err != nil {
		return Invalid
	}

	if n < numBytes {
		return Invalid
	}

	// Check if the first 4 bytes match the ZIP signature
	if bytes.Equal(buffer, zipSignature) {
		return Standard
	}

	return Invalid
}

// Indicates JSON Schema validation failed for the manifest or header of the TDF file.
// Some invalid manifests are still usable, so this file may still be usable.
var ErrInvalidPerSchema = errors.New("manifest was not valid")

//go:embed schema/manifest-lax.schema.json
var manifestLaxSchema []byte

//go:embed schema/manifest.schema.json
var manifestStrictSchema []byte

// Detects whether, or not the reader is a valid TDF. It first checks if it can "open" it
// Then attempts to extract a manifest, then finally it validates the manifest using the json schema
// If any of the checks fail, it will return false.
//
// Something to keep in mind is that if we make updates to the schema, such as making certain fields
// 'required', older TDF versions will fail despite being valid. So each time we release an update to
// the TDF spec, we'll need to include the respective schema in the schema directory, then update this code
// to validate against all previously known schema versions.
func IsValidTdf(reader io.ReadSeeker) (bool, error) {
	// create tdf reader
	tdfReader, err := zipstream.NewTDFReader(reader)
	if err != nil {
		return false, fmt.Errorf("zipstream.NewTDFReader failed: %w", err)
	}

	manifest, err := tdfReader.Manifest()
	if err != nil {
		return false, fmt.Errorf("tdfReader.Manifest failed: %w", err)
	}

	return isValidManifest(manifest, Lax)
}

func isValidManifest(manifest string, intensity SchemaValidationIntensity) (bool, error) {
	// Convert the embedded data to a string
	var manifestSchemaString string
	switch intensity {
	case Strict:
		manifestSchemaString = string(manifestStrictSchema)
	case Lax:
		manifestSchemaString = string(manifestLaxSchema)
	case Skip:
		return true, nil
	default:
		manifestSchemaString = string(manifestLaxSchema)
	}
	loader := gojsonschema.NewStringLoader(manifestSchemaString)
	manifestStringLoader := gojsonschema.NewStringLoader(manifest)
	result, err := gojsonschema.Validate(loader, manifestStringLoader)
	if err != nil {
		return false, errors.New("could not validate manifest.json")
	}

	if !result.Valid() {
		return false, fmt.Errorf("%w: %v", ErrInvalidPerSchema, result.Errors())
	}

	return true, nil
}

// checkPlatformHealth issues a single gRPC Health v1 Check against the platform endpoint and
// reports whether the response is SERVING. ctx controls deadline, cancellation, and trace-context.
func checkPlatformHealth(
	ctx context.Context,
	endpoint string,
	httpClient *http.Client,
	options []connect.ClientOption,
) (bool, error) {
	checkURL, err := url.JoinPath(endpoint, "grpc.health.v1.Health", "Check")
	if err != nil {
		return false, err
	}
	healthClient := connect.NewClient[healthpb.HealthCheckRequest, healthpb.HealthCheckResponse](
		httpClient,
		checkURL,
		options...,
	)
	res, err := healthClient.CallUnary(ctx, connect.NewRequest(&healthpb.HealthCheckRequest{}))
	if err != nil {
		return false, err
	}
	return res.Msg.GetStatus() == healthpb.HealthCheckResponse_SERVING, nil
}

// validateHealthyPlatformConnection is the construction-time reachability gate used by New when
// WithConnectionValidation is set. Callers pass cfg.extraClientOptions (pre-auth) because the
// auth and audit interceptors are assembled after this gate fires; the runtime SDK.IsHealthy
// method uses the post-interceptor s.conn.Options instead.
func validateHealthyPlatformConnection(platformEndpoint string, httpClient *http.Client, options []connect.ClientOption) error {
	healthy, err := checkPlatformHealth(context.Background(), platformEndpoint, httpClient, options)
	if err != nil {
		return errors.Join(ErrPlatformUnreachable, err)
	}
	if !healthy {
		return ErrPlatformUnreachable
	}
	return nil
}

func getPlatformConfiguration(conn *ConnectRPCConnection) (PlatformConfiguration, error) {
	req := wellknownconfiguration.GetWellKnownConfigurationRequest{}
	wellKnownConfig := wellknownconfigurationconnect.NewWellKnownServiceClient(conn.Client, conn.Endpoint, conn.Options...)

	response, err := wellKnownConfig.GetWellKnownConfiguration(context.Background(), connect.NewRequest(&req))
	if err != nil {
		return nil, errors.Join(errors.New("unable to retrieve config information, and none was provided"), err)
	}
	// Get token endpoint
	configuration := response.Msg.GetConfiguration()

	return configuration.AsMap(), nil
}

// TODO: This should be moved to a separate package. We do discovery in ../service/internal/auth/discovery.go
func getTokenEndpoint(c config) (string, error) {
	issuerURL, ok := c.PlatformConfiguration["platform_issuer"].(string)

	if !ok {
		return "", errors.New("platform_issuer is not set, or is not a string")
	}

	oidcConfigURL, err := url.JoinPath(issuerURL, ".well-known/openid-configuration")
	if err != nil {
		return "", fmt.Errorf("invalid issuer URL %q: %w", issuerURL, err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, oidcConfigURL, nil)
	if err != nil {
		return "", err
	}

	client := c.httpClient
	if client == nil {
		client = httputil.SafeHTTPClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var config map[string]interface{}

	if err = json.Unmarshal(body, &config); err != nil {
		return "", err
	}
	tokenEndpoint, ok := config["token_endpoint"].(string)
	if !ok {
		return "", errors.New("token_endpoint not found in well-known configuration")
	}

	return tokenEndpoint, nil
}

// StoreKASKeys caches the given values as the public keys associated with the
// KAS at the given URL, replacing any existing keys that are cached for that URL
// with the same algorithm and URL.
// Only one key per url and algorithm is stored in the cache,
// so only store the most recent known key per url & algorithm pair.
func (s *SDK) StoreKASKeys(url string, keys *policy.KasPublicKeySet) error {
	for _, key := range keys.GetKeys() {
		s.store(KASInfo{
			URL:       url,
			PublicKey: key.GetPem(),
			KID:       key.GetKid(),
			Algorithm: algProto2String(key.GetAlg()),
		})
	}
	return nil
}
