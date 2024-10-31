package sdk

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"github.com/opentdf/platform/sdk/audit"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/internal/archive"
	"github.com/xeipuuv/gojsonschema"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type SDK struct {
	config
	*kasKeyCache
	conn                    *grpc.ClientConn
	dialOptions             []grpc.DialOption
	tokenSource             auth.AccessTokenSource
	Namespaces              namespaces.NamespaceServiceClient
	Attributes              attributes.AttributesServiceClient
	ResourceMapping         resourcemapping.ResourceMappingServiceClient
	SubjectMapping          subjectmapping.SubjectMappingServiceClient
	KeyAccessServerRegistry kasregistry.KeyAccessServerRegistryServiceClient
	Unsafe                  unsafe.UnsafeServiceClient
	Authorization           authorization.AuthorizationServiceClient
	EntityResoution         entityresolution.EntityResolutionServiceClient
	wellknownConfiguration  wellknownconfiguration.WellKnownServiceClient
}

type TdfType string

const (
	OIDCWellKnownConfigurationEndpoint = "/.well-known/openid-configuration"

	OIDCConfigTokenEndpoint = "token_endpoint"

	Invalid  TdfType = "Invalid"
	Nano     TdfType = "Nano"
	Standard TdfType = "Standard"
)

var (
	URLSchemeRegexp        = regexp.MustCompile(`^https?://`)
	PlatformEndpointRegexp = regexp.MustCompile(`^(https?:\/\/)?(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d+)?|(localhost)(:\d+)?)\/?$`)
)

func New(platformEndpoint string, opts ...Option) (*SDK, error) {
	var (
		platformConn *grpc.ClientConn // Connection to the platform
		err          error
	)

	// Set default options
	cfg := &config{
		dialOption: grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12,
		})),
	}

	// Apply options
	for _, opt := range opts {
		opt(cfg)
	}

	// If IPC is enabled, we need to have a core connection
	if cfg.ipc && cfg.coreConn == nil {
		return nil, ErrSDKIPCCoreConnectionRequired
	}

	// If KAS session key is not provided, generate a new one
	if cfg.kasSessionKey == nil {
		key, err := ocrypto.NewRSAKeyPair(tdf3KeySize)
		if err != nil {
			return nil, err
		}
		cfg.kasSessionKey = &key
	}

	// once we change KAS to use standard DPoP we can put this all in the `build()` method
	dialOptions := append([]grpc.DialOption{}, cfg.build()...)
	// Add extra grpc dial options if provided. This is useful during tests.
	if len(cfg.extraDialOptions) > 0 {
		dialOptions = append(dialOptions, cfg.extraDialOptions...)
	}

	// IF IPC is disabled we build a connection to the platform
	if !cfg.ipc {
		platformEndpoint, err = SanitizePlatformEndpoint(platformEndpoint)
		if err != nil {
			return nil, errors.Join(ErrPlatformEndpointMalformed, err)
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
			pcfg, err = fetchPlatformConfiguration(platformEndpoint, dialOptions)
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

	var uci []grpc.UnaryClientInterceptor

	// Add request ID interceptor
	uci = append(uci, audit.MetadataAddingClientInterceptor)

	accessTokenSource, err := buildIDPTokenSource(cfg)
	if err != nil {
		return nil, err
	}
	if accessTokenSource != nil {
		interceptor := auth.NewTokenAddingInterceptor(accessTokenSource, cfg.tlsConfig)
		uci = append(uci, interceptor.AddCredentials)
	}

	dialOptions = append(dialOptions, grpc.WithChainUnaryInterceptor(uci...))

	// If coreConn is provided, use it as the platform connection
	if cfg.coreConn != nil {
		platformConn = cfg.coreConn
	} else {
		platformConn, err = grpc.NewClient(platformEndpoint, dialOptions...)
		if err != nil {
			return nil, errors.Join(ErrGrpcDialFailed, err)
		}
	}

	return &SDK{
		config:                  *cfg,
		kasKeyCache:             newKasKeyCache(),
		conn:                    platformConn,
		dialOptions:             dialOptions,
		tokenSource:             accessTokenSource,
		Attributes:              attributes.NewAttributesServiceClient(platformConn),
		Namespaces:              namespaces.NewNamespaceServiceClient(platformConn),
		ResourceMapping:         resourcemapping.NewResourceMappingServiceClient(platformConn),
		SubjectMapping:          subjectmapping.NewSubjectMappingServiceClient(platformConn),
		Unsafe:                  unsafe.NewUnsafeServiceClient(platformConn),
		KeyAccessServerRegistry: kasregistry.NewKeyAccessServerRegistryServiceClient(platformConn),
		Authorization:           authorization.NewAuthorizationServiceClient(platformConn),
		EntityResoution:         entityresolution.NewEntityResolutionServiceClient(platformConn),
		wellknownConfiguration:  wellknownconfiguration.NewWellKnownServiceClient(platformConn),
	}, nil
}

func SanitizePlatformEndpoint(e string) (string, error) {
	// check if there's a scheme, if not, add https
	if !URLSchemeRegexp.MatchString(e) {
		e = "https://" + e
	}

	if !PlatformEndpointRegexp.MatchString(e) {
		return "", ErrPlatformEndpointMalformed
	}

	u, err := url.ParseRequestURI(e)
	if err != nil {
		return "", errors.Join(ErrPlatformEndpointParseFailed, err)
	}

	p := u.Port()
	if p == "" {
		if u.Scheme == "http" {
			p = "80"
		} else {
			p = "443"
		}
	}

	return net.JoinHostPort(u.Hostname(), p), nil
}

func buildIDPTokenSource(c *config) (auth.AccessTokenSource, error) {
	var ts auth.AccessTokenSource
	var err error

	if c.customAccessTokenSource != nil {
		return c.customAccessTokenSource, nil
	}

	// There are uses for uncredentialed clients (i.e. consuming the well-known configuration).
	if c.clientCredentials == nil && c.oauthAccessTokenSource == nil {
		return nil, nil //nolint:nilnil // not having credentials is not an error
	}

	if c.certExchange != nil && c.tokenExchange != nil {
		return nil, ErrAuthTokenExchangeOrCertExchange
	}

	if c.dpopKey == nil {
		rsaKeyPair, err := ocrypto.NewRSAKeyPair(dpopKeySize)
		if err != nil {
			return nil, errors.Join(ErrSDKRSAKeyGenerationFailed, err)
		}
		c.dpopKey = &rsaKeyPair
	}

	switch {
	case c.oauthAccessTokenSource != nil:
		ts, err = NewOAuthAccessTokenSource(c.oauthAccessTokenSource, c.scopes, c.dpopKey)
	case c.certExchange != nil:
		ts, err = NewCertExchangeTokenSource(*c.certExchange, *c.clientCredentials, c.tokenEndpoint, c.dpopKey)
	case c.tokenExchange != nil:
		ts, err = NewIDPTokenExchangeTokenSource(
			*c.tokenExchange,
			*c.clientCredentials,
			c.tokenEndpoint,
			c.scopes,
			c.dpopKey,
		)
	default:
		ts, err = NewIDPAccessTokenSource(
			*c.clientCredentials,
			c.tokenEndpoint,
			c.scopes,
			c.dpopKey,
		)
	}

	return ts, err
}

// Close closes the underlying grpc.ClientConn.
func (s SDK) Close() error {
	if s.conn == nil {
		return nil
	}
	if err := s.conn.Close(); err != nil {
		return errors.Join(ErrSDKShutdownFailed, err)
	}
	return nil
}

// Conn returns the underlying grpc.ClientConn.
func (s SDK) Conn() *grpc.ClientConn {
	return s.conn
}

// String returns the string representation of the applies to state.
func (t TdfType) String() string {
	return string(t)
}

// String method to make the custom type printable
func GetTdfType(reader io.ReadSeeker) TdfType {
	isValidNanoTdf, _ := IsValidNanoTdf(reader)

	if isValidNanoTdf {
		return Nano
	}

	isValidStandardTdf, _ := IsValidTdf(reader)

	if isValidStandardTdf {
		return Standard
	}

	return Invalid
}

//go:embed schema/manifest.schema.json
var manifestSchema []byte

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
	tdfReader, err := archive.NewTDFReader(reader)
	if err != nil {
		return false, errors.Join(ErrTDFArchiveReaderUnexpected, err)
	}

	manifest, err := tdfReader.Manifest()
	if err != nil {
		return false, errors.Join(ErrTDFReaderManifestUnexpected, err)
	}

	// Convert the embedded data to a string
	manifestSchemaString := string(manifestSchema)
	loader := gojsonschema.NewStringLoader(manifestSchemaString)
	manifestStringLoader := gojsonschema.NewStringLoader(manifest)
	result, err := gojsonschema.Validate(loader, manifestStringLoader)
	if err != nil {
		return false, ErrTDFManifestValidationFailed
	}

	if !result.Valid() {
		return false, ErrTDFManifestInvalid
	}

	return true, nil
}

func IsValidNanoTdf(reader io.ReadSeeker) (bool, error) {
	_, _, err := NewNanoTDFHeaderFromReader(reader)
	if err != nil {
		return false, err
	}

	return true, nil
}

func fetchPlatformConfiguration(platformEndpoint string, dialOptions []grpc.DialOption) (PlatformConfiguration, error) {
	conn, err := grpc.NewClient(platformEndpoint, dialOptions...)
	if err != nil {
		return nil, errors.Join(ErrGrpcDialFailed, err)
	}
	defer conn.Close()

	return getPlatformConfiguration(conn)
}

func getPlatformConfiguration(conn *grpc.ClientConn) (PlatformConfiguration, error) {
	req := wellknownconfiguration.GetWellKnownConfigurationRequest{}
	wellKnownConfig := wellknownconfiguration.NewWellKnownServiceClient(conn)

	response, err := wellKnownConfig.GetWellKnownConfiguration(context.Background(), &req)
	if err != nil {
		return nil, errors.Join(ErrPlatformConfigRetrieval, err)
	}
	// Get token endpoint
	configuration := response.GetConfiguration()

	return configuration.AsMap(), nil
}

// TODO: This should be moved to a separate package. We do discovery in ../service/internal/auth/discovery.go
func getTokenEndpoint(c config) (string, error) {
	issuerURL, ok := c.PlatformConfiguration[PlatformConfigIssuer].(string)

	if !ok {
		return "", ErrPlatformConfigIssuerNotFound
	}

	oidcConfigURL := issuerURL + OIDCWellKnownConfigurationEndpoint

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, oidcConfigURL, nil)
	if err != nil {
		return "", err
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: c.tlsConfig,
		},
	}

	resp, err := httpClient.Do(req)
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
	tokenEndpoint, ok := config[OIDCConfigTokenEndpoint].(string)
	if !ok {
		return "", ErrOIDCTokenEndpointMissing
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
		s.kasKeyCache.store(KASInfo{
			URL:       url,
			PublicKey: key.GetPem(),
			KID:       key.GetKid(),
			Algorithm: algProto2String(key.GetAlg()),
		})
	}
	return nil
}
