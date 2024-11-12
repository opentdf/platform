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

const (
	// Failure while connecting to a service.
	// Check your configuration and/or retry.
	ErrGrpcDialFailed                 = Error("failed to dial grpc endpoint")
	ErrShutdownFailed                 = Error("failed to shutdown sdk")
	ErrPlatformConfigFailed           = Error("failed to retrieve platform configuration")
	ErrPlatformEndpointMalformed      = Error("platform endpoint is malformed")
	ErrPlatformIssuerNotFound         = Error("issuer not found in well-known idp configuration")
	ErrPlatformAuthzEndpointNotFound  = Error("authorization_endpoint not found in well-known idp configuration")
	ErrPlatformTokenEndpointNotFound  = Error("token_endpoint not found in well-known idp configuration")
	ErrPlatformPublicClientIDNotFound = Error("public_client_id not found in well-known idp configuration")
	ErrAccessTokenInvalid             = Error("access token is invalid")
)

type Error string

func (c Error) Error() string {
	return string(c)
}

type SDK struct {
	config
	*kasKeyCache
	*collectionStore
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
		collectionStore:         cfg.collectionStore,
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
	if !regexp.MustCompile(`^https?://`).MatchString(e) {
		e = "https://" + e
	}

	if !regexp.MustCompile(`^(https?:\/\/)?(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d+)?|(localhost)(:\d+)?)\/?$`).MatchString(e) {
		return "", errors.New("platform endpoint is not valid")
	}

	u, err := url.ParseRequestURI(e)
	if err != nil {
		return "", errors.Join(fmt.Errorf("cannot parse platform endpoint(%s)", e), err)
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
	if c.customAccessTokenSource != nil {
		return c.customAccessTokenSource, nil
	}

	// There are uses for uncredentialed clients (i.e. consuming the well-known configuration).
	if c.clientCredentials == nil && c.oauthAccessTokenSource == nil {
		return nil, nil //nolint:nilnil // not having credentials is not an error
	}

	if c.certExchange != nil && c.tokenExchange != nil {
		return nil, fmt.Errorf("cannot do both token exchange and certificate exchange")
	}

	if c.dpopKey == nil {
		rsaKeyPair, err := ocrypto.NewRSAKeyPair(dpopKeySize)
		if err != nil {
			return nil, fmt.Errorf("could not generate RSA Key: %w", err)
		}
		c.dpopKey = &rsaKeyPair
	}

	var ts auth.AccessTokenSource
	var err error

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
	if s.collectionStore != nil {
		s.collectionStore.close()
	}

	if s.conn == nil {
		return nil
	}
	if err := s.conn.Close(); err != nil {
		return errors.Join(ErrShutdownFailed, err)
	}
	return nil
}

// Conn returns the underlying grpc.ClientConn.
func (s SDK) Conn() *grpc.ClientConn {
	return s.conn
}

type TdfType string

const (
	Invalid  TdfType = "Invalid"
	Nano     TdfType = "Nano"
	Standard TdfType = "Standard"
)

// String returns the string representation of the applies to state.
func (t TdfType) String() string {
	return string(t)
}

var (
	// ZIP file Signature
	zipSignature = []byte{0x50, 0x4B, 0x03, 0x04}
	// Nano TDF Signature
	nanoSignature = []byte{0x4C, 0x31, 0x4C}
)

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

	// Check if the first 3 bytes match the Nano signature
	if bytes.Equal(buffer[:3], nanoSignature) {
		return Nano
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
		return false, fmt.Errorf("archive.NewTDFReader failed: %w", err)
	}

	manifest, err := tdfReader.Manifest()
	if err != nil {
		return false, fmt.Errorf("tdfReader.Manifest failed: %w", err)
	}

	// Convert the embedded data to a string
	manifestSchemaString := string(manifestSchema)
	loader := gojsonschema.NewStringLoader(manifestSchemaString)
	manifestStringLoader := gojsonschema.NewStringLoader(manifest)
	result, err := gojsonschema.Validate(loader, manifestStringLoader)
	if err != nil {
		return false, errors.New("could not validate manifest.json")
	}

	if !result.Valid() {
		return false, errors.New("manifest was not valid")
	}

	return true, nil
}

// IsValidNanoTdf detects whether, or not the reader is a valid Nano TDF.
// Reader is reset after the check.
func IsValidNanoTdf(reader io.ReadSeeker) (bool, error) {
	_, _, err := NewNanoTDFHeaderFromReader(reader)
	_, _ = reader.Seek(0, io.SeekStart) // Ignore the error as we're just checking if it's a valid nano TDF
	return err == nil, err
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
		return nil, errors.Join(errors.New("unable to retrieve config information, and none was provided"), err)
	}
	// Get token endpoint
	configuration := response.GetConfiguration()

	return configuration.AsMap(), nil
}

// TODO: This should be moved to a separate package. We do discovery in ../service/internal/auth/discovery.go
func getTokenEndpoint(c config) (string, error) {
	issuerURL, ok := c.PlatformConfiguration["platform_issuer"].(string)

	if !ok {
		return "", errors.New("platform_issuer is not set, or is not a string")
	}

	oidcConfigURL := issuerURL + "/.well-known/openid-configuration"

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
		s.kasKeyCache.store(KASInfo{
			URL:       url,
			PublicKey: key.GetPem(),
			KID:       key.GetKid(),
			Algorithm: algProto2String(key.GetAlg()),
		})
	}
	return nil
}
