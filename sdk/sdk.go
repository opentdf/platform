package sdk

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/opentdf/platform/protocol/go/wellknownconfiguration"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/sdk/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	ErrGrpcDialFailed       = Error("failed to dial grpc endpoint")
	ErrShutdownFailed       = Error("failed to shutdown sdk")
	ErrPlatformConfigFailed = Error("failed to retrieve platform configuration")
)

type Error string

func (c Error) Error() string {
	return string(c)
}

type SDK struct {
	conn                    *grpc.ClientConn
	dialOptions             []grpc.DialOption
	kasKey                  ocrypto.RsaKeyPair
	tokenSource             auth.AccessTokenSource
	Namespaces              namespaces.NamespaceServiceClient
	Attributes              attributes.AttributesServiceClient
	ResourceMapping         resourcemapping.ResourceMappingServiceClient
	SubjectMapping          subjectmapping.SubjectMappingServiceClient
	KeyAccessServerRegistry kasregistry.KeyAccessServerRegistryServiceClient
	Authorization           authorization.AuthorizationServiceClient
	platformConfiguration   PlatformConfiguration
	wellknownConfiguration  wellknownconfiguration.WellKnownServiceClient
	EntityResoution         entityresolution.EntityResolutionServiceClient
}

func New(platformEndpoint string, opts ...Option) (*SDK, error) {
	var (
		defaultConn          *grpc.ClientConn // Connection to the platform if no other connection is provided
		policyConn           *grpc.ClientConn
		authorizationConn    *grpc.ClientConn
		wellknownConn        *grpc.ClientConn
		entityresolutionConn *grpc.ClientConn
		err                  error
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

	// If KAS key is not provided, generate a new one
	if cfg.kasKey == nil {
		key, err := ocrypto.NewRSAKeyPair(tdf3KeySize)
		if err != nil {
			return nil, err
		}
		cfg.kasKey = &key
	}

	// once we change KAS to use standard DPoP we can put this all in the `build()` method
	dialOptions := append([]grpc.DialOption{}, cfg.build()...)
	// Add extra grpc dial options if provided. This is useful during tests.
	if len(cfg.extraDialOptions) > 0 {
		dialOptions = append(dialOptions, cfg.extraDialOptions...)
	}

	// If platformConfiguration is not provided, fetch it from the platform
	if cfg.platformConfiguration == nil && platformEndpoint != "" { //nolint:nestif // Most of checks are for errors
		// We need an initial connection to the platform to get the platform configuration
		initialConn, err := grpc.Dial(platformEndpoint, dialOptions...)
		if err != nil {
			return nil, errors.Join(ErrGrpcDialFailed, err)
		}
		pcfg, err := getPlatformConfiguration(initialConn)
		if err != nil {
			return nil, errors.Join(ErrPlatformConfigFailed, err)
		}
		cfg.platformConfiguration = pcfg
		if cfg.tokenEndpoint == "" {
			cfg.tokenEndpoint, err = getTokenEndpoint(*cfg)
			if err != nil {
				return nil, err
			}
		}
	}

	accessTokenSource, err := buildIDPTokenSource(cfg)
	if err != nil {
		return nil, err
	}
	if accessTokenSource != nil {
		interceptor := auth.NewTokenAddingInterceptor(accessTokenSource, cfg.tlsConfig)
		dialOptions = append(dialOptions, grpc.WithUnaryInterceptor(interceptor.AddCredentials))
	}

	if platformEndpoint != "" {
		var err error
		defaultConn, err = grpc.Dial(platformEndpoint, dialOptions...)
		if err != nil {
			return nil, errors.Join(ErrGrpcDialFailed, err)
		}
	}

	if cfg.policyConn != nil {
		policyConn = cfg.policyConn
	} else {
		policyConn = defaultConn
	}

	if cfg.authorizationConn != nil {
		authorizationConn = cfg.authorizationConn
	} else {
		authorizationConn = defaultConn
	}

	if cfg.wellknownConn != nil {
		wellknownConn = cfg.wellknownConn
	} else {
		wellknownConn = defaultConn
	}

	if cfg.entityresolutionConn != nil {
		entityresolutionConn = cfg.entityresolutionConn
	} else {
		entityresolutionConn = defaultConn
	}

	return &SDK{
		conn:                    defaultConn,
		dialOptions:             dialOptions,
		tokenSource:             accessTokenSource,
		platformConfiguration:   cfg.platformConfiguration,
		kasKey:                  *cfg.kasKey,
		Attributes:              attributes.NewAttributesServiceClient(policyConn),
		Namespaces:              namespaces.NewNamespaceServiceClient(policyConn),
		ResourceMapping:         resourcemapping.NewResourceMappingServiceClient(policyConn),
		SubjectMapping:          subjectmapping.NewSubjectMappingServiceClient(policyConn),
		KeyAccessServerRegistry: kasregistry.NewKeyAccessServerRegistryServiceClient(policyConn),
		Authorization:           authorization.NewAuthorizationServiceClient(authorizationConn),
		EntityResoution:         entityresolution.NewEntityResolutionServiceClient(entityresolutionConn),
		wellknownConfiguration:  wellknownconfiguration.NewWellKnownServiceClient(wellknownConn),
	}, nil
}

func buildIDPTokenSource(c *config) (auth.AccessTokenSource, error) {
	if (c.clientCredentials == nil) != (c.tokenEndpoint == "") {
		return nil, errors.New("either both or neither of client credentials and token endpoint must be specified")
	}

	// at this point we have either both client credentials and a token endpoint or none of the above. if we don't have
	// any just return a KAS client that can only get public keys
	if c.clientCredentials == nil {
		slog.Info("no client credentials provided. GRPC requests to KAS and services will not be authenticated.")
		return nil, nil // not having credentials is not an error
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
		return errors.Join(ErrShutdownFailed, err)
	}
	return nil
}

// Conn returns the underlying grpc.ClientConn.
func (s SDK) Conn() *grpc.ClientConn {
	return s.conn
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
	issuerURL, ok := c.platformConfiguration["platform_issuer"].(string)

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
