package sdk

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"github.com/opentdf/platform/sdk/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"log/slog"
	"net/http"
	"time"
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
	tokenSource             auth.AccessTokenSource
	Namespaces              namespaces.NamespaceServiceClient
	Attributes              attributes.AttributesServiceClient
	ResourceMapping         resourcemapping.ResourceMappingServiceClient
	SubjectMapping          subjectmapping.SubjectMappingServiceClient
	KeyAccessServerRegistry kasregistry.KeyAccessServerRegistryServiceClient
	Authorization           authorization.AuthorizationServiceClient
	platformConfiguration   PlatformConfigurationType
	WellknownConfiguration  wellknownconfiguration.WellKnownServiceClient
}

func New(platformEndpoint string, opts ...Option) (*SDK, error) {
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

	// once we change KAS to use standard DPoP we can put this all in the `build()` method
	dialOptions := append([]grpc.DialOption{}, cfg.build()...)
	// Add extra grpc dial options if provided. This is useful during tests.
	if len(cfg.extraDialOptions) > 0 {
		dialOptions = append(dialOptions, cfg.extraDialOptions...)
	}

	var (
		defaultConn           *grpc.ClientConn
		policyConn            *grpc.ClientConn
		authorizationConn     *grpc.ClientConn
		wellknownConn         *grpc.ClientConn
		platformConfiguration PlatformConfigurationType
		accessTokenSource     auth.AccessTokenSource
	)
	slog.Info("On top of platformEndpoint")
	if platformEndpoint != "" {
		slog.Info("Inside platformEndpoint")
		slog.Info(platformEndpoint)
		// Setup all the necessary GRPC clients
		var err error
		defaultConn, err = grpc.Dial(platformEndpoint, dialOptions...)
		if err != nil {
			return nil, errors.Join(ErrGrpcDialFailed, err)
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
			fmt.Printf("wellknownConn : %+v\n", wellknownConn)

		} else {
			wellknownConn = defaultConn
		}

		// Next, retrieve, or use the provided platformConfiguration.
		if cfg.platformConfiguration == nil {

			configMap, err := getPlatformConfiguration(wellknownConn)

			fmt.Printf("Config@!!!@#@$@$ : %+v\n", configMap)

			if err != nil {
				return nil, errors.Join(ErrPlatformConfigFailed, err)
			}
			platformConfiguration = configMap
		}

		// Finally, bootstrap the SDK with the necessary information for it to authenticate.
		tokenEndpoint, err := fetchTokenEndpoint(platformConfiguration)

		cfg.tokenEndpoint = tokenEndpoint

		if err != nil {
			return nil, errors.Join(ErrPlatformConfigFailed, err)
		}

		accessTokenSource, err := buildIDPTokenSource(cfg)
		fmt.Printf("ATS : %+v\n", accessTokenSource)

		if err != nil {
			return nil, err
		}

		if accessTokenSource != nil {
			interceptor := auth.NewTokenAddingInterceptor(accessTokenSource, cfg.tlsConfig)
			dialOptions = append(dialOptions, grpc.WithUnaryInterceptor(interceptor.AddCredentials))
		}
	} else {
		platformConfiguration = cfg.platformConfiguration
	}

	return &SDK{
		conn:                    defaultConn,
		dialOptions:             dialOptions,
		tokenSource:             accessTokenSource,
		platformConfiguration:   platformConfiguration,
		Attributes:              attributes.NewAttributesServiceClient(policyConn),
		Namespaces:              namespaces.NewNamespaceServiceClient(policyConn),
		ResourceMapping:         resourcemapping.NewResourceMappingServiceClient(policyConn),
		SubjectMapping:          subjectmapping.NewSubjectMappingServiceClient(policyConn),
		KeyAccessServerRegistry: kasregistry.NewKeyAccessServerRegistryServiceClient(policyConn),
		Authorization:           authorization.NewAuthorizationServiceClient(authorizationConn),
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

	var ts auth.AccessTokenSource
	var err error

	switch {
	case c.certExchange != nil:
		ts, err = NewCertExchangeTokenSource(*c.certExchange, *c.clientCredentials, c.tokenEndpoint)
	case c.tokenExchange != nil:
		ts, err = NewIDPTokenExchangeTokenSource(
			*c.tokenExchange,
			*c.clientCredentials,
			c.tokenEndpoint,
			c.scopes,
		)
	default:
		ts, err = NewIDPAccessTokenSource(
			*c.clientCredentials,
			c.tokenEndpoint,
			c.scopes,
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

func getPlatformConfiguration(conn *grpc.ClientConn) (PlatformConfigurationType, error) {
	req := wellknownconfiguration.GetWellKnownConfigurationRequest{}
	time.Sleep(time.Second * 90)
	wellKnownConfig := wellknownconfiguration.NewWellKnownServiceClient(conn)

	response, err := wellKnownConfig.GetWellKnownConfiguration(context.Background(), &req)
	time.Sleep(time.Second * 90)
	fmt.Printf("err : %+v\n", err.Error())
	fmt.Printf("Respnose : %+v\n", response)
	if err != nil {
		return nil, errors.New("Unable to retrieve config information, and none was provided")
	}
	// Get token endpoint

	configuration := response.GetConfiguration()
	fmt.Printf("Full Config : %+v\n", configuration)
	return configuration.AsMap(), nil
}

type OIDCConfig struct {
	TokenEndpoint string `json:"token_endpoint"`
}

func fetchTokenEndpoint(c PlatformConfigurationType) (string, error) {
	issuerURL, ok := c["platform_issuer"].(string)

	if !ok {
		return "", errors.New("platform_issuer is not set, or is not a string")
	}
	wellKnownConfigURL := issuerURL + "/.well-known/openid-configuration"

	resp, err := http.Get(wellKnownConfigURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var config OIDCConfig
	if err = json.Unmarshal(body, &config); err != nil {
		return "", err
	}

	return config.TokenEndpoint, nil
}
