package sdk

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"io/ioutil"
	"log/slog"
	"net/http"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/sdk/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	ErrGrpcDialFailed = Error("failed to dial grpc endpoint")
	ErrShutdownFailed = Error("failed to shutdown sdk")
)

type Error string

func (c Error) Error() string {
	return string(c)
}

type SDK struct {
	conn                    *grpc.ClientConn
	unwrapper               Unwrapper
	platformConfiguration   *wellknownconfiguration.GetWellKnownConfigurationResponse
	Namespaces              namespaces.NamespaceServiceClient
	Attributes              attributes.AttributesServiceClient
	ResourceMapping         resourcemapping.ResourceMappingServiceClient
	SubjectMapping          subjectmapping.SubjectMappingServiceClient
	KeyAccessServerRegistry kasregistry.KeyAccessServerRegistryServiceClient
	Authorization           authorization.AuthorizationServiceClient
	WellknownConfiguration  wellknownconfiguration.WellKnownServiceClient
}

func New(platformEndpoint string, opts ...Option) (*SDK, error) {
	tlsConfig := tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Set default options
	cfg := &config{
		tls: grpc.WithTransportCredentials(credentials.NewTLS(&tlsConfig)),
	}

	// Apply options
	for _, opt := range opts {
		opt(cfg)
	}

	// once we change KAS to use standard DPoP we can put this all in the `build()` method
	dialOptions := append([]grpc.DialOption{}, cfg.build()...)

	var (
		defaultConn           *grpc.ClientConn
		policyConn            *grpc.ClientConn
		authorizationConn     *grpc.ClientConn
		wellknownConn         *grpc.ClientConn
		platformConfiguration *wellknownconfiguration.GetWellKnownConfigurationResponse
	)

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

	if cfg.platformConfiguration == nil && platformEndpoint != "" {
		configResponse, err := setPlatformConfiguration(cfg, wellknownConn)

		platformConfiguration = configResponse
		if err != nil {
			return nil, errors.New("Unable to retrieve platform configuration.")
		}

	} else {
		platformConfiguration = cfg.platformConfiguration
	}

	accessTokenSource, err := buildIDPTokenSource(cfg)

	if err != nil {
		return nil, err
	}

	if accessTokenSource != nil {
		interceptor := auth.NewTokenAddingInterceptor(accessTokenSource)
		dialOptions = append(dialOptions, grpc.WithUnaryInterceptor(interceptor.AddCredentials))
	}

	var unwrapper Unwrapper
	if cfg.authConfig == nil {
		unwrapper, err = newKASClient(dialOptions, accessTokenSource)
		if err != nil {
			return nil, err
		}
	} else {
		unwrapper = cfg.authConfig
	}
	return &SDK{
		conn:                    defaultConn,
		unwrapper:               unwrapper,
		platformConfiguration:   platformConfiguration,
		Attributes:              attributes.NewAttributesServiceClient(policyConn),
		Namespaces:              namespaces.NewNamespaceServiceClient(policyConn),
		ResourceMapping:         resourcemapping.NewResourceMappingServiceClient(policyConn),
		SubjectMapping:          subjectmapping.NewSubjectMappingServiceClient(policyConn),
		KeyAccessServerRegistry: kasregistry.NewKeyAccessServerRegistryServiceClient(policyConn),
		Authorization:           authorization.NewAuthorizationServiceClient(authorizationConn),
		WellknownConfiguration:  wellknownconfiguration.NewWellKnownServiceClient(wellknownConn),
	}, nil
}

func buildIDPTokenSource(c *config) (*IDPAccessTokenSource, error) {
	if (c.clientCredentials.ClientId == "") != (c.clientCredentials.ClientAuth == nil) {
		return nil,
			errors.New("if specifying client credentials must specify both client id and authentication secret")
	}
	if (c.clientCredentials.ClientId == "") != (c.tokenEndpoint == "") {
		return nil, errors.New("either both or neither of client credentials and token endpoint must be specified")
	}

	// at this point we have either both client credentials and a token endpoint or none of the above. if we don't have
	// any just return a KAS client that can only get public keys
	if c.clientCredentials.ClientId == "" {
		slog.Info("no client credentials provided. GRPC requests to KAS and services will not be authenticated.")
		return nil, nil //nolint:nilnil // not having credentials is not an error
	}

	ts, err := NewIDPAccessTokenSource(
		c.clientCredentials,
		c.tokenEndpoint,
		c.scopes,
	)

	return &ts, err
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

// TokenExchange exchanges a access token for a new token. https://datatracker.ietf.org/doc/html/rfc8693
func (s SDK) TokenExchange(token string) (string, error) {
	return "", nil
}

type OIDCConfig struct {
	TokenEndpoint string `json:"token_endpoint"`
}

type ConfigurationResponse struct {
	platform_issuer string
}

func setPlatformConfiguration(c *config, conn *grpc.ClientConn) (*wellknownconfiguration.GetWellKnownConfigurationResponse, error) {
	req := wellknownconfiguration.GetWellKnownConfigurationRequest{}
	wellKnownConfig := wellknownconfiguration.NewWellKnownServiceClient(conn)

	response, err := wellKnownConfig.GetWellKnownConfiguration(context.Background(), &req)
	if err != nil {
		return nil, errors.New("Unable to retrieve config information, and none was provided")
	}
	// Get token endpoint
	configuration := response.GetConfiguration()

	configMap := configuration.AsMap()

	issuerUrl, ok := configMap["platform_issuer"].(string)

	if !ok {
		return nil, errors.New("platform_issuer is not a string")
	}

	tokenEndpoint, err := fetchTokenEndpoint(issuerUrl)

	if err != nil {
		return nil, errors.New("Unable to retrieve token endpoint")
	}

	c.tokenEndpoint = tokenEndpoint

	return response, nil
}

func fetchTokenEndpoint(issuerURL string) (string, error) {
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
