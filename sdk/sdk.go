package sdk

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"

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
	ErrGrpcDialFailed = Error("failed to dial grpc endpoint")
	ErrShutdownFailed = Error("failed to shutdown sdk")
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
	EntityResoution         entityresolution.EntityResolutionServiceClient
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

	accessTokenSource, err := buildIDPTokenSource(cfg)
	if err != nil {
		return nil, err
	}
	if accessTokenSource != nil {
		interceptor := auth.NewTokenAddingInterceptor(accessTokenSource, cfg.tlsConfig)
		dialOptions = append(dialOptions, grpc.WithUnaryInterceptor(interceptor.AddCredentials))
	}

	var (
		defaultConn          *grpc.ClientConn
		policyConn           *grpc.ClientConn
		authorizationConn    *grpc.ClientConn
		entityresolutionConn *grpc.ClientConn
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

	if cfg.entityresolutionConn != nil {
		entityresolutionConn = cfg.entityresolutionConn
	} else {
		entityresolutionConn = defaultConn
	}

	return &SDK{
		conn:                    defaultConn,
		dialOptions:             dialOptions,
		tokenSource:             accessTokenSource,
		Attributes:              attributes.NewAttributesServiceClient(policyConn),
		Namespaces:              namespaces.NewNamespaceServiceClient(policyConn),
		ResourceMapping:         resourcemapping.NewResourceMappingServiceClient(policyConn),
		SubjectMapping:          subjectmapping.NewSubjectMappingServiceClient(policyConn),
		KeyAccessServerRegistry: kasregistry.NewKeyAccessServerRegistryServiceClient(policyConn),
		Authorization:           authorization.NewAuthorizationServiceClient(authorizationConn),
		EntityResoution:         entityresolution.NewEntityResolutionServiceClient(entityresolutionConn),
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
