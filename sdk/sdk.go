package sdk

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
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
	Namespaces              namespaces.NamespaceServiceClient
	Attributes              attributes.AttributesServiceClient
	ResourceMapping         resourcemapping.ResourceMappingServiceClient
	SubjectMapping          subjectmapping.SubjectMappingServiceClient
	KeyAccessServerRegistry kasregistry.KeyAccessServerRegistryServiceClient
	Authorization           authorization.AuthorizationServiceClient
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

	var unwrapper Unwrapper
	if cfg.authConfig == nil {
		uw, err := buildKASClient(cfg)
		if err != nil {
			return nil, err
		}
		unwrapper = &uw
	} else {
		unwrapper = cfg.authConfig
	}

	conn, err := grpc.Dial(platformEndpoint, cfg.build()...)
	if err != nil {
		return nil, errors.Join(ErrGrpcDialFailed, err)
	}

	return &SDK{
		conn:                    conn,
		unwrapper:               unwrapper,
		Attributes:              attributes.NewAttributesServiceClient(conn),
		Namespaces:              namespaces.NewNamespaceServiceClient(conn),
		ResourceMapping:         resourcemapping.NewResourceMappingServiceClient(conn),
		SubjectMapping:          subjectmapping.NewSubjectMappingServiceClient(conn),
		KeyAccessServerRegistry: kasregistry.NewKeyAccessServerRegistryServiceClient(conn),
		Authorization:           authorization.NewAuthorizationServiceClient(conn),
	}, nil
}

func buildKASClient(c *config) (KASClient, error) {
	if (c.clientCredentials.ClientId == "") != (c.clientCredentials.ClientAuth == nil) {
		return KASClient{},
			errors.New("if specifying client credentials must specify both client id and authentication secret")
	}
	if (c.clientCredentials.ClientId == "") != (c.tokenEndpoint == "") {
		return KASClient{}, errors.New("either both or neither of client credentials and token endpoint must be specified")
	}

	// at this point we have either both client credentials and a token endpoint or none of the above
	if c.clientCredentials.ClientId == "" {
		return KASClient{}, nil
	}

	ts, err := NewIDPAccessTokenSource(
		c.clientCredentials,
		c.tokenEndpoint,
		c.scopes,
	)

	if err != nil {
		return KASClient{}, fmt.Errorf("error configuring IDP access: %w", err)
	}

	kasClient := KASClient{
		accessTokenSource: &ts,
		dialOptions:       c.build(),
	}

	return kasClient, nil
}

// Close closes the underlying grpc.ClientConn.
func (s SDK) Close() error {
	if err := s.conn.Close(); err != nil {
		return errors.Join(ErrShutdownFailed, err)
	}
	return nil
}

// Conn returns the underlying grpc.ClientConn.
func (s SDK) Conn() *grpc.ClientConn {
	return s.conn
}

// ExchangeToken exchanges a access token for a new token. https://datatracker.ietf.org/doc/html/rfc8693
func (s SDK) TokenExchange(token string) (string, error) {
	return "", nil
}
