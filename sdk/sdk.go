package sdk

import (
	"errors"

	"github.com/opentdf/platform/sdk/attributes"
	"github.com/opentdf/platform/sdk/authorization"
	"github.com/opentdf/platform/sdk/kasregistry"
	"github.com/opentdf/platform/sdk/namespaces"
	"github.com/opentdf/platform/sdk/resourcemapping"
	"github.com/opentdf/platform/sdk/subjectmapping"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	ErrGrpcDialFailed = Error("failed to dial grpc endpoint")
	ErrNotImplemented = Error("function not implemented")
	ErrShutdownFailed = Error("failed to shutdown sdk")
)

type Error string

func (c Error) Error() string {
	return string(c)
}

type SDK struct {
	conn                    *grpc.ClientConn
	Namespaces              namespaces.NamespaceServiceClient
	Attributes              attributes.AttributesServiceClient
	ResourceMapping         resourcemapping.ResourceMappingServiceClient
	SubjectMapping          subjectmapping.SubjectMappingServiceClient
	KeyAccessServerRegistry kasregistry.KeyAccessServerRegistryServiceClient
	Authorization           authorization.AuthorizationServiceClient
}

// New returns a new SDK to connect to the platform Endpoint as configured
// by the opts Options
func New(platformEndpoint string, opts ...Option) (*SDK, error) {
	cfg := &options{
		dialOptions: []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, ""))},
	}
	for _, opt := range opts {
		opt(cfg)
	}

	conn, err := grpc.Dial(platformEndpoint, cfg.dialOptions...)
	if err != nil {
		return nil, errors.Join(ErrGrpcDialFailed, err)
	}

	return &SDK{
		conn:                    conn,
		Attributes:              attributes.NewAttributesServiceClient(conn),
		Namespaces:              namespaces.NewNamespaceServiceClient(conn),
		ResourceMapping:         resourcemapping.NewResourceMappingServiceClient(conn),
		SubjectMapping:          subjectmapping.NewSubjectMappingServiceClient(conn),
		KeyAccessServerRegistry: kasregistry.NewKeyAccessServerRegistryServiceClient(conn),
		Authorization:           authorization.NewAuthorizationServiceClient(conn),
	}, nil
}

// Close closes the underlying grpc.ClientConn.
func (s *SDK) Close() error {
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
//
// WARNING: Not yet implemented
func (s SDK) TokenExchange(token string) (string, error) {
	// TODO Store the token type of dialOptions during initialization
	return "", ErrNotImplemented
}
