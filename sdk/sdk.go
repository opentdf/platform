package sdk

import (
	"errors"

	"github.com/opentdf/opentdf-v2-poc/sdk/acre"
	"github.com/opentdf/opentdf-v2-poc/sdk/acse"
	"github.com/opentdf/opentdf-v2-poc/sdk/attributes"
	"github.com/opentdf/opentdf-v2-poc/sdk/keyaccessgrants"
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
	conn             *grpc.ClientConn
	Attributes       attributes.AttributesServiceClient
	ResourceEncoding acre.ResourcEncodingServiceClient
	SubjectEncoding  acse.SubjectEncodingServiceClient
	KeyAccessGrants  keyaccessgrants.KeyAccessGrantsServiceClient
}

func New(platformEndpoint string, opts ...Option) (*SDK, error) {
	// Set default options
	cfg := &config{
		tls: grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")),
	}

	// Apply options
	for _, opt := range opts {
		opt(cfg)
	}

	conn, err := grpc.Dial(platformEndpoint, cfg.build()...)
	if err != nil {
		return nil, errors.Join(ErrGrpcDialFailed, err)
	}

	return newSDK(conn), nil
}

func newSDK(conn *grpc.ClientConn) *SDK {
	return &SDK{
		conn:             conn,
		Attributes:       attributes.NewAttributesServiceClient(conn),
		ResourceEncoding: acre.NewResourcEncodingServiceClient(conn),
		SubjectEncoding:  acse.NewSubjectEncodingServiceClient(conn),
		KeyAccessGrants:  keyaccessgrants.NewKeyAccessGrantsServiceClient(conn),
	}
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
