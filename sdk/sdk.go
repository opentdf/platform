package sdk

import (
	"errors"

	"github.com/opentdf/opentdf-v2-poc/services/acre"
	"github.com/opentdf/opentdf-v2-poc/services/acse"
	"github.com/opentdf/opentdf-v2-poc/services/attributes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	ErrGrpcDialFailed = Error("failed to dial grpc endpoint")
	ErrShutdownFailed = Error("failed to shutdown sdk")
)

type Error string

func (c Error) Error() string {
	return string(c)
}

type Options struct {
	Insecure         bool `default:"false"`
	IDPEndpoint      string
	PlatformEndpoint string
	ClientID         string
	ClientSecret     string
	Token            string
}

type SDK struct {
	conn             *grpc.ClientConn
	Attributes       attributes.AttributesServiceClient
	ResourceEncoding acre.ResourcEncodingServiceClient
	SubjectEncoding  acse.SubjectEncodingServiceClient
}

func NewSDK(opts Options) (*SDK, error) {
	var dialOpts []grpc.DialOption

	if opts.Insecure {
		// Disable TLS
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// Enable TLS
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")))
	}

	if opts.Token != "" && opts.ClientID != "" && opts.ClientSecret != "" {
		return nil, errors.New("can't set both token and client credentials")
	}

<<<<<<< HEAD
	if opts.Token != "" {
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(credentials.PerRPCCredentials)
	}
=======
>>>>>>> 6e918fa (save)
	conn, err := grpc.Dial(opts.PlatformEndpoint, dialOpts...)
	if err != nil {
		return nil, errors.Join(ErrGrpcDialFailed, err)
	}

	return newSDK(conn), nil
}

func newSDK(conn *grpc.ClientConn) *SDK {
	return &SDK{
		Attributes:       attributes.NewAttributesServiceClient(conn),
		ResourceEncoding: acre.NewResourcEncodingServiceClient(conn),
		SubjectEncoding:  acse.NewSubjectEncodingServiceClient(conn),
	}
}

// Shutdown closes the underlying grpc.ClientConn.
func (s SDK) Shutdown() error {
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
func (s SDK) ExchangeToken(token string) (string, error) {
	return "", nil
}