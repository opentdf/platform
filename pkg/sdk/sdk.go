package sdk

import (
	"errors"

	acrev1 "github.com/opentdf/opentdf-v2-poc/gen/acre/v1"
	acsev1 "github.com/opentdf/opentdf-v2-poc/gen/acse/v1"
	attributesv1 "github.com/opentdf/opentdf-v2-poc/gen/attributes/v1"
	"google.golang.org/grpc"
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

type SDK struct {
	conn             *grpc.ClientConn
	Attributes       attributesv1.AttributesServiceClient
	ResourceEncoding acrev1.ResourcEncodingServiceClient
	SubjectEncoding  acsev1.SubjectEncodingServiceClient
}

func New(opts SDKOptions) (*SDK, error) {
	var dialOpts []grpc.DialOption

	if opts.Insecure {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.Dial(opts.DefaultEndpoint, dialOpts...)
	if err != nil {
		return nil, errors.Join(ErrGrpcDialFailed, err)
	}

	return &SDK{
		Attributes:       attributesv1.NewAttributesServiceClient(conn),
		ResourceEncoding: acrev1.NewResourcEncodingServiceClient(conn),
		SubjectEncoding:  acsev1.NewSubjectEncodingServiceClient(conn),
	}, nil
}

func (s SDK) Shutdown() error {
	if err := s.conn.Close(); err != nil {
		return errors.Join(ErrShutdownFailed, err)
	}
	return nil
}
