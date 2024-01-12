package sdk

import (
	acrev1 "github.com/opentdf/opentdf-v2-poc/sdk/acre/v1"
	acsev1 "github.com/opentdf/opentdf-v2-poc/sdk/acse/v1"
	attributesv1 "github.com/opentdf/opentdf-v2-poc/sdk/attributes/v1"
	keyaccessgrantsv1 "github.com/opentdf/opentdf-v2-poc/sdk/key_access_grants/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var Conn *grpc.ClientConn

type Clients struct {
	ResourceEncodings acrev1.ResourcEncodingServiceClient
	SubjectEncodings  acsev1.SubjectEncodingServiceClient
	Attributes        attributesv1.AttributesServiceClient
	KeyAccessGrants   keyaccessgrantsv1.KeyAccessGrantsServiceClient
}

type ErrMissingHost struct{}

func (e ErrMissingHost) Error() string {
	return "missing host"
}

func NewClient(host string) (Clients, error) {
	if host == "" {
		return Clients{}, &ErrMissingHost{}
	}

	Conn, err := grpc.Dial(host, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return Clients{}, err
	}

	return Clients{
		ResourceEncodings: acrev1.NewResourcEncodingServiceClient(Conn),
		SubjectEncodings:  acsev1.NewSubjectEncodingServiceClient(Conn),
		Attributes:        attributesv1.NewAttributesServiceClient(Conn),
		KeyAccessGrants:   keyaccessgrantsv1.NewKeyAccessGrantsServiceClient(Conn),
	}, nil
}
