package sdk

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"log/slog"
	"os"

	"github.com/arkavo-org/opentdf-platform/protocol/go/authorization"
	"github.com/arkavo-org/opentdf-platform/protocol/go/kasregistry"
	"github.com/arkavo-org/opentdf-platform/protocol/go/policy/attributes"
	"github.com/arkavo-org/opentdf-platform/protocol/go/policy/namespaces"
	"github.com/arkavo-org/opentdf-platform/protocol/go/policy/resourcemapping"
	"github.com/arkavo-org/opentdf-platform/protocol/go/policy/subjectmapping"
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
	// Load the client's certificate and private key
	certificate, err := tls.LoadX509KeyPair("../pep.crt", "../pep.key")
	if err != nil {
		log.Fatalf("could not load client key pair: %s", err)
	}
	// Create a certificate pool from the certificate authority
	certPool := x509.NewCertPool()
	ca, err := os.ReadFile("../ca.crt")
	if err != nil {
		log.Fatalf("could not read ca certificate: %s", err)
	}

	// Append the client certificates from the CA
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		log.Fatalf("failed to append client certs")
	}
	tlsConfig := tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      certPool,
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
	// no need for this with PKI
	dialOptions := append([]grpc.DialOption{}, cfg.build()...)
	//accessTokenSource, err := buildIDPTokenSource(cfg)
	//if err != nil {
	//	return nil, err
	//}
	//if accessTokenSource != nil {
	//	interceptor := auth.NewTokenAddingInterceptor(accessTokenSource)
	//	dialOptions = append(dialOptions, grpc.WithUnaryInterceptor(interceptor.AddCredentials))
	//}

	var unwrapper Unwrapper
	//if cfg.authConfig == nil {
	//	unwrapper, err = newKASClient(dialOptions, accessTokenSource)
	//	if err != nil {
	//		return nil, err
	//	}
	//} else {
	unwrapper = cfg.authConfig
	//}

	var (
		defaultConn       *grpc.ClientConn
		policyConn        *grpc.ClientConn
		authorizationConn *grpc.ClientConn
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

	return &SDK{
		conn:                    defaultConn,
		unwrapper:               unwrapper,
		Attributes:              attributes.NewAttributesServiceClient(policyConn),
		Namespaces:              namespaces.NewNamespaceServiceClient(policyConn),
		ResourceMapping:         resourcemapping.NewResourceMappingServiceClient(policyConn),
		SubjectMapping:          subjectmapping.NewSubjectMappingServiceClient(policyConn),
		KeyAccessServerRegistry: kasregistry.NewKeyAccessServerRegistryServiceClient(policyConn),
		Authorization:           authorization.NewAuthorizationServiceClient(authorizationConn),
	}, nil
}

func buildIDPTokenSource(c *config) (*IDPAccessTokenSource, error) {
	if (c.clientCredentials.ClientID == "") != (c.clientCredentials.ClientAuth == nil) {
		return nil,
			errors.New("if specifying client credentials must specify both client id and authentication secret")
	}
	if (c.clientCredentials.ClientID == "") != (c.tokenEndpoint == "") {
		return nil, errors.New("either both or neither of client credentials and token endpoint must be specified")
	}

	// at this point we have either both client credentials and a token endpoint or none of the above. if we don't have
	// any just return a KAS client that can only get public keys
	if c.clientCredentials.ClientID == "" {
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
func (s SDK) TokenExchange(_ string) (string, error) {
	return "", nil
}
