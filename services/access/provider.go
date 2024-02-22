package access

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	apb "github.com/opentdf/platform/protocol/go/access"
	"github.com/opentdf/platform/services/access/internal/p11"
)

const (
	ErrHSM    = Error("hsm unexpected")
	ErrConfig = Error("invalid port")
)

type Provider struct {
	apb.AccessServiceServer
	URI           url.URL `json:"uri"`
	PrivateKey    p11.Pkcs11PrivateKeyRSA
	PublicKeyRSA  rsa.PublicKey `json:"publicKey"`
	PrivateKeyEC  p11.Pkcs11PrivateKeyEC
	PublicKeyEC   ecdsa.PublicKey
	Certificate   x509.Certificate `json:"certificate"`
	CertificateEC x509.Certificate `json:"certificateEc"`
	AttributeSvc  *apb.NewAttributesServiceClient
	Session       p11.Pkcs11Session
	OIDCVerifier  *oidc.IDTokenVerifier
}
