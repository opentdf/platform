package access

import (
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/opentdf/platform/internal/security/keyprovider"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
)

const (
	ErrHSM    = Error("hsm unexpected")
	ErrConfig = Error("invalid port")
)

type Provider struct {
	kaspb.AccessServiceServer
	URI          url.URL `json:"uri"`
	AttributeSvc *url.URL
	KeyProvider  keyprovider.Provider
	OIDCVerifier *oidc.IDTokenVerifier
}
