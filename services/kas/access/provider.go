package access

import (
	"net/url"

	"github.com/opentdf/platform/internal/security"

	"github.com/coreos/go-oidc/v3/oidc"
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
	Session      security.HSMSession
	OIDCVerifier *oidc.IDTokenVerifier
}
