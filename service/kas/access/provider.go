package access

import (
	"net/url"

	kaspb "github.com/arkavo-org/opentdf-platform/protocol/go/kas"
	otdf "github.com/arkavo-org/opentdf-platform/sdk"
	"github.com/arkavo-org/opentdf-platform/service/internal/security"
	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	ErrHSM    = Error("hsm unexpected")
	ErrConfig = Error("invalid port")
)

type Provider struct {
	kaspb.AccessServiceServer
	URI            url.URL `json:"uri"`
	SDK            *otdf.SDK
	AttributeSvc   *url.URL
	CryptoProvider security.CryptoProvider
	OIDCVerifier   *oidc.IDTokenVerifier
}
