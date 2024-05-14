package access

import (
	"context"
	"log/slog"
	"net/url"

	kaspb "github.com/opentdf/platform/protocol/go/kas"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/internal/security"
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
}

func (p *Provider) IsReady(ctx context.Context) error {
	// TODO: Not sure what we want to check here? perhaps check if HSM is available and ready
	slog.DebugContext(ctx, "checking readiness of kas service")
	return nil
}
