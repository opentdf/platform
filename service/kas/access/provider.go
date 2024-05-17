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
	ErrConfig = Error("invalid config")
)

type Provider struct {
	kaspb.AccessServiceServer
	URI            url.URL `json:"uri"`
	SDK            *otdf.SDK
	AttributeSvc   *url.URL
	CryptoProvider security.CryptoProvider
}

// TODO: Not sure what we want to check here?
func (p Provider) IsReady(ctx context.Context) error {
	slog.DebugContext(ctx, "checking readiness of kas service")
	return nil
}
