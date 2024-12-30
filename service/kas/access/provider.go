package access

import (
	"context"
	"net/url"

	kaspb "github.com/opentdf/platform/protocol/go/kas"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel/trace"
)

const (
	ErrConfig = Error("invalid config")
)

type Provider struct {
	kaspb.AccessServiceServer
	URI            url.URL `json:"uri"`
	SDK            *otdf.SDK
	AttributeSvc   *url.URL
	CryptoProvider security.CryptoProvider
	Logger         *logger.Logger
	Config         *serviceregistry.ServiceConfig
	KASConfig
	trace.Tracer
}

type KASConfig struct {
	// Which keys are currently the default.
	Keyring []CurrentKeyFor `mapstructure:"keyring" json:"keyring"`
	// Deprecated
	ECCertID string `mapstructure:"eccertid" json:"eccertid"`
	// Deprecated
	RSACertID string `mapstructure:"rsacertid" json:"rsacertid"`
}

// Details about a key. 
type CurrentKeyFor struct {
	// Valid algorithm. May be able to be derived from Private but it is better to just say it.
	Algorithm string `mapstructure:"alg"`
	// Key identifier. Should be short
	KID string `mapstructure:"kid"`
	// Implementation specific locator for private key;
	// for 'standard' crypto service this is the path to a PEM file
	Private string `mapstructure:"private"`
	// Optional locator for the corresponding certificate.
	// If not found, only public key (derivable from Private) is available.
	Certificate string `mapstructure:"cert"`
	// TODO: Options listing to support 'active' and 'kidless or legacy' parameters
}

func (p *Provider) IsReady(ctx context.Context) error {
	// TODO: Not sure what we want to check here?
	p.Logger.TraceContext(ctx, "checking readiness of kas service")
	return nil
}
