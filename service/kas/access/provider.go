package access

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"github.com/opentdf/platform/lib/ocrypto"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/kas/recrypt"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel/trace"
)

const (
	ErrConfig = Error("invalid config")
)

type Provider struct {
	kaspb.AccessServiceServer
	URI          url.URL `json:"uri"`
	SDK          *otdf.SDK
	AttributeSvc *url.URL
	recrypt.CryptoProvider
	Logger *logger.Logger
	Config *serviceregistry.ServiceConfig
	KASConfig
	trace.Tracer
}

type KASConfig struct {
	// Which keys are currently the default.
	Keyring []CurrentKeyFor `mapstructure:"keyring" json:"keyring"`
}

func (p *Provider) LoadStandardCryptoProvider() (*recrypt.Standard, error) {
	var opts []recrypt.StandardOption
	for _, key := range p.Keyring {
		privatePemData, err := os.ReadFile(key.Private)
		if err != nil {
			return nil, fmt.Errorf("failed to rsa private key file: %w", err)
		}

		// FIXME will this work for EC keys? It seems to be rsa only.
		asymDecryption, err := ocrypto.NewAsymDecryption(string(privatePemData))
		if err != nil {
			return nil, fmt.Errorf("ocrypto.NewAsymDecryption failed: %w", err)
		}

		publicPemData, err := os.ReadFile(key.Certificate)
		if err != nil {
			return nil, fmt.Errorf("failed to rsa public key file: %w", err)
		}
		opts = append(opts, recrypt.WithKey(key.KID, key.Algorithm, asymDecryption.PrivateKey, publicPemData, true, false))
	}
	c, err := recrypt.NewStandardWithOptions(opts...)
	if err != nil {
		return nil, fmt.Errorf("recrypt.NewStandardWithOptions failed: %w", err)
	}
	p.CryptoProvider = c
	return c, nil
}

// Details about a key.
type CurrentKeyFor struct {
	// Valid algorithm. May be able to be derived from Private but it is better to just say it.
	recrypt.Algorithm `mapstructure:"alg"`
	// Key identifier. Should be short
	KID recrypt.KeyIdentifier `mapstructure:"kid"`
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
