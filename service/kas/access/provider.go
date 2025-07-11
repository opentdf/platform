package access

import (
	"context"
	"net/url"
	"time"

	kaspb "github.com/opentdf/platform/protocol/go/kas"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/trust"
	"go.opentelemetry.io/otel/trace"
)

const (
	ErrHSM    = Error("hsm unexpected")
	ErrConfig = Error("invalid config")
)

type Provider struct {
	kaspb.AccessServiceServer
	URI          url.URL `json:"uri"`
	SDK          *otdf.SDK
	AttributeSvc *url.URL
	KeyDelegator *trust.DelegatingKeyService
	// Deprecated: Use SecurityProvider instead
	CryptoProvider *security.StandardCrypto // Kept for backward compatibility
	Logger         *logger.Logger
	Config         *config.ServiceConfig
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

	RootKey string `mapstructure:"root_key" json:"root_key"`

	KeyCacheExpiration time.Duration `mapstructure:"key_cache_expiration" json:"key_cache_expiration"`

	// Deprecated
	// Enables experimental EC rewrap support in TDFs
	// Enabling is required to parse KAOs with the `ec-wrapped` type,
	// and (currently) also enables responding with ECIES encrypted responses.
	ECTDFEnabled bool    `mapstructure:"ec_tdf_enabled" json:"ec_tdf_enabled"`
	Preview      Preview `mapstructure:"preview" json:"preview"`
}

type Preview struct {
	ECTDFEnabled  bool `mapstructure:"ec_tdf_enabled" json:"ec_tdf_enabled"`
	KeyManagement bool `mapstructure:"key_management" json:"key_management"`
}

// Specifies the preferred/default key for a given algorithm type.
type CurrentKeyFor struct {
	Algorithm string `mapstructure:"alg" json:"alg"`
	KID       string `mapstructure:"kid" json:"kid"`
	// Indicates that the key should not be serves by default,
	// but instead is allowed for legacy reasons on decrypt (rewrap) only
	Legacy bool `mapstructure:"legacy" json:"legacy"`
}

func (p *Provider) IsReady(ctx context.Context) error {
	// TODO: Not sure what we want to check here?
	p.Logger.TraceContext(ctx, "checking readiness of kas service")
	return nil
}

func (kasCfg *KASConfig) UpgradeMapToKeyring(c *security.StandardCrypto) {
	switch {
	case kasCfg.ECCertID != "" && len(kasCfg.Keyring) > 0:
		panic("invalid kas cfg: please specify keyring or eccertid, not both")
	case len(kasCfg.Keyring) == 0:
		deprecatedOrDefault := func(kid, alg string) {
			if kid == "" {
				kid = c.FindKID(alg)
			}
			if kid == "" {
				// no known key for this algorithm type
				return
			}
			kasCfg.Keyring = append(kasCfg.Keyring, CurrentKeyFor{
				Algorithm: alg,
				KID:       kid,
			})
			kasCfg.Keyring = append(kasCfg.Keyring, CurrentKeyFor{
				Algorithm: alg,
				KID:       kid,
				Legacy:    true,
			})
		}
		deprecatedOrDefault(kasCfg.ECCertID, security.AlgorithmECP256R1)
		deprecatedOrDefault(kasCfg.RSACertID, security.AlgorithmRSA2048)
	default:
		kasCfg.Keyring = append(kasCfg.Keyring, inferLegacyKeys(kasCfg.Keyring)...)
	}
}

// If there exists *any* legacy keys, returns empty list.
// Otherwise, create a copy with legacy=true for all values
func inferLegacyKeys(keys []CurrentKeyFor) []CurrentKeyFor {
	for _, k := range keys {
		if k.Legacy {
			return nil
		}
	}
	l := make([]CurrentKeyFor, len(keys))
	for i, k := range keys {
		l[i] = k
		l[i].Legacy = true
	}
	return l
}
