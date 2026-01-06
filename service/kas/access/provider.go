package access

import (
	"context"
	"fmt"
	"log/slog"
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
	SDK          *otdf.SDK
	AttributeSvc *url.URL
	KeyDelegator *trust.DelegatingKeyService
	// Deprecated: Use SecurityProvider instead
	CryptoProvider *security.StandardCrypto // Kept for backward compatibility
	Logger         *logger.Logger
	Config         *config.ServiceConfig
	KASConfig
	securityConfig *config.SecurityConfig
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
	ECTDFEnabled     bool    `mapstructure:"ec_tdf_enabled" json:"ec_tdf_enabled"`
	Preview          Preview `mapstructure:"preview" json:"preview"`
	RegisteredKASURI string  `mapstructure:"registered_kas_uri" json:"registered_kas_uri"`
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

// ApplyConfig stores the latest KAS configuration, tracks the associated security
// overrides, and emits a warning when the configured clock skew exceeds the default.
func (p *Provider) ApplyConfig(cfg KASConfig, securityCfg *config.SecurityConfig) {
	p.KASConfig = cfg
	p.securityConfig = securityCfg

	if p.Logger != nil {
		if skew := p.acceptableSkew(); skew > config.DefaultUnsafeClockSkew {
			p.Logger.Warn("configured SRT acceptable skew exceeds default",
				slog.Duration("configured_skew", skew),
				slog.Duration("default_skew", config.DefaultUnsafeClockSkew),
			)
		}
	}
}

// SecurityConfig exposes the most recent security configuration captured via ApplyConfig.
func (p *Provider) SecurityConfig() *config.SecurityConfig {
	return p.securityConfig
}

// acceptableSkew returns the tolerated clock skew for SRT validation, falling back to the
// global unsafe default when no override is present.
func (p *Provider) acceptableSkew() time.Duration {
	if p.securityConfig == nil {
		return config.DefaultUnsafeClockSkew
	}
	return p.securityConfig.ClockSkew()
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

func (kasCfg KASConfig) String() string {
	rootKeySummary := ""
	if kasCfg.RootKey != "" {
		rootKeySummary = fmt.Sprintf("[REDACTED len=%d]", len(kasCfg.RootKey))
	}

	return fmt.Sprintf(
		"KASConfig{Keyring:%v, ECCertID:%q, RSACertID:%q, RootKey:%s, KeyCacheExpiration:%s, ECTDFEnabled:%t, Preview:%+v, RegisteredKASURI:%q}",
		kasCfg.Keyring,
		kasCfg.ECCertID,
		kasCfg.RSACertID,
		rootKeySummary,
		kasCfg.KeyCacheExpiration,
		kasCfg.ECTDFEnabled,
		kasCfg.Preview,
		kasCfg.RegisteredKASURI,
	)
}

func (kasCfg KASConfig) LogValue() slog.Value {
	rootKeyVal := ""
	if kasCfg.RootKey != "" {
		rootKeyVal = fmt.Sprintf("[REDACTED len=%d]", len(kasCfg.RootKey))
	}

	return slog.GroupValue(
		slog.Any("keyring", kasCfg.Keyring),
		slog.String("eccertid", kasCfg.ECCertID),
		slog.String("rsacertid", kasCfg.RSACertID),
		slog.String("root_key", rootKeyVal),
		slog.Duration("key_cache_expiration", kasCfg.KeyCacheExpiration),
		slog.Bool("ec_tdf_enabled", kasCfg.ECTDFEnabled),
		slog.Any("preview", kasCfg.Preview),
		slog.String("registered_kas_uri", kasCfg.RegisteredKASURI),
	)
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
