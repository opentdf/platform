package access

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
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
	trace.Tracer
}

type KASConfig struct {
	// Which keys are currently the default.
	Keyring []CurrentKeyFor `mapstructure:"keyring" json:"keyring"`
	// Deprecated
	ECCertID string `mapstructure:"eccertid" json:"eccertid"`
	// Deprecated
	RSACertID string `mapstructure:"rsacertid" json:"rsacertid"`

	RootKey     string `mapstructure:"root_key" json:"root_key"`
	RootKeyFile string `mapstructure:"root_key_file" json:"root_key_file"`

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

// LoadRootKey loads and validates the root key from the configuration.
// It supports loading from RootKey (hex or base64 string) or RootKeyFile (file path).
// If both are present, it logs a warning and uses RootKey, ignoring the file.
func (kasCfg *KASConfig) LoadRootKey(l *logger.Logger) (string, error) {
	// Check if both are present and warn
	if kasCfg.RootKey != "" && kasCfg.RootKeyFile != "" {
		l.Warn("both root_key and root_key_file are configured, ignoring root_key_file",
			slog.String("root_key_file", kasCfg.RootKeyFile))
		return validateAndNormalizeKey(kasCfg.RootKey)
	}

	// Use RootKey if present
	if kasCfg.RootKey != "" {
		return validateAndNormalizeKey(kasCfg.RootKey)
	}

	// Use RootKeyFile if present
	if kasCfg.RootKeyFile != "" {
		keyData, err := os.ReadFile(kasCfg.RootKeyFile)
		if err != nil {
			return "", fmt.Errorf("failed to read root key file %s: %w", kasCfg.RootKeyFile, err)
		}

		// Clean up any whitespace/newlines from file content
		keyStr := strings.TrimSpace(string(keyData))
		return validateAndNormalizeKey(keyStr)
	}

	return "", fmt.Errorf("neither root_key nor root_key_file is configured")
}

// validateAndNormalizeKey validates the key format and converts it to hex encoding.
// It supports both hex and base64 encoded AES-256 keys.
func validateAndNormalizeKey(keyStr string) (string, error) {
	keyStr = strings.TrimSpace(keyStr)

	// Try hex decoding first
	if hexKey, err := hex.DecodeString(keyStr); err == nil {
		// Validate it's exactly 32 bytes (256 bits)
		if len(hexKey) == 32 {
			return keyStr, nil
		}
		return "", fmt.Errorf("hex decoded key must be exactly 32 bytes (256 bits), got %d bytes", len(hexKey))
	}

	// Try base64 decoding
	if base64Key, err := base64.StdEncoding.DecodeString(keyStr); err == nil {
		// Validate it's exactly 32 bytes (256 bits)
		if len(base64Key) == 32 {
			// Convert to hex for consistent internal representation
			return hex.EncodeToString(base64Key), nil
		}
		return "", fmt.Errorf("base64 decoded key must be exactly 32 bytes (256 bits), got %d bytes", len(base64Key))
	}

	// If neither works, it's invalid
	return "", fmt.Errorf("key must be a valid hex or base64 encoded 32-byte (256-bit) AES key")
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
