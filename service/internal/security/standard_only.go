package security

import "log/slog"

type Config struct {
	Type string `mapstructure:"type" json:"type"`
	// StandardConfig is the configuration for the standard key provider
	StandardConfig StandardConfig `mapstructure:"standard" json:"standard"`
}

func (c Config) IsEmpty() bool {
	return c.Type == "" && c.StandardConfig.IsEmpty()
}

func NewCryptoProvider(cfg Config) (*StandardCrypto, error) {
	switch cfg.Type {
	case "hsm":
		slog.Error("opentdf hsm mode has been removed")
		return nil, ErrHSMNotFound
	case "standard":
		return NewStandardCrypto(cfg.StandardConfig)
	default:
		if cfg.Type != "" {
			slog.Warn("unsupported crypto type", slog.String("crypto_type", cfg.Type))
		}
		return NewStandardCrypto(cfg.StandardConfig)
	}
}
