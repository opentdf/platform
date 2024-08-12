package security

import "log/slog"

type Config struct {
	Type string `yaml:"type" default:"standard"`
	// StandardConfig is the configuration for the standard key provider
	StandardConfig StandardConfig `yaml:"standard,omitempty" mapstructure:"standard"`
}

func NewCryptoProvider(cfg Config) (CryptoProvider, error) {
	switch cfg.Type {
	case "hsm":
		slog.Error("opentdf hsm mode has been removed")
		return nil, ErrHSMNotFound
	case "standard":
		return NewStandardCrypto(cfg.StandardConfig)
	default:
		if cfg.Type != "" {
			slog.Warn("unsupported crypto type", "crypto.type", cfg.Type)
		}
		return NewStandardCrypto(cfg.StandardConfig)
	}
}
