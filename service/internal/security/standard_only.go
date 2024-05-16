//go:build !opentdf.hsm

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
		// To enable HSM, compile with `go build --tags=opentdf.hsm ...service`
		slog.Error("not compiled with `opentdf.hsm` flag set; hsm functionality disabled")
		return nil, ErrHSMNotFound
	case "standard":
		return NewStandardCrypto(cfg.StandardConfig)
	default:
		return NewStandardCrypto(cfg.StandardConfig)
	}
}
