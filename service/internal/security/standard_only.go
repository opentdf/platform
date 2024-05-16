//go:build !opentdf.hsm

package security

import "log/slog"

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
