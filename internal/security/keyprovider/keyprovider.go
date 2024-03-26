package keyprovider

import (
	"crypto"
	"fmt"

	"github.com/opentdf/platform/internal/security/keyprovider/hsm"
	"github.com/opentdf/platform/internal/security/keyprovider/standard"
)

type Config struct {
	Type string `yaml:"type" default:"standard"`
	// HSMConfig is the configuration for the HSM
	HSMConfig hsm.HSMConfig `yaml:"hsm,omitempty" mapstructure:"hsm"`
	// StandardConfig is the configuration for the standard key provider
	StandardConfig standard.Config `yaml:"standard,omitempty" mapstructure:"standard"`
}

type Provider interface {
	DecryptOAEP(hash crypto.Hash, cipherText []byte, label []byte) ([]byte, error)
	PublicKey() []byte
}

func New(cfg Config) (Provider, error) {
	fmt.Println(cfg)
	switch cfg.Type {
	case "hsm":
		return hsm.New(&cfg.HSMConfig)
	case "standard":
		return standard.New(cfg.StandardConfig)
	default:
		return standard.New(cfg.StandardConfig)
	}
}
