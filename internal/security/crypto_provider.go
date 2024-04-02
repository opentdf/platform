package security

type Config struct {
	Type string `yaml:"type" default:"standard"`
	// HSMConfig is the configuration for the HSM
	HSMConfig HSMConfig `yaml:"hsm,omitempty" mapstructure:"hsm"`
	// StandardConfig is the configuration for the standard key provider
	StandardConfig StandardConfig `yaml:"standard,omitempty" mapstructure:"standard"`
}

type CryptoProvider interface {
	RSAPublicKey(keyId string) (string, error)
	RSAPublicKeyAsJson(keyId string) (string, error)
	ECPublicKey(keyId string) (string, error)
	RSADecrypt(hashFunction string, keyId string, keyLabel string, ciphertext []byte) ([]byte, error)
}

func NewCryptoProvider(cfg Config) (CryptoProvider, error) {
	switch cfg.Type {
	case "hsm":
		return New(&cfg.HSMConfig)
	case "standard":
		return NewStandardCrypto(cfg.StandardConfig)
	default:
		return NewStandardCrypto(cfg.StandardConfig)
	}
}
