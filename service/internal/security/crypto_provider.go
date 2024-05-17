package security

import "crypto"

type Config struct {
	Type string `yaml:"type" default:"standard"`
	// HSMConfig is the configuration for the HSM
	HSMConfig HSMConfig `yaml:"hsm,omitempty" mapstructure:"hsm"`
	// StandardConfig is the configuration for the standard key provider
	StandardConfig StandardConfig `yaml:"standard,omitempty" mapstructure:"standard"`
}

type CryptoProvider interface {
	RSAPublicKey(keyID string) (string, error)
	RSAPublicKeyAsJSON(keyID string) (string, error)
	RSADecrypt(hash crypto.Hash, keyID string, keyLabel string, ciphertext []byte) ([]byte, error)

	ECPublicKey(keyID string) (string, error)
	ECCertificate(keyID string) (string, error)
	GenerateNanoTDFSymmetricKey(ephemeralPublicKeyBytes []byte) ([]byte, error)
	GenerateEphemeralKasKeys() (PrivateKeyEC, []byte, error)
	GenerateNanoTDFSessionKey(privateKeyHandle PrivateKeyEC, ephemeralPublicKey []byte) ([]byte, error)
	Close()
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
