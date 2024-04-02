package security

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"github.com/opentdf/platform/lib/crypto"
	"log/slog"
	"os"
)

var (
	errStandardCryptoNotEnabled   = errors.New("standard crypto flag is enabled in the config")
	errStandardCryptoObjIsInvalid = errors.New("standard crypto object is invalid")
)

type StandardConfig struct {
	RSAKeys map[string]StandardKeyInfo `yaml:"rsa,omitempty" mapstructure:"rsa"`
	ECKeys  map[string]StandardKeyInfo `yaml:"ec,omitempty" mapstructure:"ec"`
}

type StandardKeyInfo struct {
	PrivateKeyPath string `yaml:"privateKeyPath" mapstructure:"privateKeyPath"`
	PublicKeyPath  string `yaml:"publicKeyPath" mapstructure:"publicKeyPath"`
}

type StandardRSACrypto struct {
	Identifier     string
	asymDecryption crypto.AsymDecryption
	asymEncryption crypto.AsymEncryption
}

type StandardECCrypto struct {
	Identifier   string
	ecPublicKey  *ecdh.PublicKey
	ecPrivateKey *ecdh.PrivateKey
}

type StandardCrypto struct {
	rsaKeys []StandardRSACrypto
	ecKeys  []StandardECCrypto
}

// NewStandardCrypto Create a new instance of standard crypto
func NewStandardCrypto(cfg StandardConfig) (*StandardCrypto, error) {
	standardCrypto := &StandardCrypto{}
	for id, kasInfo := range cfg.RSAKeys {
		privatePemData, err := os.ReadFile(kasInfo.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to rsa private key file: %w", err)
		}

		asymDecryption, err := crypto.NewAsymDecryption(string(privatePemData))
		if err != nil {
			return nil, fmt.Errorf("crypto.NewAsymDecryption failed: %w", err)
		}

		publicPemData, err := os.ReadFile(kasInfo.PublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to rsa public key file: %w", err)
		}

		asymEncryption, err := crypto.NewAsymEncryption(string(publicPemData))
		if err != nil {
			return nil, fmt.Errorf("crypto.NewAsymEncryption failed: %w", err)
		}

		standardCrypto.rsaKeys = append(standardCrypto.rsaKeys, StandardRSACrypto{
			Identifier:     id,
			asymDecryption: asymDecryption,
			asymEncryption: asymEncryption,
		})
	}

	return standardCrypto, nil
}

func (s StandardCrypto) RSAPublicKey(keyId string) (string, error) {

	if len(s.rsaKeys) == 0 {
		return "", errStandardCryptoObjIsInvalid
	}

	// TODO: For now ignore the key id
	slog.Info("⚠️ Ignoring the", slog.String("key id", keyId))

	pem, err := s.rsaKeys[0].asymEncryption.PublicKeyInPemFormat()
	if err != nil {
		return "", fmt.Errorf("failed to retrive rsa public key file: %w", err)
	}

	return pem, nil
}

func (s StandardCrypto) ECPublicKey(keyId string) (string, error) {
	return "", nil
}

func (s StandardCrypto) RSADecrypt(hashFunction string, keyId string, keyLabel string, ciphertext []byte) ([]byte, error) {

	if len(s.rsaKeys) == 0 {
		return nil, errStandardCryptoObjIsInvalid
	}

	// TODO: For now ignore the key id
	slog.Info("⚠️ Ignoring the", slog.String("key id", keyId))

	data, err := s.rsaKeys[0].asymDecryption.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return data, nil
}
