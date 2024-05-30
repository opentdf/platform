package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/lib/ocrypto"
)

// / Constants
const (
	kNanoTDFMagicStringAndVersion = "L1L"
)

var errStandardCryptoObjIsInvalid = errors.New("standard crypto object is invalid")

type StandardConfig struct {
	RSAKeys map[string]StandardKeyInfo `yaml:"rsa,omitempty" mapstructure:"rsa"`
	ECKeys  map[string]StandardKeyInfo `yaml:"ec,omitempty" mapstructure:"ec"`
}

type StandardKeyInfo struct {
	PrivateKeyPath string `yaml:"private_key_path" mapstructure:"private_key_path"`
	PublicKeyPath  string `yaml:"public_key_path" mapstructure:"public_key_path"`
}

type StandardRSACrypto struct {
	Identifier     string
	asymDecryption ocrypto.AsymDecryption
	asymEncryption ocrypto.AsymEncryption
}

type StandardECCrypto struct {
	Identifier       string
	ecPrivateKeyPem  string
	ecCertificatePEM string
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

		asymDecryption, err := ocrypto.NewAsymDecryption(string(privatePemData))
		if err != nil {
			return nil, fmt.Errorf("ocrypto.NewAsymDecryption failed: %w", err)
		}

		publicPemData, err := os.ReadFile(kasInfo.PublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to rsa public key file: %w", err)
		}

		asymEncryption, err := ocrypto.NewAsymEncryption(string(publicPemData))
		if err != nil {
			return nil, fmt.Errorf("ocrypto.NewAsymEncryption failed: %w", err)
		}

		standardCrypto.rsaKeys = append(standardCrypto.rsaKeys, StandardRSACrypto{
			Identifier:     id,
			asymDecryption: asymDecryption,
			asymEncryption: asymEncryption,
		})
	}
	for id, kasInfo := range cfg.ECKeys {
		slog.Info("cfg.ECKeys", "id", id, "kasInfo", kasInfo)
		// private and public EC KAS key
		privatePemData, err := os.ReadFile(kasInfo.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to EC private key file: %w", err)
		}
		// certificate EC KAS key
		ecCertificatePEM, err := os.ReadFile(kasInfo.PublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to EC certificate file: %w", err)
		}
		standardCrypto.ecKeys = append(standardCrypto.ecKeys, StandardECCrypto{
			Identifier:       id,
			ecPrivateKeyPem:  string(privatePemData),
			ecCertificatePEM: string(ecCertificatePEM),
		})
	}

	return standardCrypto, nil
}

func (s StandardCrypto) RSAPublicKey(keyID string) (string, error) {
	if len(s.rsaKeys) == 0 {
		return "", ErrCertNotFound
	}

	// TODO: For now ignore the key id
	slog.Info("⚠️ Ignoring the", slog.String("key id", keyID))

	pem, err := s.rsaKeys[0].asymEncryption.PublicKeyInPemFormat()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve rsa public key file: %w", err)
	}

	return pem, nil
}

func (s StandardCrypto) ECCertificate(identifier string) (string, error) {
	if len(s.ecKeys) == 0 {
		return "", ErrCertNotFound
	}
	// this endpoint returns certificate
	for _, ecKey := range s.ecKeys {
		slog.Debug("ecKey", "id", ecKey.Identifier)
		if ecKey.Identifier == identifier {
			return ecKey.ecCertificatePEM, nil
		}
	}
	return "", fmt.Errorf("no EC Key found with the given identifier: %s", identifier)
}

func (s StandardCrypto) ECPublicKey(identifier string) (string, error) {
	if len(s.ecKeys) == 0 {
		return "", ErrCertNotFound
	}
	for _, ecKey := range s.ecKeys {
		slog.Debug("ecKey", "id", ecKey.Identifier)
		if ecKey.Identifier != identifier {
			continue
		}

		ecPrivateKey, err := ocrypto.ECPrivateKeyFromPem([]byte(ecKey.ecPrivateKeyPem))
		if err != nil {
			return "", fmt.Errorf("ECPrivateKeyFromPem failed: %s %w", identifier, err)
		}

		ecPublicKey := ecPrivateKey.PublicKey()
		derBytes, err := x509.MarshalPKIXPublicKey(ecPublicKey)
		if err != nil {
			return "", fmt.Errorf("failed to marshal public key: %s %w", identifier, err)
		}

		pemBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derBytes,
		}
		pemBytes := pem.EncodeToMemory(pemBlock)
		if pemBytes == nil {
			return "", fmt.Errorf("failed to encode public key to PEM: %s", identifier)
		}
		return string(pemBytes), nil
	}
	return "", fmt.Errorf("no EC Key found with the given identifier: %s", identifier)
}

func (s StandardCrypto) RSADecrypt(_ crypto.Hash, keyID string, _ string, ciphertext []byte) ([]byte, error) {
	if len(s.rsaKeys) == 0 {
		return nil, errStandardCryptoObjIsInvalid
	}

	// TODO: For now ignore the key id
	slog.Info("⚠️ Ignoring the", slog.String("key id", keyID))

	data, err := s.rsaKeys[0].asymDecryption.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return data, nil
}

func (s StandardCrypto) RSAPublicKeyAsJSON(keyID string) (string, error) {
	if len(s.rsaKeys) == 0 {
		return "", errStandardCryptoObjIsInvalid
	}

	// TODO: For now ignore the key id
	slog.Info("⚠️ Ignoring the", slog.String("key id", keyID))

	rsaPublicKeyJwk, err := jwk.FromRaw(s.rsaKeys[0].asymEncryption.PublicKey)
	if err != nil {
		return "", fmt.Errorf("jwk.FromRaw: %w", err)
	}

	jsonPublicKey, err := json.Marshal(rsaPublicKeyJwk)
	if err != nil {
		return "", fmt.Errorf("jwk.FromRaw: %w", err)
	}

	return string(jsonPublicKey), nil
}

func (s StandardCrypto) GenerateNanoTDFSymmetricKey(ephemeralPublicKeyBytes []byte) ([]byte, error) {
	ephemeralECDSAPublicKey, err := ConvertEphemeralPublicKeyBytesToECDSAPublicKey(ephemeralPublicKeyBytes)
	if err != nil {
		return nil, err
	}
	derBytes, err := x509.MarshalPKIXPublicKey(ephemeralECDSAPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA public key: %w", err)
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	ephemeralECDSAPublicKeyPEM := pem.EncodeToMemory(pemBlock)

	symmetricKey, err := ocrypto.ComputeECDHKey([]byte(s.ecKeys[0].ecPrivateKeyPem), ephemeralECDSAPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.ComputeECDHKey failed: %w", err)
	}

	key, err := ocrypto.CalculateHKDF(versionSalt(), symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.CalculateHKDF failed:%w", err)
	}

	return key, nil
}

func (s StandardCrypto) GenerateEphemeralKasKeys() (any, []byte, error) {
	ephemeralKeyPair, err := ocrypto.NewECKeyPair(ocrypto.ECCModeSecp256r1)
	if err != nil {
		return nil, nil, fmt.Errorf("ocrypto.NewECKeyPair failed: %w", err)
	}

	pubKeyInPem, err := ephemeralKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get public key in PEM format: %w", err)
	}
	pubKeyBytes := []byte(pubKeyInPem)

	privKey, err := ocrypto.ConvertToECDHPrivateKey(ephemeralKeyPair.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert provate key to ECDH: %w", err)
	}
	return privKey, pubKeyBytes, nil
}

func (s StandardCrypto) GenerateNanoTDFSessionKey(privateKey any, ephemeralPublicKeyPEM []byte) ([]byte, error) {
	ecdhKey, err := ocrypto.ConvertToECDHPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("GenerateNanoTDFSessionKey failed to ConvertToECDHPrivateKey: %w", err)
	}
	ephemeralECDHPublicKey, err := ocrypto.ECPubKeyFromPem(ephemeralPublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("GenerateNanoTDFSessionKey failed to ocrypto.ECPubKeyFromPem: %w", err)
	}
	// shared secret
	sessionKey, err := ecdhKey.ECDH(ephemeralECDHPublicKey)
	if err != nil {
		return nil, fmt.Errorf("GenerateNanoTDFSessionKey failed to ecdhKey.ECDH: %w", err)
	}

	salt := versionSalt()
	derivedKey, err := ocrypto.CalculateHKDF(salt, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.CalculateHKDF failed:%w", err)
	}
	return derivedKey, nil
}

func ConvertEphemeralPublicKeyBytesToECDSAPublicKey(ephemeralPublicKeyBytes []byte) (*ecdsa.PublicKey, error) {
	// Converting ephemeralPublicKey byte array to *big.Int
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), ephemeralPublicKeyBytes)
	if x == nil {
		return nil, errors.New("failed to unmarshal compressed public key")
	}
	// Creating ecdsa.PublicKey from *big.Int
	ephemeralECDSAPublicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	return ephemeralECDSAPublicKey, nil
}

func (s StandardCrypto) Close() {
}

func versionSalt() []byte {
	digest := sha256.New()
	digest.Write([]byte(kNanoTDFMagicStringAndVersion))
	return digest.Sum(nil)
}
