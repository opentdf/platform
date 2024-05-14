package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

var (
	errNotImplemented             = errors.New("standard crypto for nano not implemented")
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
	asymDecryption ocrypto.AsymDecryption
	asymEncryption ocrypto.AsymEncryption
}

type StandardECCrypto struct {
	Identifier       string
	ecPrivateKey     *ecdsa.PrivateKey
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
		privatePemData, err := os.ReadFile(kasInfo.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to rsa private key file: %w", err)
		}
		// this returns a certificate not a PUBLIC KEY
		publicPemData, err := os.ReadFile(kasInfo.PublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to rsa public key file: %w", err)
		}
		//block, _ := pem.Decode(publicPemData)
		//if block == nil {
		//	return nil, errors.New("failed to decode PEM block containing public key")
		//}
		//ecPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		//if err != nil {
		//	return nil, fmt.Errorf("failed to parse EC public key: %w", err)
		//}
		block, _ := pem.Decode(privatePemData)
		if block == nil {
			return nil, errors.New("failed to decode PEM block containing private key")
		}
		ecPrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		//var ecdsaPublicKey *ecdsa.PublicKey
		//switch pub := ecPublicKey.(type) {
		//case *ecdsa.PublicKey:
		//	fmt.Println("pub is of type ECDSA:", pub)
		//	ecdsaPublicKey = pub
		//default:
		//	panic("unknown type of public key")
		//}
		var ecdsaPrivateKey *ecdsa.PrivateKey
		switch priv := ecPrivateKey.(type) {
		case *ecdsa.PrivateKey:
			fmt.Println("pub is of type ECDSA:", priv)
			ecdsaPrivateKey = priv
		default:
			panic("unknown type of public key")
		}
		standardCrypto.ecKeys = append(standardCrypto.ecKeys, StandardECCrypto{
			Identifier: id,
			//ecPublicKey:      ecdsaPublicKey,
			ecPrivateKey:     ecdsaPrivateKey,
			ecCertificatePEM: string(publicPemData),
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

func (s StandardCrypto) ECPublicKey(string) (string, error) {
	if len(s.ecKeys) == 0 {
		return "", ErrCertNotFound
	}
	ecKey := s.ecKeys[0]
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(ecKey.ecPrivateKey.PublicKey)
	if err != nil {
		return "", ErrPublicKeyMarshal
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	return string(pemEncoded), nil
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

func (s StandardCrypto) GenerateNanoTDFSymmetricKey(ephemeralPublicKey []byte) ([]byte, error) {
	keyLengthBytes := len(ephemeralPublicKey)
	if keyLengthBytes <= 0 {
		return nil, errors.New("key length should be positive")
	}
	key := make([]byte, keyLengthBytes)
	_, err := rand.Read(key)

	if err != nil {
		return nil, fmt.Errorf("failed to generate symmetric key: %w", err)
	}
	return key, nil
}

func (s StandardCrypto) GenerateEphemeralKasKeys() (PrivateKeyEC, []byte, error) {
	// prepare private key template
	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
	}
	// generate private key
	privKey, err := ecdsa.GenerateKey(privKey.PublicKey.Curve, rand.Reader)
	if err != nil {
		return PrivateKeyEC(0), nil, fmt.Errorf("failed to generate elliptic curve key pair: %w", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(privKey.PublicKey)
	if err != nil {
		return PrivateKeyEC(0), nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return PrivateKeyEC(0), pubBytes, nil
}

func (s StandardCrypto) GenerateNanoTDFSessionKey(privateKeyHandle PrivateKeyEC, ephemeralPublicKey []byte) ([]byte, error) {
	// Parse the received elliptic public key
	pubKeyInterface, err := x509.ParsePKIXPublicKey(ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// We have to ensure we have an ECDSA public key
	pubKey, ok := pubKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("parsed key was not of type *ecdsa.PublicKey")
	}
	// get ecKey using privateKeyHandle as index
	ecKey := s.ecKeys[privateKeyHandle]

	// Implement the ECDH key agreement scheme
	sharedKeyX, sharedKeyY := ecKey.ecPrivateKey.PublicKey.Curve.ScalarMult(pubKey.X, pubKey.Y, ecKey.ecPrivateKey.D.Bytes())

	// Concatenate x and y coordinates to form the session key
	sessionKey := append(sharedKeyX.Bytes(), sharedKeyY.Bytes()...)

	return sessionKey, nil
}

func (s StandardCrypto) Close() {
}
