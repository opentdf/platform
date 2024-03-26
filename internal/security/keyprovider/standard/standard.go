package standard

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
)

type Config struct {
	RSAPrivateKeyPath string `yaml:"rsaPrivateKeyPath" mapstructure:"rsaPrivateKeyPath"`
	RSAPublicKeyPath  string `yaml:"rsaPublicKeyPath" mapstructure:"rsaPublicKeyPath"`
}

type Standard struct {
	rsaPublicKey  *rsa.PublicKey
	rsaPrivateKey *rsa.PrivateKey
	// ecPublicKey   *x509.Certificate
	// ecPrivateKey  *elliptic.
}

func New(cfg Config) (*Standard, error) {
	var (
		err           error
		rsaPublicKey  *rsa.PublicKey
		rsaPrivateKey *rsa.PrivateKey
	)

	// Generate new RSA key pair if no paths are provided
	if cfg.RSAPrivateKeyPath == "" && cfg.RSAPublicKeyPath == "" {
		slog.Info("Generating new RSA key pair")
		rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		rsaPublicKey = &rsaPrivateKey.PublicKey
	}

	// Load RSA key pair from paths
	if cfg.RSAPrivateKeyPath != "" && cfg.RSAPublicKeyPath != "" {
		slog.Info("Loading RSA key pair from paths")
		// Load RSA private key
		rsaPrivateKeyBytes, err := os.ReadFile(cfg.RSAPrivateKeyPath)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(rsaPrivateKeyBytes)
		if block == nil {
			return nil, errors.New("failed to decode PEM block containing the private key")
		}

		switch block.Type {
		case "RSA PRIVATE KEY":
			privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			rsaPrivateKey = privateKey
		case "PRIVATE KEY":
			privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}

			if _, ok := privateKey.(*rsa.PrivateKey); !ok {
				return nil, errors.New("private key is not RSA")
			}
			rsaPrivateKey = privateKey.(*rsa.PrivateKey)
		default:
			return nil, errors.New("unsupported key type")
		}

		// Load RSA public key
		rsaPublicKeyBytes, err := os.ReadFile(cfg.RSAPublicKeyPath)
		if err != nil {
			return nil, err
		}
		block, _ = pem.Decode(rsaPublicKeyBytes)
		if block == nil {
			return nil, errors.New("failed to decode PEM block containing the public key")
		}

		if block == nil || block.Type != "RSA PUBLIC KEY" && block.Type != "PUBLIC KEY" {
			return nil, errors.New("failed to decode PEM block containing public key")
		}

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		if _, ok := pub.(*rsa.PublicKey); !ok {
			return nil, errors.New("public key is not RSA")
		}
		rsaPublicKey = pub.(*rsa.PublicKey)
	}

	return &Standard{
		rsaPublicKey:  rsaPublicKey,
		rsaPrivateKey: rsaPrivateKey,
	}, nil
}

func (s Standard) DecryptOAEP(hash crypto.Hash, cipherText []byte, label []byte) ([]byte, error) {
	return rsa.DecryptOAEP(hash.New(), rand.Reader, s.rsaPrivateKey, cipherText, label)
}

func (s Standard) PublicKey() []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(s.rsaPublicKey)
	if err != nil {
		return nil
	}
	rsaPublicKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	return rsaPublicKey
}
