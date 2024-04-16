package ocrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // used for padding which is safe
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

type AsymEncryption struct {
	PublicKey *rsa.PublicKey
}

// NewAsymEncryption creates and returns a new AsymEncryption.
func NewAsymEncryption(publicKeyInPem string) (AsymEncryption, error) {
	block, _ := pem.Decode([]byte(publicKeyInPem))
	if block == nil {
		return AsymEncryption{}, errors.New("failed to parse PEM formatted public key")
	}

	var pub any
	if strings.Contains(publicKeyInPem, "BEGIN CERTIFICATE") {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return AsymEncryption{}, fmt.Errorf("x509.ParseCertificate failed: %w", err)
		}

		var ok bool
		if pub, ok = cert.PublicKey.(*rsa.PublicKey); !ok {
			return AsymEncryption{}, errors.New("failed to parse PEM formatted public key")
		}
	} else {
		var err error
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return AsymEncryption{}, fmt.Errorf("x509.ParsePKIXPublicKey failed: %w", err)
		}
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return AsymEncryption{pub}, nil
	default:
		break
	}

	return AsymEncryption{}, errors.New("not an rsa PEM formatted public key")
}

// Encrypt encrypts data with public key.
func (asymEncryption AsymEncryption) Encrypt(data []byte) ([]byte, error) {
	if asymEncryption.PublicKey == nil {
		return nil, errors.New("failed to encrypt, public key is empty")
	}

	bytes, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, asymEncryption.PublicKey, data, nil) //nolint:gosec // used for padding which is safe
	if err != nil {
		return nil, fmt.Errorf("rsa.EncryptOAEP failed: %w", err)
	}

	return bytes, nil
}

// PublicKeyInPemFormat Returns public key in pem format.
func (asymEncryption AsymEncryption) PublicKeyInPemFormat() (string, error) {
	if asymEncryption.PublicKey == nil {
		return "", errors.New("failed to generate PEM formatted public key")
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(asymEncryption.PublicKey)
	if err != nil {
		return "", fmt.Errorf("x509.MarshalPKIXPublicKey failed: %w", err)
	}

	publicKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)

	return string(publicKeyPem), nil
}
