package ocrypto

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

type AsymDecryption struct {
	PrivateKey *rsa.PrivateKey
}

// NewAsymDecryption creates and returns a new AsymDecryption.
func NewAsymDecryption(privateKeyInPem string) (AsymDecryption, error) {
	block, _ := pem.Decode([]byte(privateKeyInPem))
	if block == nil {
		return AsymDecryption{}, errors.New("failed to parse PEM formatted private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	switch {
	case err == nil:
		break
	case strings.Contains(err.Error(), "use ParsePKCS1PrivateKey instead"):
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return AsymDecryption{}, fmt.Errorf("x509.ParsePKCS1PrivateKey failed: %w", err)
		}
	case strings.Contains(err.Error(), "use ParseECPrivateKey instead"):
		priv, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return AsymDecryption{}, fmt.Errorf("x509.ParseECPrivateKey failed: %w", err)
		}
	default:
		return AsymDecryption{}, fmt.Errorf("x509.ParsePKCS8PrivateKey failed: %w", err)
	}

	switch privateKey := priv.(type) {
	case *rsa.PrivateKey:
		return AsymDecryption{privateKey}, nil
	default:
		break
	}

	return AsymDecryption{}, errors.New("not an rsa PEM formatted private key")
}

// Decrypt decrypts ciphertext with private key.
func (asymDecryption AsymDecryption) Decrypt(data []byte) ([]byte, error) {
	if asymDecryption.PrivateKey == nil {
		return nil, errors.New("failed to decrypt, private key is empty")
	}

	bytes, err := asymDecryption.PrivateKey.Decrypt(nil,
		data,
		&rsa.OAEPOptions{Hash: crypto.SHA1})
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKCS8PrivateKey failed: %w", err)
	}

	return bytes, nil
}
