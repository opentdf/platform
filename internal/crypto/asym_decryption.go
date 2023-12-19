package crypto

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type AsymDecryption struct {
	privateKey *rsa.PrivateKey
}

// CreateAsymDecryption creates and returns a new AsymDecryption.
func CreateAsymDecryption(privateKeyInPem string) (AsymDecryption, error) {
	block, _ := pem.Decode([]byte(privateKeyInPem))
	if block == nil {
		return AsymDecryption{}, errors.New("failed to parse PEM formatted private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return AsymDecryption{}, err
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
	if asymDecryption.privateKey == nil {
		return nil, errors.New("failed to decrypt, private key is empty")
	}

	return asymDecryption.privateKey.Decrypt(nil,
		data,
		&rsa.OAEPOptions{Hash: crypto.SHA256})
}
