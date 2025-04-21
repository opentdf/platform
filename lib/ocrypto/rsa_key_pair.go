package ocrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type RsaKeyPair struct {
	PrivateKey *rsa.PrivateKey
}

func FromRSA(k *rsa.PrivateKey) RsaKeyPair {
	return RsaKeyPair{k}
}

// NewRSAKeyPair Generates an RSA key pair of the given bit size.
func NewRSAKeyPair(bits int) (RsaKeyPair, error) {
	PrivateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return RsaKeyPair{}, fmt.Errorf("rsa.GenerateKe failed: %w", err)
	}

	rsaKeyPair := RsaKeyPair{PrivateKey: PrivateKey}
	return rsaKeyPair, nil
}

// PrivateKeyInPemFormat Returns private key in pem format.
func (keyPair RsaKeyPair) PrivateKeyInPemFormat() (string, error) {
	if keyPair.PrivateKey == nil {
		return "", errors.New("failed to generate PEM formatted private key")
	}

	PrivateKeyBytes, err := x509.MarshalPKCS8PrivateKey(keyPair.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("x509.MarshalPKCS8PrivateKey failed: %w", err)
	}

	PrivateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: PrivateKeyBytes,
		},
	)
	return string(PrivateKeyPem), nil
}

// PublicKeyInPemFormat Returns public key in pem format.
func (keyPair RsaKeyPair) PublicKeyInPemFormat() (string, error) {
	if keyPair.PrivateKey == nil {
		return "", errors.New("failed to generate PEM formatted public key")
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&keyPair.PrivateKey.PublicKey)
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

// KeySize Return the size of this rsa key pair.
func (keyPair RsaKeyPair) KeySize() (int, error) {
	if keyPair.PrivateKey == nil {
		return -1, errors.New("failed to return key size")
	}
	return keyPair.PrivateKey.N.BitLen(), nil
}

// GetKeyType returns the key type (RSAKey)
func (keyPair RsaKeyPair) GetKeyType() KeyType {
	return RSA2048Key
}
