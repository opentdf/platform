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
	privateKey *rsa.PrivateKey
}

// NewRSAKeyPair Generates an RSA key pair of the given bit size.
func NewRSAKeyPair(bits int) (RsaKeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return RsaKeyPair{}, fmt.Errorf("rsa.GenerateKe failed: %w", err)
	}

	rsaKeyPair := RsaKeyPair{privateKey: privateKey}
	return rsaKeyPair, nil
}

// PrivateKeyInPemFormat Returns private key in pem format.
func (keyPair RsaKeyPair) PrivateKeyInPemFormat() (string, error) {
	if keyPair.privateKey == nil {
		return "", errors.New("failed to generate PEM formatted private key")
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(keyPair.privateKey)
	if err != nil {
		return "", fmt.Errorf("x509.MarshalPKCS8PrivateKey failed: %w", err)
	}

	privateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)
	return string(privateKeyPem), nil
}

// PublicKeyInPemFormat Returns public key in pem format.
func (keyPair RsaKeyPair) PublicKeyInPemFormat() (string, error) {
	if keyPair.privateKey == nil {
		return "", errors.New("failed to generate PEM formatted public key")
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&keyPair.privateKey.PublicKey)
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
	if keyPair.privateKey == nil {
		return -1, errors.New("failed to return key size")
	}
	return keyPair.privateKey.N.BitLen(), nil
}
