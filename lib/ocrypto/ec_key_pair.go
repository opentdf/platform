package ocrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type ECCMode uint8

const (
	ECCModeSecp256r1 ECCMode = 0
	ECCModeSecp384r1 ECCMode = 1
	ECCModeSecp521r1 ECCMode = 2
	ECCModeSecp256k1 ECCMode = 3
)

type ECKeyPair struct {
	PrivateKey *ecdsa.PrivateKey
}

// NewECKeyPair Generates an EC key pair of the given bit size.
func NewECKeyPair(mode ECCMode) (ECKeyPair, error) {
	var c elliptic.Curve
	switch mode {
	case ECCModeSecp256r1:
		c = elliptic.P256()
	case ECCModeSecp384r1:
		c = elliptic.P384()
	case ECCModeSecp521r1:
		c = elliptic.P521()
	case ECCModeSecp256k1:
		// TODO FIXME - unsupported?
		return ECKeyPair{}, errors.New("unsupported ec key pair mode")
	default:
		return ECKeyPair{}, fmt.Errorf("invalid ec key pair mode %d", mode)
	}

	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return ECKeyPair{}, fmt.Errorf("ec.GenerateKey failed: %w", err)
	}

	ecKeyPair := ECKeyPair{PrivateKey: privateKey}
	return ecKeyPair, nil
}

// PrivateKeyInPemFormat Returns private key in pem format.
func (keyPair ECKeyPair) PrivateKeyInPemFormat() (string, error) {
	if keyPair.PrivateKey == nil {
		return "", errors.New("failed to generate PEM formatted private key")
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(keyPair.PrivateKey)
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
func (keyPair ECKeyPair) PublicKeyInPemFormat() (string, error) {
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

// KeySize Return the size of this ec key pair.
func (keyPair ECKeyPair) KeySize() (int, error) {
	if keyPair.PrivateKey == nil {
		return -1, errors.New("failed to return key size")
	}
	return keyPair.PrivateKey.Params().N.BitLen(), nil
}
