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

type eccMode uint8

const (
	eccModeSecp256r1 eccMode = 0
	eccModeSecp384r1 eccMode = 1
	eccModeSecp521r1 eccMode = 2
	eccModeSecp256k1 eccMode = 3
)

type EcKeyPair struct {
	privateKey *ecdsa.PrivateKey
}

// NewECKeyPair Generates an EC key pair of the given bit size.
func NewECKeyPair(mode eccMode) (EcKeyPair, error) {

	var c elliptic.Curve
	switch mode {
	case eccModeSecp256r1:
		c = elliptic.P256()
		break
	case eccModeSecp384r1:
		c = elliptic.P384()
		break
	case eccModeSecp521r1:
		c = elliptic.P521()
		break
	case eccModeSecp256k1:
		// TODO FIXME - unsupported?
		return EcKeyPair{}, errors.New("unsupported ec key pair mode")
	default:
		return EcKeyPair{}, fmt.Errorf("invalid ec key pair mode %d", mode)
	}

	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return EcKeyPair{}, fmt.Errorf("ec.GenerateKey failed: %w", err)
	}

	ecKeyPair := EcKeyPair{privateKey: privateKey}
	return ecKeyPair, nil
}

// PrivateKeyInPemFormat Returns private key in pem format.
func (keyPair EcKeyPair) PrivateKeyInPemFormat() (string, error) {
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
func (keyPair EcKeyPair) PublicKeyInPemFormat() (string, error) {
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

// KeySize Return the size of this ec key pair.
func (keyPair EcKeyPair) KeySize() (int, error) {
	if keyPair.privateKey == nil {
		return -1, errors.New("failed to return key size")
	}
	return keyPair.privateKey.Params().N.BitLen(), nil
}
