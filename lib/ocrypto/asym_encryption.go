package ocrypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // used for padding which is safe
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

type Scheme interface {
	// Encrypt encrypts data with public key.
	Encrypt(data []byte) ([]byte, error)

	// PublicKeyInPemFormat Returns public key in pem format.
	PublicKeyInPemFormat() (string, error)
}

type AsymEncryption struct {
	PublicKey *rsa.PublicKey
}

type ECIES struct {
	PublicKey    *ecdh.PublicKey
	ephemeralKey *ecdh.PrivateKey
}

func FromPEM(publicKeyInPem string) (Scheme, error) {
	pub, err := getPublicPart(publicKeyInPem)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return &AsymEncryption{pub}, nil
	case *ecdh.PublicKey:
		return &ECIES{pub}, nil
	default:
		break
	}

	return nil, errors.New("not an supported type of public key")
}

// NewAsymEncryption creates and returns a new AsymEncryption.
// Deprecated: Use FromPEM instead.
func NewAsymEncryption(publicKeyInPem string) (AsymEncryption, error) {
	pub, err := getPublicPart(publicKeyInPem)
	if err != nil {
		return AsymEncryption{}, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return AsymEncryption{pub}, nil
	default:
		break
	}

	return AsymEncryption{}, errors.New("not an supported type of public key")
}

func getPublicPart(publicKeyInPem string) (any, error) {
	block, _ := pem.Decode([]byte(publicKeyInPem))
	if block == nil {
		return nil, errors.New("failed to parse PEM formatted public key")
	}

	var pub any
	if strings.Contains(publicKeyInPem, "BEGIN CERTIFICATE") {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParseCertificate failed: %w", err)
		}

		pub = cert.PublicKey
	} else {
		var err error
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParsePKIXPublicKey failed: %w", err)
		}
	}
	return pub, nil
}

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

func publicKeyInPemFormat(pk any) (string, error) {
	if pk == nil {
		return "", errors.New("failed to generate PEM formatted public key")
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(pk)
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

func (asymEncryption AsymEncryption) PublicKeyInPemFormat() (string, error) {
	return publicKeyInPemFormat(asymEncryption.PublicKey)
}

// Encrypts the data with the EC public key.
func (asymEncryption ECIES) Encrypt(data []byte) ([]byte, error) {
	if asymEncryption.PublicKey == nil {
		return nil, errors.New("failed to encrypt, public key is empty")
	}

	return bytes, nil
}

// PublicKeyInPemFormat Returns public key in pem format.
func (asymEncryption ECIES) PublicKeyInPemFormat() (string, error) {
	return publicKeyInPemFormat(asymEncryption.PublicKey)
}
