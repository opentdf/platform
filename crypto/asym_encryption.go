package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
)

type AsymEncryption struct {
	publicKey *rsa.PublicKey
}

// CreateAsymEncryption creates and returns a new AsymEncryption.
func CreateAsymEncryption(publicKeyInPem string) (AsymEncryption, error) {
	block, _ := pem.Decode([]byte(publicKeyInPem))
	if block == nil {
		return AsymEncryption{}, errors.New("failed to parse PEM formatted public key")
	}

	var pub any
	if strings.Contains(publicKeyInPem, "BEGIN CERTIFICATE") {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return AsymEncryption{}, err
		}

		pub = cert.PublicKey.(*rsa.PublicKey)
	} else {
		var err error
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return AsymEncryption{}, err
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

	if asymEncryption.publicKey == nil {
		return nil, errors.New("failed to encrypt, public key is empty")
	}

	return rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		asymEncryption.publicKey,
		data,
		nil)
}
