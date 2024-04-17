package ocrypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"strings"
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

// ComputeECDHKey calculate shared secret from public key from one party and the private key from another party.
func ComputeECDHKey(privateKeyInPem string, publicKeyInPem string) ([]byte, error) {
	ecdhPrivateKey, err := ECPrivateKeyFromPem(privateKeyInPem)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.ECPrivateKeyFromPem failed: %w", err)
	}

	ecdhPublicKey, err := ECPubKeyFromPem(publicKeyInPem)
	if err != nil {
		return nil, fmt.Errorf("ocrypto.ECPubKeyFromPem failed: %w", err)
	}

	sharedKey, err := ecdhPrivateKey.ECDH(ecdhPublicKey)
	if err != nil {
		return nil, fmt.Errorf("there was a problem deriving a shared ECDH key: %w", err)
	}

	return sharedKey, nil
}

// ConvertToECDHPublicKey convert the ec public key to ECDH public key
func ConvertToECDHPublicKey(key interface{}) (*ecdh.PublicKey, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		// Convert from ecdsa.PublicKey to ECDHPublicKey
		return k.ECDH()
	case *ecdh.PublicKey:
		// No conversion needed
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported public key type")
	}
}

// ConvertToECDHPrivateKey convert the ec private key to ECDH private key
func ConvertToECDHPrivateKey(key interface{}) (*ecdh.PrivateKey, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		// Convert from ecdsa.PublicKey to ECDHPublicKey
		return k.ECDH()
	case *ecdh.PrivateKey:
		// No conversion needed
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
}

// CalculateHKDF generate a key using key derivation function.
func CalculateHKDF(salt []byte, secret []byte, keyLen int) ([]byte, error) {
	hkdfObj := hkdf.New(sha256.New, secret, salt, nil)

	derivedKey := make([]byte, keyLen)
	_, err := io.ReadFull(hkdfObj, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive hkdf key: %w", err)
	}

	return derivedKey, nil
}

// ECPubKeyFromPem generate ec public from pem format
func ECPubKeyFromPem(pemECPubKey string) (*ecdh.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemECPubKey))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM formatted public key")
	}

	var pub any
	if strings.Contains(pemECPubKey, "BEGIN CERTIFICATE") {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParseCertificate failed: %w", err)
		}

		var ok bool
		if pub, ok = cert.PublicKey.(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("failed to parse PEM formatted public key")
		}
	} else {
		var err error
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParsePKIXPublicKey failed: %w", err)
		}
	}

	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		return ConvertToECDHPublicKey(pub)
	default:
		break
	}

	return nil, fmt.Errorf("not an ec PEM formatted public key")
}

// ECPrivateKeyFromPem generate ec private from pem format
func ECPrivateKeyFromPem(privateECKeyInPem string) (*ecdh.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateECKeyInPem))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM formatted private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKCS8PrivateKey failed: %w", err)
	}

	switch privateKey := priv.(type) {
	case *ecdsa.PrivateKey:
		return ConvertToECDHPrivateKey(privateKey)
	default:
		break
	}

	return nil, fmt.Errorf("not an ec PEM formatted private key")
}
