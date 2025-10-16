package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/opentdf/platform/sdk"
)

// parseRSAPrivateKeyFromFile reads and parses an RSA private key from a PEM file.
// Supports both PKCS#1 (RSA PRIVATE KEY) and PKCS#8 (PRIVATE KEY) formats.
//
// SECURITY WARNING: This function expects unencrypted keys for simplicity in examples.
// For production use:
//   - Use password-protected (encrypted) private keys
//   - Store keys in secure key management systems (HSMs, cloud KMS)
//   - Ensure key files have restrictive permissions (chmod 600)
//   - Never commit private keys to version control
func parseRSAPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	privPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, errors.New("no PEM block found in key file")
	}

	var rsaPriv *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsaPriv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#1 private key: %w", err)
		}
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		var ok bool
		rsaPriv, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("key is not an RSA private key")
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %s (expected RSA PRIVATE KEY or PRIVATE KEY)", block.Type)
	}

	return rsaPriv, nil
}

// getAssertionKeyPrivate loads an RSA private key for assertion signing.
func getAssertionKeyPrivate(path string) (sdk.AssertionKey, error) {
	rsaPriv, err := parseRSAPrivateKeyFromFile(path)
	if err != nil {
		return sdk.AssertionKey{}, err
	}

	return sdk.AssertionKey{
		Alg: sdk.AssertionKeyAlgRS256,
		Key: rsaPriv,
	}, nil
}

// getAssertionKeyPublic loads the public key portion of an RSA private key for assertion validation.
func getAssertionKeyPublic(path string) (sdk.AssertionKey, error) {
	rsaPriv, err := parseRSAPrivateKeyFromFile(path)
	if err != nil {
		return sdk.AssertionKey{}, err
	}

	return sdk.AssertionKey{
		Alg: sdk.AssertionKeyAlgRS256,
		Key: &rsaPriv.PublicKey,
	}, nil
}
