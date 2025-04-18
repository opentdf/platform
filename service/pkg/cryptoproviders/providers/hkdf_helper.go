package providers

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKeyHKDF derives key material using HKDF with SHA-256.
// Parameters:
//   - ikm: input keying material.
//   - salt: salt value (can be nil).
//   - info: context and application specific information (can be nil).
//   - length: desired length of the derived key in bytes.
//
// Returns the derived key, or an error if derivation fails.
func DeriveKeyHKDF(secret, salt []byte, info string, length int) ([]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("input key material (secret) must not be empty")
	}

	if length == 0 {
		return nil, fmt.Errorf("invalid length for derived key: %d", length)
	}

	hkdfObj := hkdf.New(sha256.New, secret, salt, nil)

	derivedKey := make([]byte, len(secret))
	if _, err := io.ReadFull(hkdfObj, derivedKey); err != nil {
		return nil, fmt.Errorf("hkdf failure: %w", err)
	}

	return derivedKey, nil
}
