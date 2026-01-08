package ocrypto

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
)

var (
	// ErrEmptyKeyData is returned when the key data is empty
	ErrEmptyKeyData = errors.New("key data is empty")
	// ErrPolicyHMACMismatch is returned when policy binding verification fails
	ErrPolicyHMACMismatch = errors.New("policy HMAC mismatch")
)

// AESProtectedKey implements the ProtectedKey interface with an in-memory secret key
type AESProtectedKey struct {
	rawKey []byte
	aesGcm AesGcm
}

var _ ProtectedKey = (*AESProtectedKey)(nil)

// NewAESProtectedKey creates a new instance of AESProtectedKey
func NewAESProtectedKey(rawKey []byte) (*AESProtectedKey, error) {
	if len(rawKey) == 0 {
		return nil, ErrEmptyKeyData
	}
	// Create a defensive copy of the key
	keyCopy := append([]byte{}, rawKey...)

	// Pre-initialize the AES-GCM cipher for performance
	aesGcm, err := NewAESGcm(keyCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES-GCM cipher: %w", err)
	}

	return &AESProtectedKey{
		rawKey: keyCopy,
		aesGcm: aesGcm,
	}, nil
}

// DecryptAESGCM decrypts data using AES-GCM with the protected key
func (k *AESProtectedKey) DecryptAESGCM(iv []byte, body []byte, tagSize int) ([]byte, error) {
	// Use the pre-initialized AES-GCM cipher for better performance
	decryptedData, err := k.aesGcm.DecryptWithIVAndTagSize(iv, body, tagSize)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return decryptedData, nil
}

// Export returns the raw key data, optionally encrypting it with the provided Encapsulator
//
// Deprecated: Use the Encapsulator's Encapsulate method instead.
func (k *AESProtectedKey) Export(encapsulator Encapsulator) ([]byte, error) {
	if encapsulator == nil {
		// Return error if encapsulator is nil
		return nil, errors.New("encapsulator cannot be nil")
	}

	// Encrypt the key data before returning
	keyCopy := append([]byte{}, k.rawKey...)
	encryptedKey, err := encapsulator.Encrypt(keyCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key data for export: %w", err)
	}

	return encryptedKey, nil
}

// VerifyBinding checks if the policy binding matches the given policy data
func (k *AESProtectedKey) VerifyBinding(_ context.Context, policy, policyBinding []byte) error {
	actualHMAC := k.generateHMACDigest(policy)

	if !hmac.Equal(actualHMAC, policyBinding) {
		return ErrPolicyHMACMismatch
	}

	return nil
}

// generateHMACDigest is a helper to generate an HMAC digest from a message using the key
func (k *AESProtectedKey) generateHMACDigest(msg []byte) []byte {
	mac := hmac.New(sha256.New, k.rawKey)
	mac.Write(msg)
	return mac.Sum(nil)
}
