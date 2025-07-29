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
	ErrPolicyHMACMismatch = errors.New("policy hmac mismatch")
	// ErrHMACGeneration is returned when HMAC digest generation fails
	ErrHMACGeneration = errors.New("failed to generate hmac digest")
)

// AESProtectedKey implements the ProtectedKey interface with an in-memory secret key
type AESProtectedKey struct {
	rawKey []byte
}

var _ ProtectedKey = (*AESProtectedKey)(nil)

// NewAESProtectedKey creates a new instance of AESProtectedKey
func NewAESProtectedKey(rawKey []byte) *AESProtectedKey {
	return &AESProtectedKey{
		rawKey: rawKey,
	}
}

// DecryptAESGCM decrypts data using AES-GCM with the protected key
func (k *AESProtectedKey) DecryptAESGCM(iv []byte, body []byte, tagSize int) ([]byte, error) {
	aesGcm, err := NewAESGcm(k.rawKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM cipher: %w", err)
	}

	decryptedData, err := aesGcm.DecryptWithIVAndTagSize(iv, body, tagSize)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return decryptedData, nil
}

// Export returns the raw key data, optionally encrypting it with the provided Encapsulator
// Deprecated: Use the Encapsulator's Encapsulate method instead
func (k *AESProtectedKey) Export(encapsulator Encapsulator) ([]byte, error) {
	if encapsulator == nil {
		// Return raw key data without encryption - caller should be aware of this
		return k.rawKey, nil
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
func (k *AESProtectedKey) VerifyBinding(ctx context.Context, policy, policyBinding []byte) error {
	if len(k.rawKey) == 0 {
		return ErrEmptyKeyData
	}

	actualHMAC, err := k.generateHMACDigest(ctx, policy)
	if err != nil {
		return fmt.Errorf("unable to generate policy hmac: %w", err)
	}

	if !hmac.Equal(actualHMAC, policyBinding) {
		return ErrPolicyHMACMismatch
	}

	return nil
}

// generateHMACDigest is a helper to generate an HMAC digest from a message using the key
func (k *AESProtectedKey) generateHMACDigest(ctx context.Context, msg []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, k.rawKey)
	_, err := mac.Write(msg)
	if err != nil {
		return nil, ErrHMACGeneration
	}
	return mac.Sum(nil), nil
}
