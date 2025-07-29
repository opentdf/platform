package ocrypto

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAESProtectedKey(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	protectedKey := NewAESProtectedKey(key)
	assert.NotNil(t, protectedKey)
	assert.Equal(t, key, protectedKey.rawKey)
}

func TestAESProtectedKey_DecryptAESGCM(t *testing.T) {
	// Generate a random 256-bit key
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	protectedKey := NewAESProtectedKey(key)

	// Test data
	plaintext := []byte("Hello, World!")

	// Encrypt the data first using the same key
	aesGcm, err := NewAESGcm(key)
	require.NoError(t, err)

	encrypted, err := aesGcm.Encrypt(plaintext)
	require.NoError(t, err)

	// Extract IV and ciphertext (first 12 bytes are IV for GCM standard nonce size)
	iv := encrypted[:GcmStandardNonceSize]
	ciphertext := encrypted[GcmStandardNonceSize:]

	// Test decryption
	decrypted, err := protectedKey.DecryptAESGCM(iv, ciphertext, 16) // 16 is standard GCM tag size
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAESProtectedKey_DecryptAESGCM_InvalidKey(t *testing.T) {
	// Empty key should fail
	protectedKey := NewAESProtectedKey([]byte{})

	iv := make([]byte, 12)
	ciphertext := make([]byte, 16)

	_, err := protectedKey.DecryptAESGCM(iv, ciphertext, 16)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create AES-GCM cipher")
}

func TestAESProtectedKey_Export_NoEncapsulator(t *testing.T) {
	key := []byte("test-key-1234567890123456") // 24 bytes
	protectedKey := NewAESProtectedKey(key)

	exported, err := protectedKey.Export(nil)
	require.NoError(t, err)
	assert.Equal(t, key, exported)
}

func TestAESProtectedKey_Export_WithEncapsulator(t *testing.T) {
	key := []byte("test-key-1234567890123456") // 24 bytes
	protectedKey := NewAESProtectedKey(key)

	// Mock encapsulator
	mockEncapsulator := &mockEncapsulator{
		encryptFunc: func(data []byte) ([]byte, error) {
			// Simple XOR encryption for testing
			result := make([]byte, len(data))
			for i, b := range data {
				result[i] = b ^ 0xFF
			}
			return result, nil
		},
	}

	exported, err := protectedKey.Export(mockEncapsulator)
	require.NoError(t, err)

	// Verify it was encrypted (should be different from original)
	assert.NotEqual(t, key, exported)
	assert.Len(t, exported, len(key))

	// Verify we can decrypt it back
	for i, b := range exported {
		assert.Equal(t, key[i], b^0xFF)
	}
}

func TestAESProtectedKey_Export_EncapsulatorError(t *testing.T) {
	key := []byte("test-key-1234567890123456")
	protectedKey := NewAESProtectedKey(key)

	mockEncapsulator := &mockEncapsulator{
		encryptFunc: func(_ []byte) ([]byte, error) {
			return nil, assert.AnError
		},
	}

	_, err := protectedKey.Export(mockEncapsulator)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to encrypt key data for export")
}

func TestAESProtectedKey_VerifyBinding(t *testing.T) {
	key := []byte("test-key-1234567890123456")
	protectedKey := NewAESProtectedKey(key)

	policy := []byte("test-policy-data")
	ctx := context.Background()

	// Generate the expected HMAC
	expectedHMAC := protectedKey.generateHMACDigest(policy)

	// Verify binding should succeed with correct HMAC
	err := protectedKey.VerifyBinding(ctx, policy, expectedHMAC)
	assert.NoError(t, err)
}

func TestAESProtectedKey_VerifyBinding_Mismatch(t *testing.T) {
	key := []byte("test-key-1234567890123456")
	protectedKey := NewAESProtectedKey(key)

	policy := []byte("test-policy-data")
	wrongBinding := []byte("wrong-binding-data")
	ctx := context.Background()

	err := protectedKey.VerifyBinding(ctx, policy, wrongBinding)
	require.Error(t, err)
	assert.Equal(t, ErrPolicyHMACMismatch, err)
}

func TestAESProtectedKey_VerifyBinding_EmptyKey(t *testing.T) {
	protectedKey := NewAESProtectedKey([]byte{})

	policy := []byte("test-policy-data")
	binding := []byte("some-binding")
	ctx := context.Background()

	err := protectedKey.VerifyBinding(ctx, policy, binding)
	require.Error(t, err)
	assert.Equal(t, ErrEmptyKeyData, err)
}

func TestAESProtectedKey_VerifyBinding_DifferentPolicyData(t *testing.T) {
	key := []byte("test-key-1234567890123456")
	protectedKey := NewAESProtectedKey(key)

	ctx := context.Background()

	// Generate HMAC for first policy
	policy1 := []byte("policy-data-1")
	hmac1 := protectedKey.generateHMACDigest(policy1)

	// Try to verify with different policy data
	policy2 := []byte("policy-data-2")
	err := protectedKey.VerifyBinding(ctx, policy2, hmac1)
	require.Error(t, err)
	assert.Equal(t, ErrPolicyHMACMismatch, err)
}

func TestAESProtectedKey_InterfaceCompliance(t *testing.T) {
	key := make([]byte, 32)
	protectedKey := NewAESProtectedKey(key)

	// Ensure it implements the ProtectedKey interface
	assert.Implements(t, (*ProtectedKey)(nil), protectedKey)
}

// Mock encapsulator for testing
type mockEncapsulator struct {
	encryptFunc      func([]byte) ([]byte, error)
	publicKeyPEMFunc func() (string, error)
	ephemeralKeyFunc func() []byte
}

func (m *mockEncapsulator) Encrypt(data []byte) ([]byte, error) {
	if m.encryptFunc != nil {
		return m.encryptFunc(data)
	}
	return data, nil
}

func (m *mockEncapsulator) PublicKeyInPemFormat() (string, error) {
	if m.publicKeyPEMFunc != nil {
		return m.publicKeyPEMFunc()
	}
	return "", nil
}

func (m *mockEncapsulator) EphemeralKey() []byte {
	if m.ephemeralKeyFunc != nil {
		return m.ephemeralKeyFunc()
	}
	return nil
}
