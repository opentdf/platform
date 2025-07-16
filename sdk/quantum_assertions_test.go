package sdk

import (
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithQuantumResistantAssertions(t *testing.T) {
	// Test the TDF option
	config, err := newTDFConfig(WithQuantumResistantAssertions())
	require.NoError(t, err)
	assert.True(t, config.useQuantumAssertions, "useQuantumAssertions should be true")
}

func TestGenerateMLDSAKeyPair(t *testing.T) {
	key, err := GenerateMLDSAKeyPair()
	require.NoError(t, err)

	assert.Equal(t, AssertionKeyAlgMLDSA44, key.Alg)
	assert.NotNil(t, key.Key)

	// Verify it's actually an ML-DSA private key
	_, ok := key.Key.(*mldsa44.PrivateKey)
	assert.True(t, ok, "Key should be an ML-DSA-44 private key")
}

func TestGetQuantumSafeSystemMetadataAssertionConfig(t *testing.T) {
	config, err := GetQuantumSafeSystemMetadataAssertionConfig()
	require.NoError(t, err)

	// Should have the same basic structure as regular system metadata
	assert.Equal(t, SystemMetadataAssertionID, config.ID)
	assert.Equal(t, BaseAssertion, config.Type)
	assert.Equal(t, PayloadScope, config.Scope)
	assert.Equal(t, Unencrypted, config.AppliesToState)

	// But should have an ML-DSA signing key
	assert.Equal(t, AssertionKeyAlgMLDSA44, config.SigningKey.Alg)
	assert.NotNil(t, config.SigningKey.Key)

	// Verify it's actually an ML-DSA private key
	_, ok := config.SigningKey.Key.(*mldsa44.PrivateKey)
	assert.True(t, ok, "Signing key should be an ML-DSA-44 private key")
}

func TestQuantumAssertionSigningAndVerification(t *testing.T) {
	// Create a quantum-safe assertion config
	config, err := GetQuantumSafeSystemMetadataAssertionConfig()
	require.NoError(t, err)

	// Create an assertion from the config
	assertion := Assertion{
		ID:             config.ID,
		Type:           config.Type,
		Scope:          config.Scope,
		AppliesToState: config.AppliesToState,
		Statement:      config.Statement,
	}

	// Sign the assertion
	hash := "test-hash"
	sig := "test-signature"
	err = assertion.Sign(hash, sig, config.SigningKey)
	require.NoError(t, err)

	// Verify the signature is present
	assert.NotEmpty(t, assertion.Binding.Signature)
	assert.Equal(t, "jws", assertion.Binding.Method)

	// Create verification key from the private key
	privateKey := config.SigningKey.Key.(*mldsa44.PrivateKey)
	publicKey := privateKey.Public().(*mldsa44.PublicKey)

	verificationKey := AssertionKey{
		Alg: AssertionKeyAlgMLDSA44,
		Key: publicKey,
	}

	// Verify the assertion
	verifiedHash, verifiedSig, err := assertion.Verify(verificationKey)
	require.NoError(t, err)

	assert.Equal(t, hash, verifiedHash)
	assert.Equal(t, sig, verifiedSig)
}
