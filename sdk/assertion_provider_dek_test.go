package sdk

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDEKAssertionBinding tests that assertions without explicit signing keys
// are correctly signed with the DEK during TDF creation.
// This is a regression test for the bug where manifest.RootSignature.Signature
// was incorrectly used instead of computing the proper assertion signature format.
func TestDEKAssertionBinding(t *testing.T) {
	tests := []struct {
		name       string
		tdfVersion string
		useHex     bool
	}{
		{
			name:       "TDF 4.3.0 format (raw bytes)",
			tdfVersion: "4.3.0",
			useHex:     false,
		},
		{
			name:       "Legacy TDF format (hex encoding)",
			tdfVersion: "", // Empty version = legacy TDF with hex encoding
			useHex:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a simple assertion without binding
			assertion := Assertion{
				ID:             "test-assertion-dek",
				Type:           "handling",
				Scope:          "tdo",
				AppliesToState: "encrypted",
				Statement: Statement{
					Format: "json+stanag5636",
					Schema: "urn:nato:stanag:5636:A:1:elements:json",
					Value:  `{"test":"value"}`,
				},
			}

			// Create mock manifest with segments
			payloadKey := make([]byte, 32)
			_, err := rand.Read(payloadKey)
			require.NoError(t, err)

			// Create test segments
			segments := []Segment{
				{Hash: base64.StdEncoding.EncodeToString([]byte("hash1"))},
				{Hash: base64.StdEncoding.EncodeToString([]byte("hash2"))},
			}

			manifest := Manifest{
				TDFVersion: tc.tdfVersion,
				EncryptionInformation: EncryptionInformation{
					IntegrityInformation: IntegrityInformation{
						RootSignature: RootSignature{
							Signature: "test-root-signature",
							Algorithm: "HS256",
						},
						Segments: segments,
					},
				},
			}

			// Get assertion hash
			assertionHashBytes, err := assertion.GetHash()
			require.NoError(t, err)

			// Compute aggregate hash
			aggregateHashBytes, err := ComputeAggregateHash(segments)
			require.NoError(t, err)

			// Compute expected assertion signature (the correct format)
			useHex := ShouldUseHexEncoding(manifest)
			assert.Equal(t, tc.useHex, useHex, "useHex flag should match test case")

			expectedSig, err := ComputeAssertionSignature(string(aggregateHashBytes), assertionHashBytes, useHex)
			require.NoError(t, err)

			// Sign the assertion with DEK (simulating what CreateTDF does)
			dekKey := AssertionKey{
				Alg: AssertionKeyAlgHS256,
				Key: payloadKey,
			}

			err = assertion.Sign(string(assertionHashBytes), expectedSig, dekKey)
			require.NoError(t, err)

			// Verify the assertion has a binding
			assert.False(t, assertion.Binding.IsEmpty(), "Assertion should have a binding")
			assert.Equal(t, "jws", assertion.Binding.Method, "Binding method should be jws")
			assert.NotEmpty(t, assertion.Binding.Signature, "Binding signature should not be empty")

			// Verify the assertion can be validated with the DEK
			validator := NewDEKAssertionValidator(dekKey)
			reader := Reader{manifest: manifest}

			err = validator.Verify(t.Context(), assertion, reader)
			assert.NoError(t, err, "DEK validator should successfully verify the assertion")
		})
	}
}

// TestDEKAssertionBinding_WrongSignatureFormat tests that using the wrong signature format
// (e.g., manifest.RootSignature.Signature instead of computed assertion signature) fails verification.
// This test documents the bug that was fixed.
func TestDEKAssertionBinding_WrongSignatureFormat(t *testing.T) {
	// Create a simple assertion without binding
	assertion := Assertion{
		ID:             "test-assertion-wrong-sig",
		Type:           "handling",
		Scope:          "tdo",
		AppliesToState: "encrypted",
		Statement: Statement{
			Format: "json+stanag5636",
			Schema: "urn:nato:stanag:5636:A:1:elements:json",
			Value:  `{"test":"value"}`,
		},
	}

	// Create mock manifest
	payloadKey := make([]byte, 32)
	_, err := rand.Read(payloadKey)
	require.NoError(t, err)

	segments := []Segment{
		{Hash: base64.StdEncoding.EncodeToString([]byte("hash1"))},
		{Hash: base64.StdEncoding.EncodeToString([]byte("hash2"))},
	}

	manifest := Manifest{
		TDFVersion: "4.3.0",
		EncryptionInformation: EncryptionInformation{
			IntegrityInformation: IntegrityInformation{
				RootSignature: RootSignature{
					Signature: "wrong-signature-format",
					Algorithm: "HS256",
				},
				Segments: segments,
			},
		},
	}

	// Get assertion hash
	assertionHashBytes, err := assertion.GetHash()
	require.NoError(t, err)

	// WRONG: Use manifest.RootSignature.Signature (this was the bug)
	wrongSig := manifest.Signature

	// Sign with the WRONG signature format
	dekKey := AssertionKey{
		Alg: AssertionKeyAlgHS256,
		Key: payloadKey,
	}

	err = assertion.Sign(string(assertionHashBytes), wrongSig, dekKey)
	require.NoError(t, err)

	// Verify the assertion - this SHOULD FAIL because we used the wrong signature format
	validator := NewDEKAssertionValidator(dekKey)
	reader := Reader{manifest: manifest}

	err = validator.Verify(t.Context(), assertion, reader)
	require.Error(t, err, "Verification should fail with wrong signature format")
	assert.Contains(t, err.Error(), "failed integrity check on assertion signature",
		"Error should indicate signature integrity check failure")
}
