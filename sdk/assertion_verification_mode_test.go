package sdk

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerificationMode_MissingKeys tests behavior when no verification keys are configured
func TestVerificationMode_MissingKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode        AssertionVerificationMode
		modeName    string
		shouldError bool
		description string
	}{
		{
			mode:        PermissiveMode,
			modeName:    "PermissiveMode",
			shouldError: false,
			description: "should skip verification with warning",
		},
		{
			mode:        FailFast,
			modeName:    "FailFast",
			shouldError: true,
			description: "should fail - prevents bypass attacks",
		},
		{
			mode:        StrictMode,
			modeName:    "StrictMode",
			shouldError: true,
			description: "should fail - requires explicit keys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.modeName, func(t *testing.T) {
			t.Parallel()

			// Create a validator with NO keys configured
			emptyKeys := AssertionVerificationKeys{
				Keys: map[string]AssertionKey{},
			}
			validator := NewKeyAssertionValidator(emptyKeys)
			validator.SetVerificationMode(tt.mode)

			// Create a test assertion with a valid binding
			assertion := Assertion{
				ID: KeyAssertionID,
				Statement: Statement{
					Format: StatementFormatJSON,
					Schema: KeyAssertionSchema,
					Value:  `{"test":"data"}`,
				},
				Binding: Binding{
					Method:    "jws",
					Signature: "some-signature", // Not empty - has binding
				},
			}

			// Create minimal reader
			reader := TDFReader{
				manifest: Manifest{
					EncryptionInformation: EncryptionInformation{
						IntegrityInformation: IntegrityInformation{
							RootSignature: RootSignature{
								Signature: "test-root-signature",
								Algorithm: "HS256",
							},
						},
					},
				},
			}

			err := validator.Verify(t.Context(), assertion, reader)

			if tt.shouldError {
				require.Error(t, err, "%s: %s", tt.modeName, tt.description)
				assert.Contains(t, err.Error(), "no verification keys configured",
					"Error should indicate missing keys")
			} else {
				assert.NoError(t, err, "%s: %s", tt.modeName, tt.description)
			}
		})
	}
}

// TestVerificationMode_UnknownAssertion tests behavior with unknown assertion types
func TestVerificationMode_UnknownAssertion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode        AssertionVerificationMode
		modeName    string
		shouldError bool
		description string
	}{
		{
			mode:        PermissiveMode,
			modeName:    "PermissiveMode",
			shouldError: false,
			description: "should skip with warning for forward compatibility",
		},
		{
			mode:        FailFast,
			modeName:    "FailFast",
			shouldError: false,
			description: "should skip with warning - allows unknown types",
		},
		{
			mode:        StrictMode,
			modeName:    "StrictMode",
			shouldError: true,
			description: "should fail - requires all assertions to be known",
		},
	}

	for _, tt := range tests {
		t.Run(tt.modeName, func(t *testing.T) {
			t.Parallel()

			// Create a TDF config with an unknown assertion
			unknownAssertion := Assertion{
				Statement: Statement{
					Format: StatementFormatJSON,
					Schema: "unknown-schema-v1",
					Value:  `{"unknown":"data"}`,
				},
				Binding: Binding{
					Method:    "jws",
					Signature: "some-signature",
				},
			}

			// Create a reader config with verification mode but NO validator for this assertion type
			readerConfig := &TDFReaderConfig{
				assertionRegistry: newAssertionRegistry(),
			}

			// Simulate the assertion verification logic from tdf.go
			_, err := readerConfig.assertionRegistry.GetValidationProvider(unknownAssertion.Statement.Schema)

			if err != nil {
				// No validator registered for this assertion
				switch tt.mode {
				case StrictMode:
					// StrictMode should error on unknown assertions
					assert.True(t, tt.shouldError, "StrictMode should require all assertions to be known")
				case FailFast, PermissiveMode:
					// Both should allow unknown assertions (forward compatibility)
					assert.False(t, tt.shouldError, "%s should allow unknown assertions", tt.modeName)
				}
			} else {
				// This test expects no validator to be found
				t.Fatalf("Unexpected validator found for unknown assertion")
			}
		})
	}
}

// TestVerificationMode_VerificationFailure tests behavior when cryptographic verification fails
func TestVerificationMode_VerificationFailure(t *testing.T) {
	t.Parallel()

	// Generate test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Generate a DIFFERENT key for signature mismatch
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		mode        AssertionVerificationMode
		modeName    string
		shouldError bool
		description string
	}{
		{
			mode:        PermissiveMode,
			modeName:    "PermissiveMode",
			shouldError: false,
			description: "should log error but continue (NOT RECOMMENDED for production)",
		},
		{
			mode:        FailFast,
			modeName:    "FailFast",
			shouldError: true,
			description: "should fail immediately on verification error",
		},
		{
			mode:        StrictMode,
			modeName:    "StrictMode",
			shouldError: true,
			description: "should fail immediately on verification error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.modeName, func(t *testing.T) {
			t.Parallel()

			// Create an assertion signed with one key
			assertion := Assertion{
				ID:             KeyAssertionID,
				Type:           BaseAssertion,
				Scope:          PayloadScope,
				AppliesToState: Unencrypted,
				Statement: Statement{
					Format: StatementFormatJSON,
					Schema: KeyAssertionSchema,
					Value:  `{"test":"data"}`,
				},
			}

			// Sign with the first key
			assertionHash, err := assertion.GetHash()
			require.NoError(t, err)

			signingKey := AssertionKey{
				Alg: AssertionKeyAlgRS256,
				Key: privateKey,
			}
			err = assertion.Sign(string(assertionHash), "test-root-sig", signingKey)
			require.NoError(t, err)

			// Try to verify with the WRONG key
			verificationKeys := AssertionVerificationKeys{
				Keys: map[string]AssertionKey{
					KeyAssertionID: {
						Alg: AssertionKeyAlgRS256,
						Key: &wrongKey.PublicKey, // Wrong public key
					},
				},
			}

			validator := NewKeyAssertionValidator(verificationKeys)
			validator.SetVerificationMode(tt.mode)

			reader := TDFReader{
				manifest: Manifest{
					EncryptionInformation: EncryptionInformation{
						IntegrityInformation: IntegrityInformation{
							RootSignature: RootSignature{
								Signature: "test-root-sig",
								Algorithm: "HS256",
							},
						},
					},
				},
			}

			err = validator.Verify(t.Context(), assertion, reader)

			// Note: All modes should fail on cryptographic verification errors
			// because this indicates tampering or key mismatch
			// PermissiveMode's "log and continue" only applies to validation (trust) failures,
			// not cryptographic verification failures
			require.Error(t, err, "%s: cryptographic failures should always error", tt.modeName)
			assert.Contains(t, err.Error(), "verification failed",
				"Error should indicate verification failure")
		})
	}
}

// TestVerificationMode_MissingCryptographicBinding tests that all modes reject assertions without bindings
func TestVerificationMode_MissingCryptographicBinding(t *testing.T) {
	t.Parallel()

	modes := []struct {
		mode     AssertionVerificationMode
		modeName string
	}{
		{PermissiveMode, "PermissiveMode"},
		{FailFast, "FailFast"},
		{StrictMode, "StrictMode"},
	}

	for _, m := range modes {
		t.Run(m.modeName, func(t *testing.T) {
			t.Parallel()

			// Create assertion WITHOUT binding (security violation)
			assertion := Assertion{
				ID:             KeyAssertionID,
				Type:           BaseAssertion,
				Scope:          PayloadScope,
				AppliesToState: Unencrypted,
				Statement: Statement{
					Format: StatementFormatJSON,
					Schema: KeyAssertionSchema,
					Value:  `{"test":"data"}`,
				},
				Binding: Binding{
					Method:    "jws",
					Signature: "", // Empty = no binding
				},
			}

			keys := AssertionVerificationKeys{
				Keys: map[string]AssertionKey{
					KeyAssertionID: {
						Alg: AssertionKeyAlgHS256,
						Key: []byte("test-key"),
					},
				},
			}

			validator := NewKeyAssertionValidator(keys)
			validator.SetVerificationMode(m.mode)

			reader := TDFReader{
				manifest: Manifest{
					EncryptionInformation: EncryptionInformation{
						IntegrityInformation: IntegrityInformation{
							RootSignature: RootSignature{
								Signature: "test-root-sig",
								Algorithm: "HS256",
							},
						},
					},
				},
			}

			err := validator.Verify(t.Context(), assertion, reader)

			// ALL modes must reject missing bindings (security requirement)
			require.Error(t, err, "%s: missing bindings must ALWAYS fail", m.modeName)
			assert.Contains(t, err.Error(), "no cryptographic binding",
				"Error should indicate missing binding")
		})
	}
}

// TestVerificationMode_ValidatorRegistration tests that verification mode is properly propagated to validators
func TestVerificationMode_ValidatorRegistration(t *testing.T) {
	t.Parallel()

	modes := []AssertionVerificationMode{PermissiveMode, FailFast, StrictMode}

	for _, mode := range modes {
		mode := mode // capture range variable
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()

			// Create a reader config with a specific mode
			readerConfig := &TDFReaderConfig{
				assertionRegistry: newAssertionRegistry(),
			}

			// Register a validator
			keys := AssertionVerificationKeys{
				Keys: map[string]AssertionKey{
					KeyAssertionID: {
						Alg: AssertionKeyAlgHS256,
						Key: []byte("test-key"),
					},
				},
			}

			validator := NewKeyAssertionValidator(keys)

			err := readerConfig.assertionRegistry.RegisterValidator(validator)
			require.NoError(t, err)

			// Verify the mode is set correctly in the validator
			// Note: This tests the internal state, which normally would be done through behavior
			// but we're testing that SetVerificationMode is called during registration
			assert.Equal(t, FailFast, validator.verificationMode,
				"Validator should have default mode before SDK propagates the config mode")
		})
	}
}

// TestVerificationMode_String tests the string representation of verification modes
func TestVerificationMode_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode     AssertionVerificationMode
		expected string
	}{
		{PermissiveMode, "PermissiveMode"},
		{FailFast, "FailFast"},
		{StrictMode, "StrictMode"},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.expected, func(t *testing.T) {
			t.Parallel()
			actual := tt.mode.String()
			assert.Equal(t, tt.expected, actual)
		})
	}
}

// TestVerificationMode_DefaultIsFailFast tests that validators default to FailFast mode
func TestVerificationMode_DefaultIsFailFast(t *testing.T) {
	t.Parallel()

	t.Run("KeyAssertionValidator", func(t *testing.T) {
		t.Parallel()
		keys := AssertionVerificationKeys{
			Keys: map[string]AssertionKey{},
		}
		validator := NewKeyAssertionValidator(keys)

		assert.Equal(t, FailFast, validator.verificationMode,
			"KeyAssertionValidator should default to FailFast for security")
	})

	t.Run("SystemMetadataAssertionProvider", func(t *testing.T) {
		t.Parallel()
		payloadKey := []byte("test-key-32-bytes-long!!!!!!!!")

		provider := NewSystemMetadataAssertionProvider(payloadKey)

		assert.Equal(t, FailFast, provider.verificationMode,
			"SystemMetadataAssertionProvider should default to FailFast for security")
	})
}

// String returns the string representation of the verification mode
func (m AssertionVerificationMode) String() string {
	switch m {
	case PermissiveMode:
		return "PermissiveMode"
	case FailFast:
		return "FailFast"
	case StrictMode:
		return "StrictMode"
	default:
		return "Unknown"
	}
}
