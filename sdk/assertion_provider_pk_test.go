package sdk

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeyAssertionValidator_EmptyKeys_PermissiveMode verifies that validators
// with no keys configured skip validation with a warning in PermissiveMode
func TestKeyAssertionValidator_EmptyKeys_PermissiveMode(t *testing.T) {
	t.Parallel()

	// Create validator with empty keys
	emptyKeys := AssertionVerificationKeys{Keys: map[string]AssertionKey{}}
	validator := NewKeyAssertionValidator(emptyKeys)
	validator.SetVerificationMode(PermissiveMode)

	// Create a test assertion with a binding
	assertion := Assertion{
		ID:             KeyAssertionID,
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: StatementFormatJSON,
			Schema: KeyAssertionSchema,
			Value:  `{"algorithm":"RS256","key":"test-key"}`,
		},
		Binding: Binding{
			Method:    "jws",
			Signature: "fake-signature-for-testing",
		},
	}

	// Create minimal reader
	reader := &TDFReader{
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

	// Verify should succeed (skip) in PermissiveMode with empty keys
	err := validator.Verify(t.Context(), assertion, *reader)
	assert.NoError(t, err, "PermissiveMode should skip validation when keys are empty")
}

// TestKeyAssertionValidator_EmptyKeys_FailFast verifies that validators
// with no keys configured fail immediately in FailFast mode
func TestKeyAssertionValidator_EmptyKeys_FailFast(t *testing.T) {
	t.Parallel()

	// Create validator with empty keys
	emptyKeys := AssertionVerificationKeys{Keys: map[string]AssertionKey{}}
	validator := NewKeyAssertionValidator(emptyKeys)
	validator.SetVerificationMode(FailFast)

	// Create a test assertion with a binding
	assertion := Assertion{
		ID:             KeyAssertionID,
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: StatementFormatJSON,
			Schema: KeyAssertionSchema,
			Value:  `{"algorithm":"RS256","key":"test-key"}`,
		},
		Binding: Binding{
			Method:    "jws",
			Signature: "fake-signature-for-testing",
		},
	}

	// Create minimal reader
	reader := &TDFReader{
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

	// Verify should fail in FailFast mode with empty keys
	err := validator.Verify(t.Context(), assertion, *reader)
	require.Error(t, err, "FailFast mode should fail when keys are empty")
	assert.Contains(t, err.Error(), "no verification keys configured",
		"Error should indicate missing keys")
}

// TestKeyAssertionValidator_EmptyKeys_StrictMode verifies that validators
// with no keys configured fail immediately in StrictMode
func TestKeyAssertionValidator_EmptyKeys_StrictMode(t *testing.T) {
	t.Parallel()

	// Create validator with empty keys
	emptyKeys := AssertionVerificationKeys{Keys: map[string]AssertionKey{}}
	validator := NewKeyAssertionValidator(emptyKeys)
	validator.SetVerificationMode(StrictMode)

	// Create a test assertion with a binding
	assertion := Assertion{
		ID:             KeyAssertionID,
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: StatementFormatJSON,
			Schema: KeyAssertionSchema,
			Value:  `{"algorithm":"RS256","key":"test-key"}`,
		},
		Binding: Binding{
			Method:    "jws",
			Signature: "fake-signature-for-testing",
		},
	}

	// Create minimal reader
	reader := &TDFReader{
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

	// Verify should fail in StrictMode with empty keys
	err := validator.Verify(t.Context(), assertion, *reader)
	require.Error(t, err, "StrictMode should fail when keys are empty")
	assert.Contains(t, err.Error(), "no verification keys configured",
		"Error should indicate missing keys")
}

// TestKeyAssertionValidator_MissingBinding_AllModes verifies that assertions
// without cryptographic bindings always fail, regardless of verification mode
func TestKeyAssertionValidator_MissingBinding_AllModes(t *testing.T) {
	t.Parallel()

	modes := []AssertionVerificationMode{PermissiveMode, FailFast, StrictMode}

	modeNames := map[AssertionVerificationMode]string{
		PermissiveMode: "PermissiveMode",
		FailFast:       "FailFast",
		StrictMode:     "StrictMode",
	}

	for _, mode := range modes {
		mode := mode // capture range variable
		t.Run(modeNames[mode], func(t *testing.T) {
			t.Parallel()

			// Create validator with some keys
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)

			keys := AssertionVerificationKeys{
				Keys: map[string]AssertionKey{
					KeyAssertionID: {
						Alg: AssertionKeyAlgRS256,
						Key: &privateKey.PublicKey,
					},
				},
			}
			validator := NewKeyAssertionValidator(keys)
			validator.SetVerificationMode(mode)

			// Create a test assertion WITHOUT a binding (security violation)
			assertion := Assertion{
				ID:             KeyAssertionID,
				Type:           BaseAssertion,
				Scope:          PayloadScope,
				AppliesToState: Unencrypted,
				Statement: Statement{
					Format: StatementFormatJSON,
					Schema: KeyAssertionSchema,
					Value:  `{"algorithm":"RS256","key":"test-key"}`,
				},
				Binding: Binding{
					Method:    "jws",
					Signature: "", // Empty signature = no binding
				},
			}

			// Create minimal reader
			reader := &TDFReader{
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

			// Verify should ALWAYS fail when binding is missing
			err = validator.Verify(t.Context(), assertion, *reader)
			require.Error(t, err, "Missing bindings should fail in %s mode", mode)
			assert.Contains(t, err.Error(), "no cryptographic binding",
				"Error should indicate missing binding")
		})
	}
}

// TestKeyAssertionValidator_DefaultMode verifies that validators
// default to FailFast mode for security
func TestKeyAssertionValidator_DefaultMode(t *testing.T) {
	t.Parallel()

	// Create validator without setting mode
	emptyKeys := AssertionVerificationKeys{Keys: map[string]AssertionKey{}}
	validator := NewKeyAssertionValidator(emptyKeys)

	// Create a test assertion with a binding
	assertion := Assertion{
		ID:             KeyAssertionID,
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: StatementFormatJSON,
			Schema: KeyAssertionSchema,
			Value:  `{"algorithm":"RS256","key":"test-key"}`,
		},
		Binding: Binding{
			Method:    "jws",
			Signature: "fake-signature-for-testing",
		},
	}

	// Create minimal reader
	reader := &TDFReader{
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

	// Should fail (default is FailFast, not PermissiveMode)
	err := validator.Verify(t.Context(), assertion, *reader)
	require.Error(t, err, "Default mode should be FailFast (fail-secure)")
	assert.Contains(t, err.Error(), "no verification keys configured",
		"Error should indicate missing keys")
}

// TestKeyAssertionBinder_CreatesValidAssertion verifies that KeyAssertionBinder
// creates assertions with proper structure. The assertion is returned unsigned
// and the caller is responsible for signing it.
func TestKeyAssertionBinder_CreatesValidAssertion(t *testing.T) {
	t.Parallel()

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	assertionKey := AssertionKey{
		Alg: AssertionKeyAlgRS256,
		Key: privateKey,
	}

	publicKey := AssertionKey{
		Alg: AssertionKeyAlgRS256,
		Key: &privateKey.PublicKey,
	}

	// Statement value can be empty or contain custom data
	binder := NewKeyAssertionBinder(assertionKey, publicKey, "")

	// Create a minimal manifest
	manifest := Manifest{
		EncryptionInformation: EncryptionInformation{
			IntegrityInformation: IntegrityInformation{
				RootSignature: RootSignature{
					Signature: "test-root-signature",
					Algorithm: "RS256",
				},
			},
		},
	}

	// Compute payload hash from manifest
	payloadHash, err := manifest.ComputeAggregateHash()
	require.NoError(t, err)

	// Bind the assertion (returns unsigned assertion)
	assertion, err := binder.Bind(t.Context(), payloadHash)
	require.NoError(t, err)

	// Verify assertion structure
	assert.Equal(t, KeyAssertionID, assertion.ID)
	assert.Equal(t, BaseAssertion, assertion.Type)
	assert.Equal(t, PayloadScope, assertion.Scope)
	assert.Equal(t, Unencrypted, assertion.AppliesToState)
	assert.Equal(t, KeyAssertionSchema, assertion.Statement.Schema)

	// Bind returns unsigned assertions - caller is responsible for signing
	assert.True(t, assertion.Binding.IsEmpty(), "Assertion should be unsigned after Bind")
}
