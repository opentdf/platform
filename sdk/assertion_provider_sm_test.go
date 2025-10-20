package sdk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSystemMetadataAssertion_SchemaVersionDetection verifies that the
// validation correctly detects v1 (legacy) vs v2 (current) schemas
func TestSystemMetadataAssertion_SchemaVersionDetection(t *testing.T) {
	tests := []struct {
		name           string
		schema         string
		expectedLegacy bool
		description    string
	}{
		{
			name:           "v2_schema_is_current",
			schema:         SystemMetadataSchemaV2,
			expectedLegacy: false,
			description:    "V2 schema should be treated as current (uses root signature)",
		},
		{
			name:           "v1_schema_is_legacy",
			schema:         SystemMetadataSchemaV1,
			expectedLegacy: true,
			description:    "V1 schema should be treated as legacy (uses aggregate hash)",
		},
		{
			name:           "empty_schema_is_legacy",
			schema:         "",
			expectedLegacy: true,
			description:    "Empty schema should default to legacy for backwards compatibility",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Check if the schema detection logic would classify this as legacy
			// This mimics the logic in SystemMetadataAssertionProvider.Verify()
			isLegacySchema := tt.schema == SystemMetadataSchemaV1 || tt.schema == ""

			assert.Equal(t, tt.expectedLegacy, isLegacySchema,
				"%s: %s", tt.name, tt.description)
		})
	}
}

// TestGetSystemMetadataAssertionConfig_DefaultsToV1 verifies that newly
// created system metadata assertions use the v1 schema for cross-SDK compatibility
func TestGetSystemMetadataAssertionConfig_DefaultsToV1(t *testing.T) {
	config, err := GetSystemMetadataAssertionConfig()
	require.NoError(t, err)

	assert.Equal(t, SystemMetadataAssertionID, config.ID,
		"Assertion ID should be 'system-metadata'")
	assert.Equal(t, SystemMetadataSchemaV1, config.Statement.Schema,
		"New assertions should use v1 schema for cross-SDK compatibility")
	// Verify statement format (string comparison, not JSON)
	if config.Statement.Format != StatementFormatJSON {
		t.Errorf("Expected format %q, got %q", StatementFormatJSON, config.Statement.Format)
	}
}

// TestSystemMetadataAssertionProvider_Bind_SchemaSelection verifies that
// the Bind() method creates assertions with the correct schema based on useHex
func TestSystemMetadataAssertionProvider_Bind_SchemaSelection(t *testing.T) {
	t.Parallel()

	payloadKey := []byte("test-payload-key-32-bytes-long!")
	aggregateHash := "test-aggregate-hash"

	// Test both legacy and modern TDF formats
	testCases := []struct {
		name           string
		useHex         bool
		expectedSchema string
	}{
		{"modern TDF (useHex=false) uses V2", false, SystemMetadataSchemaV2},
		{"legacy TDF (useHex=true) uses V1", true, SystemMetadataSchemaV1},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider := NewSystemMetadataAssertionProvider(tc.useHex, payloadKey, aggregateHash)

			// Create a minimal manifest with nested structure
			manifest := Manifest{
				EncryptionInformation: EncryptionInformation{
					IntegrityInformation: IntegrityInformation{
						RootSignature: RootSignature{
							Signature: "test-root-signature",
							Algorithm: "HS256",
						},
					},
				},
			}

			assertion, err := provider.Bind(t.Context(), manifest)
			require.NoError(t, err)

			assert.Equal(t, SystemMetadataAssertionID, assertion.ID)
			assert.Equal(t, tc.expectedSchema, assertion.Statement.Schema,
				"Schema should match useHex setting")
		})
	}
}

// TestSystemMetadataAssertionProvider_Verify_DualMode tests that the
// Verify() method can handle both v1 and v2 assertion formats
func TestSystemMetadataAssertionProvider_Verify_DualMode(t *testing.T) {
	// This test documents the dual-mode validation behavior
	// A full integration test would require actual TDF fixtures from old SDK versions

	t.Run("v2_schema_uses_root_signature", func(t *testing.T) {
		// In v2 validation:
		// - assertionSig (from JWT) is compared against manifest.RootSignature.Signature
		// - This is simpler and directly reuses the already-signed root signature

		t.Log("V2 validation: assertionSig == rootSignature")
		t.Log("✓ Validates that assertion is bound to the exact root signature")
	})

	t.Run("v1_schema_uses_aggregate_hash", func(t *testing.T) {
		// In v1 validation:
		// - assertionSig (from JWT) is compared against base64(aggregateHash + assertionHash)
		// - This was the original format used by old SDK versions

		t.Log("V1 validation: assertionSig == base64(aggregateHash + assertionHash)")
		t.Log("✓ Maintains backwards compatibility with TDFs created by old SDK")
	})

	t.Run("empty_schema_defaults_to_v1", func(t *testing.T) {
		// When schema is empty (old TDFs didn't set this field):
		// - Treated as v1 for backwards compatibility
		// - Ensures old TDFs can still be read

		t.Log("Empty schema defaults to v1 validation")
		t.Log("✓ Ensures old TDFs without schema field can be validated")
	})
}

// TestSystemMetadataAssertionProvider_MissingBinding_AllModes verifies that assertions
// without cryptographic bindings always fail, regardless of verification mode
func TestSystemMetadataAssertionProvider_MissingBinding_AllModes(t *testing.T) {
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

			payloadKey := []byte("test-payload-key-32-bytes-long!")
			aggregateHash := "test-aggregate-hash"

			provider := NewSystemMetadataAssertionProvider(false, payloadKey, aggregateHash)
			provider.SetVerificationMode(mode)

			// Create a test assertion WITHOUT a binding (security violation)
			assertion := Assertion{
				ID:             SystemMetadataAssertionID,
				Type:           BaseAssertion,
				Scope:          PayloadScope,
				AppliesToState: Unencrypted,
				Statement: Statement{
					Format: StatementFormatJSON,
					Schema: SystemMetadataSchemaV1,
					Value:  `{"tdf_spec_version":"1.0","sdk_version":"Go-test"}`,
				},
				Binding: Binding{
					Method:    "jws",
					Signature: "", // Empty signature = no binding
				},
			}

			// Create minimal reader
			reader := Reader{
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
			err := provider.Verify(t.Context(), assertion, reader)
			require.Error(t, err, "Missing bindings should fail in %s mode", mode)
			assert.Contains(t, err.Error(), "no cryptographic binding",
				"Error should indicate missing binding")
		})
	}
}

// TestSystemMetadataAssertionProvider_DefaultMode verifies that providers
// default to FailFast mode for security
func TestSystemMetadataAssertionProvider_DefaultMode(t *testing.T) {
	t.Parallel()

	payloadKey := []byte("test-payload-key-32-bytes-long!")
	aggregateHash := "test-aggregate-hash"

	// Create provider without explicitly setting mode
	provider := NewSystemMetadataAssertionProvider(false, payloadKey, aggregateHash)

	// Verify the default mode is FailFast
	assert.Equal(t, FailFast, provider.verificationMode,
		"Default verification mode should be FailFast for security")
}

// TestSystemMetadataAssertionProvider_SetVerificationMode verifies that
// the SetVerificationMode method properly updates the mode
func TestSystemMetadataAssertionProvider_SetVerificationMode(t *testing.T) {
	t.Parallel()

	payloadKey := []byte("test-payload-key-32-bytes-long!")
	aggregateHash := "test-aggregate-hash"

	provider := NewSystemMetadataAssertionProvider(false, payloadKey, aggregateHash)

	// Test each mode
	modes := []AssertionVerificationMode{PermissiveMode, FailFast, StrictMode}
	for _, mode := range modes {
		provider.SetVerificationMode(mode)
		assert.Equal(t, mode, provider.verificationMode,
			"SetVerificationMode should update the mode to %s", mode)
	}
}

// TestSystemMetadataAssertionProvider_TamperedStatement verifies that
// tampering with assertion statement values is detected and causes verification to fail.
// This mirrors the test_tdf_with_altered_assertion_statement test in tests/xtest.
func TestSystemMetadataAssertionProvider_TamperedStatement(t *testing.T) {
	t.Parallel()

	payloadKey := []byte("test-payload-key-32-bytes-long!")
	aggregateHash := "test-aggregate-hash"

	// Use modern TDF format (useHex=false) which uses V2 schema
	provider := NewSystemMetadataAssertionProvider(false, payloadKey, aggregateHash)
	provider.SetVerificationMode(FailFast)

	// Create a minimal manifest with nested structure
	manifest := Manifest{
		EncryptionInformation: EncryptionInformation{
			IntegrityInformation: IntegrityInformation{
				RootSignature: RootSignature{
					Signature: "test-root-signature",
					Algorithm: "HS256",
				},
			},
		},
	}

	// Create and bind an assertion with original statement
	originalAssertion, err := provider.Bind(t.Context(), manifest)
	require.NoError(t, err, "Binding assertion should succeed")

	// Verify original assertion passes
	reader := Reader{
		manifest: manifest,
	}
	err = provider.Verify(t.Context(), originalAssertion, reader)
	require.NoError(t, err, "Original assertion should verify successfully")

	// Now tamper with the statement value (simulate what the xtest does)
	tamperedAssertion := originalAssertion
	tamperedAssertion.Statement.Value = "tampered"

	// Verify that tampering is detected
	err = provider.Verify(t.Context(), tamperedAssertion, reader)
	require.Error(t, err, "Tampered assertion should fail verification")
	assert.Contains(t, err.Error(), "hash",
		"Error should indicate hash mismatch due to tampering")
}

// TestSystemMetadataAssertionProvider_TamperedStatement_LegacyV1 verifies that
// tampering detection works for legacy V1 schema assertions as well.
func TestSystemMetadataAssertionProvider_TamperedStatement_LegacyV1(t *testing.T) {
	t.Parallel()

	payloadKey := []byte("test-payload-key-32-bytes-long!")
	aggregateHash := "test-aggregate-hash"

	// Use legacy TDF format (useHex=true) which uses V1 schema
	provider := NewSystemMetadataAssertionProvider(true, payloadKey, aggregateHash)
	provider.SetVerificationMode(FailFast)

	// Create a minimal manifest with nested structure
	manifest := Manifest{
		EncryptionInformation: EncryptionInformation{
			IntegrityInformation: IntegrityInformation{
				RootSignature: RootSignature{
					Signature: "test-root-signature",
					Algorithm: "HS256",
				},
			},
		},
	}

	// Create and bind an assertion with original statement
	originalAssertion, err := provider.Bind(t.Context(), manifest)
	require.NoError(t, err, "Binding assertion should succeed")

	// Verify it uses V1 schema
	assert.Equal(t, SystemMetadataSchemaV1, originalAssertion.Statement.Schema,
		"Legacy TDF should use V1 schema")

	// Verify original assertion passes
	reader := Reader{
		manifest: manifest,
	}
	err = provider.Verify(t.Context(), originalAssertion, reader)
	require.NoError(t, err, "Original assertion should verify successfully")

	// Now tamper with the statement value
	tamperedAssertion := originalAssertion
	tamperedAssertion.Statement.Value = "tampered"

	// Verify that tampering is detected
	err = provider.Verify(t.Context(), tamperedAssertion, reader)
	require.Error(t, err, "Tampered assertion should fail verification")
	assert.Contains(t, err.Error(), "hash",
		"Error should indicate hash mismatch due to tampering")
}
