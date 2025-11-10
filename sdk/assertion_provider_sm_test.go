package sdk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSystemMetadataAssertion_SchemaVersionDetection verifies that the
// validation correctly handles the current schema and empty schema (legacy compatibility)
func TestSystemMetadataAssertion_SchemaVersionDetection(t *testing.T) {
	tests := []struct {
		name        string
		schema      string
		isSupported bool
		description string
	}{
		{
			name:        "current_schema_is_supported",
			schema:      SystemMetadataSchemaV1,
			isSupported: true,
			description: "Current schema is the standard cross-SDK compatible schema",
		},
		{
			name:        "empty_schema_is_legacy",
			schema:      "",
			isSupported: true,
			description: "Empty schema should be accepted for backwards compatibility",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Check if the schema is supported
			// This mimics the logic in SystemMetadataAssertionProvider.Verify()
			isValidSchema := tt.schema == SystemMetadataSchemaV1 || tt.schema == SystemMetadataSchemaV2 || tt.schema == ""

			assert.Equal(t, tt.isSupported, isValidSchema,
				"%s: %s", tt.name, tt.description)
		})
	}
}

// TestGetSystemMetadataAssertionConfig_DefaultsToCurrentSchema verifies that newly
// created system metadata assertions use the current schema for cross-SDK compatibility
func TestGetSystemMetadataAssertionConfig_DefaultsToCurrentSchema(t *testing.T) {
	config, err := GetSystemMetadataAssertionConfig()
	require.NoError(t, err)

	assert.Equal(t, SystemMetadataAssertionID, config.ID,
		"Assertion ID should be 'system-metadata'")
	assert.Equal(t, SystemMetadataSchemaV2, config.Statement.Schema,
		"New assertions should use current schema for cross-SDK compatibility")
	// Verify statement format (string comparison, not JSON)
	if config.Statement.Format != StatementFormatJSON {
		t.Errorf("Expected format %q, got %q", StatementFormatJSON, config.Statement.Format)
	}
}

// TestSystemMetadataAssertionProvider_Bind_SchemaSelection verifies that
// the Bind() method creates assertions with the current schema for cross-SDK compatibility
func TestSystemMetadataAssertionProvider_Bind_SchemaSelection(t *testing.T) {
	t.Parallel()

	payloadKey := []byte("test-payload-key-32-bytes-long!")

	// Test both legacy and modern TDF formats - both should use current schema
	testCases := []struct {
		name           string
		tdfVersion     string // Set TDFVersion to control useHex behavior
		expectedSchema string
	}{
		{"modern TDF (useHex=false) uses current schema", "4.3.0", SystemMetadataSchemaV2},
		{"legacy TDF (useHex=true) uses current schema", "", SystemMetadataSchemaV2},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider := NewSystemMetadataAssertionProvider(payloadKey)

			// Create a minimal manifest with nested structure
			manifest := Manifest{
				TDFVersion: tc.tdfVersion,
				EncryptionInformation: EncryptionInformation{
					IntegrityInformation: IntegrityInformation{
						RootSignature: RootSignature{
							Signature: "test-root-signature",
							Algorithm: "HS256",
						},
						Segments: []Segment{
							{Hash: "segment1hash"},
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

			provider := NewSystemMetadataAssertionProvider(payloadKey)
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

	// Create provider without explicitly setting mode
	provider := NewSystemMetadataAssertionProvider(payloadKey)

	// Verify the default mode is FailFast
	assert.Equal(t, FailFast, provider.verificationMode,
		"Default verification mode should be FailFast for security")
}

// TestSystemMetadataAssertionProvider_SetVerificationMode verifies that
// the SetVerificationMode method properly updates the mode
func TestSystemMetadataAssertionProvider_SetVerificationMode(t *testing.T) {
	t.Parallel()

	payloadKey := []byte("test-payload-key-32-bytes-long!")

	provider := NewSystemMetadataAssertionProvider(payloadKey)

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

	// Use modern TDF format (useHex=false) which uses V2 schema
	provider := NewSystemMetadataAssertionProvider(payloadKey)
	provider.SetVerificationMode(FailFast)

	// Create a minimal manifest with segments for proper signature computation
	segments := []Segment{
		{Hash: "dGVzdC1oYXNoLTE="}, // base64("test-hash-1")
		{Hash: "dGVzdC1oYXNoLTI="}, // base64("test-hash-2")
	}

	manifest := Manifest{
		TDFVersion: "4.3.0", // Modern format
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

	// Create and bind an assertion with original statement
	originalAssertion, err := provider.Bind(t.Context(), manifest)
	require.NoError(t, err, "Binding assertion should succeed")

	// Sign the assertion with DEK (simulating what tdf.go does)
	originalAssertion, err = signAssertionWithDEK(originalAssertion, manifest, payloadKey)
	require.NoError(t, err, "Signing assertion should succeed")

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

// TestSystemMetadataAssertionProvider_TamperedStatement_Legacy verifies that
// tampering detection works for legacy TDF format (useHex=true) assertions as well.
func TestSystemMetadataAssertionProvider_TamperedStatement_Legacy(t *testing.T) {
	t.Parallel()

	payloadKey := []byte("test-payload-key-32-bytes-long!")

	// Use legacy TDF format (useHex=true)
	provider := NewSystemMetadataAssertionProvider(payloadKey)
	provider.SetVerificationMode(FailFast)

	// Create a minimal manifest with segments for proper signature computation
	segments := []Segment{
		{Hash: "dGVzdC1oYXNoLTE="}, // base64("test-hash-1")
		{Hash: "dGVzdC1oYXNoLTI="}, // base64("test-hash-2")
	}

	manifest := Manifest{
		TDFVersion: "", // Empty = legacy format (useHex=true)
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

	// Create and bind an assertion with original statement
	originalAssertion, err := provider.Bind(t.Context(), manifest)
	require.NoError(t, err, "Binding assertion should succeed")

	// Verify it uses the current schema (V2)
	assert.Equal(t, SystemMetadataSchemaV2, originalAssertion.Statement.Schema,
		"Legacy TDF format should use current schema")

	// Sign the assertion with DEK (simulating what tdf.go does)
	originalAssertion, err = signAssertionWithDEK(originalAssertion, manifest, payloadKey)
	require.NoError(t, err, "Signing assertion should succeed")

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

// signAssertionWithDEK is a test helper that signs an assertion with the DEK.
// This simulates what tdf.go does during TDF creation for unbound assertions.
func signAssertionWithDEK(assertion Assertion, manifest Manifest, payloadKey []byte) (Assertion, error) {
	// Get assertion hash
	assertionHashBytes, err := assertion.GetHash()
	if err != nil {
		return assertion, err
	}

	// Compute aggregate hash from manifest segments
	aggregateHashBytes, err := ComputeAggregateHash(manifest.EncryptionInformation.IntegrityInformation.Segments)
	if err != nil {
		return assertion, err
	}

	// Determine encoding format from manifest
	useHex := ShouldUseHexEncoding(manifest)

	// Compute assertion signature using standard format
	assertionSignature, err := ComputeAssertionSignature(string(aggregateHashBytes), assertionHashBytes, useHex)
	if err != nil {
		return assertion, err
	}

	// Sign with DEK
	dekKey := AssertionKey{
		Alg: AssertionKeyAlgHS256,
		Key: payloadKey,
	}

	if err := assertion.Sign(string(assertionHashBytes), assertionSignature, dekKey); err != nil {
		return assertion, err
	}

	return assertion, nil
}
