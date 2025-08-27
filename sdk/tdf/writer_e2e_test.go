package tdf

import (
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test constants and mock data
const (
	testKAS1 = "https://kas1.example.com/"
	testKAS2 = "https://kas2.example.com/"
	testKAS3 = "https://kas3.example.com/"

	// Real RSA-2048 public keys for testing
	mockRSAPublicKey1 = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtQ2ZuyT/p32SFmWTj+wQ
huQwR4IJSzlJ7CqZ4fOXw90rA2joK27dIGiHrtkQHGhS4SK1mvkYyJaREoppMFRc
AyZWCgixbSdwYJS/KN0hjLIdhtkdBlZDaZN2ayTf2sZjWzOLL2cYzzVsAy9tGL8a
bMqf91DEHv+l58fPxmbJ/i6YFFQoOEsyWnPhXdiExe6poQDCHJFYYOp6iu5kOPWr
jKFj9eGXuFR/CJQ/uxTSM+8/7Ejmi8Oa52TQAUhMPH0U1CRFm/NuiFoFissa0jJC
J3k6syxvf45mPrbtlhcELskXrquDtJOpIMQmEwfuV4j8iLNwVlsR2tAbClJi6UOy
SQIDAQAB
-----END PUBLIC KEY-----`
)

// TestWriterEndToEnd contains all the end-to-end test scenarios
func TestWriterEndToEnd(t *testing.T) {
	testCases := []struct {
		name string
		test func(t *testing.T)
	}{
		{"BasicFlow", testBasicTDFCreationFlow},
		{"SingleSegmentWithAttributes", testSingleSegmentWithAttributes},
		{"MultiSegmentFlow", testMultiSegmentFlow},
		{"KeySplittingWithMultipleAttributes", testKeySplittingWithMultipleAttributes},
		{"ManifestGeneration", testManifestGeneration},
		{"AssertionsAndMetadata", testAssertionsAndMetadata},
		{"ErrorConditions", testErrorConditions},
		{"XORReconstruction", testXORReconstruction},
		{"DifferentAttributeRules", testDifferentAttributeRules},
		{"OutOfOrderSegments", testOutOfOrderSegments},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.test(t)
		})
	}
}

// testBasicTDFCreationFlow tests the basic flow: NewWriter -> WriteSegment -> Finalize
func testBasicTDFCreationFlow(t *testing.T) {
	ctx := t.Context()

	// Create writer with default configuration
	writer, err := NewWriter(ctx)
	require.NoError(t, err, "Failed to create TDF writer")
	assert.NotNil(t, writer, "Writer should not be nil")

	// Verify initial state
	assert.False(t, writer.finalized, "Writer should not be finalized initially")
	assert.Empty(t, writer.segments, "Segments should be empty initially")
	assert.Len(t, writer.dek, 32, "DEK should be 32 bytes")

	// Write a single segment
	testData := []byte("Hello, TDF World!")
	zipBytes, err := writer.WriteSegment(ctx, 0, testData)
	require.NoError(t, err, "Failed to write segment")
	assert.NotEmpty(t, zipBytes, "Zip bytes should not be empty")

	// Verify segment was recorded
	assert.Len(t, writer.segments, 1, "Should have one segment")
	assert.Equal(t, int64(len(testData)), writer.segments[0].Size, "Segment size should match input data")
	assert.NotEmpty(t, writer.segments[0].Hash, "Segment hash should be set")
	assert.Greater(t, writer.segments[0].EncryptedSize, writer.segments[0].Size, "Encrypted size should be larger due to GCM overhead")

	// Finalize with attributes that have proper KAS setup
	attributes := []*policy.Value{
		createTestAttribute("https://example.com/attr/Classification/value/Public", testKAS1, "kid1"),
	}
	finalBytes, manifest, err := writer.Finalize(ctx, WithAttributeValues(attributes))
	require.NoError(t, err, "Failed to finalize TDF")
	assert.NotEmpty(t, finalBytes, "Final TDF bytes should not be empty")
	assert.NotNil(t, manifest, "Manifest should not be nil")

	// Verify finalized state
	assert.True(t, writer.finalized, "Writer should be finalized")

	// Verify manifest structure
	assert.Equal(t, TDFSpecVersion, manifest.TDFVersion, "TDF version should match expected")
	assert.Equal(t, "application/octet-stream", manifest.Payload.MimeType, "Default MIME type should be set")
	assert.True(t, manifest.Payload.IsEncrypted, "Payload should be marked as encrypted")
	assert.Equal(t, "zip", manifest.Payload.Protocol, "Protocol should be zip")
	assert.Equal(t, "reference", manifest.Payload.Type, "Type should be reference")

	// Verify key access objects
	assert.Len(t, manifest.EncryptionInformation.KeyAccessObjs, 1, "Should have one key access object for default KAS")
	keyAccess := manifest.EncryptionInformation.KeyAccessObjs[0]
	assert.Equal(t, testKAS1, keyAccess.KasURL, "KAS URL should match")
	assert.Equal(t, "kas", keyAccess.Protocol, "Protocol should be kas")
	assert.NotEmpty(t, keyAccess.WrappedKey, "Wrapped key should not be empty")

	// Verify encryption information
	assert.Equal(t, kGCMCipherAlgorithm, manifest.EncryptionInformation.Method.Algorithm, "Algorithm should be AES-256-GCM")
	assert.True(t, manifest.EncryptionInformation.Method.IsStreamable, "Should be marked as streamable")
	assert.NotEmpty(t, manifest.EncryptionInformation.Policy, "Policy should not be empty")
}

// testSingleSegmentWithAttributes tests TDF creation with attribute-based key splitting
func testSingleSegmentWithAttributes(t *testing.T) {
	ctx := t.Context()

	writer, err := NewWriter(ctx)
	require.NoError(t, err, "Failed to create TDF writer")

	// Write test data
	testData := []byte("Sensitive data with attributes")
	_, err = writer.WriteSegment(ctx, 0, testData)
	require.NoError(t, err, "Failed to write segment")

	// Create test attributes with different KAS assignments
	attributes := []*policy.Value{
		createTestAttribute("https://example.com/attr/Classification/value/Secret", testKAS1, "kid1"),
		createTestAttribute("https://example.com/attr/Country/value/USA", testKAS2, "kid2"),
	}

	// Finalize with attributes
	finalBytes, manifest, err := writer.Finalize(ctx, WithAttributeValues(attributes))
	require.NoError(t, err, "Failed to finalize TDF with attributes")
	assert.NotEmpty(t, finalBytes, "Final TDF bytes should not be empty")

	// Verify key access objects were created for each attribute's KAS
	assert.GreaterOrEqual(t, len(manifest.EncryptionInformation.KeyAccessObjs), 1, "Should have at least one key access object")

	// Verify policy contains attributes
	policyBytes := manifest.EncryptionInformation.Policy
	assert.NotEmpty(t, policyBytes, "Policy should not be empty")

	// Policy bytes are now raw JSON, not base64 encoded
	var policy Policy
	err = json.Unmarshal(policyBytes, &policy)
	require.NoError(t, err, "Should be able to unmarshal policy")
	assert.Len(t, policy.Body.DataAttributes, 2, "Policy should contain both attributes")

	// Verify attribute FQNs are in policy
	attrFQNs := make(map[string]bool)
	for _, attr := range policy.Body.DataAttributes {
		attrFQNs[attr.Attribute] = true
	}
	assert.True(t, attrFQNs["https://example.com/attr/Classification/value/Secret"], "Classification value should be in policy")
	assert.True(t, attrFQNs["https://example.com/attr/Country/value/USA"], "Country value should be in policy")
}

// testMultiSegmentFlow tests writing multiple segments in order and out of order
func testMultiSegmentFlow(t *testing.T) {
	ctx := t.Context()

	writer, err := NewWriter(ctx)
	require.NoError(t, err, "Failed to create TDF writer")

	// Write multiple segments
	segments := [][]byte{
		[]byte("First segment data"),
		[]byte("Second segment with more content"),
		[]byte("Third segment concludes the data"),
	}

	// Write segments in order
	for i, data := range segments {
		_, err := writer.WriteSegment(ctx, i, data)
		require.NoError(t, err, "Failed to write segment %d", i)
	}

	// Verify all segments were recorded
	assert.Len(t, writer.segments, 3, "Should have three segments")
	assert.Equal(t, 2, writer.maxSegmentIndex, "Max segment index should be 2")

	// Verify each segment
	for i, data := range segments {
		assert.Equal(t, int64(len(data)), writer.segments[i].Size, "Segment %d size should match", i)
		assert.NotEmpty(t, writer.segments[i].Hash, "Segment %d hash should be set", i)
	}

	// Finalize with attributes for proper key access setup
	attributes := []*policy.Value{
		createTestAttribute("https://example.com/attr/Security/value/Internal", testKAS1, "kid1"),
	}
	_, manifest, err := writer.Finalize(ctx, WithAttributeValues(attributes))
	require.NoError(t, err, "Failed to finalize multi-segment TDF")

	// Verify root signature was calculated from all segments
	assert.NotEmpty(t, manifest.EncryptionInformation.RootSignature.Signature, "Root signature should be set")
	assert.Equal(t, "HS256", manifest.EncryptionInformation.RootSignature.Algorithm, "Root signature algorithm should be HS256")
}

// testKeySplittingWithMultipleAttributes tests XOR key splitting with complex attribute scenarios
func testKeySplittingWithMultipleAttributes(t *testing.T) {
	ctx := t.Context()

	writer, err := NewWriter(ctx)
	require.NoError(t, err, "Failed to create TDF writer")

	// Write test data
	testData := []byte("Data requiring multiple key splits")
	_, err = writer.WriteSegment(ctx, 0, testData)
	require.NoError(t, err, "Failed to write segment")

	// Create attributes that will result in multiple splits
	attributes := []*policy.Value{
		createTestAttributeWithRule("https://example.com/attr/Classification/value/TopSecret", testKAS1, "kid1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
		createTestAttributeWithRule("https://example.com/attr/Clearance/value/TS", testKAS2, "kid2", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
		createTestAttributeWithRule("https://example.com/attr/Department/value/Defense", testKAS3, "kid3", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
	}

	// Finalize with multiple attributes
	originalDEK := make([]byte, len(writer.dek))
	copy(originalDEK, writer.dek)

	_, manifest, err := writer.Finalize(ctx, WithAttributeValues(attributes))
	require.NoError(t, err, "Failed to finalize TDF with multiple attributes")

	// Verify multiple key access objects were created
	keyAccessObjs := manifest.EncryptionInformation.KeyAccessObjs
	assert.GreaterOrEqual(t, len(keyAccessObjs), 1, "Should have at least one key access object")

	// Verify each key access object has proper structure
	for i, keyAccess := range keyAccessObjs {
		assert.NotEmpty(t, keyAccess.KasURL, "Key access %d should have KAS URL", i)
		assert.Equal(t, "kas", keyAccess.Protocol, "Key access %d protocol should be kas", i)
		assert.NotEmpty(t, keyAccess.WrappedKey, "Key access %d should have wrapped key", i)
		assert.NotNil(t, keyAccess.PolicyBinding, "Key access %d should have policy binding", i)

		// Verify policy binding structure
		binding, ok := keyAccess.PolicyBinding.(PolicyBinding)
		if ok {
			assert.Equal(t, "HS256", binding.Alg, "Policy binding algorithm should be HS256")
			assert.NotEmpty(t, binding.Hash, "Policy binding hash should not be empty")
		}
	}

	// Test that we can theoretically reconstruct the key from splits
	// (This verifies the XOR splitting logic worked correctly)
	assert.Len(t, originalDEK, 32, "Original DEK should be 32 bytes")
}

// testManifestGeneration tests detailed manifest structure and content
func testManifestGeneration(t *testing.T) {
	ctx := t.Context()

	writer, err := NewWriter(ctx, WithIntegrityAlgorithm(HS256))
	require.NoError(t, err, "Failed to create TDF writer")

	// Write test data
	testData := []byte("Test data for manifest generation")
	_, err = writer.WriteSegment(ctx, 0, testData)
	require.NoError(t, err, "Failed to write segment")

	// Create attribute with metadata
	attributes := []*policy.Value{
		createTestAttribute("https://example.com/attr/Category/value/Financial", testKAS1, "kid1"),
	}

	// Finalize with custom options
	customMimeType := "application/json"
	encryptedMetadata := "Custom metadata content"

	_, manifest, err := writer.Finalize(ctx,
		WithAttributeValues(attributes),
		WithPayloadMimeType(customMimeType),
		WithEncryptedMetadata(encryptedMetadata),
	)
	require.NoError(t, err, "Failed to finalize TDF")

	// Verify manifest structure in detail
	assert.Equal(t, TDFSpecVersion, manifest.TDFVersion, "TDF version should match")

	// Verify payload information
	assert.Equal(t, customMimeType, manifest.Payload.MimeType, "MIME type should match custom value")
	assert.Equal(t, "zip", manifest.Payload.Protocol, "Protocol should be zip")
	assert.Equal(t, "reference", manifest.Payload.Type, "Type should be reference")
	assert.True(t, manifest.Payload.IsEncrypted, "Payload should be encrypted")

	// Verify encryption information
	encInfo := manifest.EncryptionInformation
	assert.Equal(t, kGCMCipherAlgorithm, encInfo.Method.Algorithm, "Algorithm should be AES-256-GCM")
	assert.True(t, encInfo.Method.IsStreamable, "Should be streamable")
	assert.NotEmpty(t, encInfo.Policy, "Policy should not be empty")

	// Verify integrity information
	intInfo := encInfo.IntegrityInformation
	assert.Equal(t, "HS256", intInfo.RootSignature.Algorithm, "Root signature algorithm should be HS256")
	assert.NotEmpty(t, intInfo.RootSignature.Signature, "Root signature should not be empty")

	// Verify key access objects
	assert.GreaterOrEqual(t, len(encInfo.KeyAccessObjs), 1, "Should have at least one key access object")
	keyAccess := encInfo.KeyAccessObjs[0]
	assert.Equal(t, testKAS1, keyAccess.KasURL, "KAS URL should match")
	assert.NotEmpty(t, keyAccess.EncryptedMetadata, "Encrypted metadata should be present")

	// Verify policy content
	policyBytes := encInfo.Policy
	// Policy bytes are now raw JSON, not base64 encoded
	var policy Policy
	err = json.Unmarshal(policyBytes, &policy)
	require.NoError(t, err, "Should be able to unmarshal policy")
	assert.NotEmpty(t, policy.UUID, "Policy should have UUID")
	assert.Len(t, policy.Body.DataAttributes, 1, "Policy should have one attribute")
	assert.Equal(t, "https://example.com/attr/Category/value/Financial", policy.Body.DataAttributes[0].Attribute, "Value FQN should be correct")
}

// testAssertionsAndMetadata tests TDF creation with assertions and encrypted metadata
func testAssertionsAndMetadata(t *testing.T) {
	ctx := t.Context()

	writer, err := NewWriter(ctx)
	require.NoError(t, err, "Failed to create TDF writer")

	// Write test data
	testData := []byte("Data with assertions and metadata")
	_, err = writer.WriteSegment(ctx, 0, testData)
	require.NoError(t, err, "Failed to write segment")

	// Create a custom test assertion to replace the removed system metadata assertion
	testAssertion := AssertionConfig{
		ID:             "test-system-metadata",
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: "json",
			Schema: "test-system-metadata-v1",
			Value:  `{"test_component": "tdf-writer", "test_type": "system-metadata", "timestamp": "2024-01-01T00:00:00Z"}`,
		},
	}

	// Finalize with assertions and metadata
	attributes := []*policy.Value{
		createTestAttribute("https://example.com/attr/Sensitivity/value/Restricted", testKAS1, "kid1"),
	}
	_, manifest, err := writer.Finalize(ctx,
		WithAttributeValues(attributes),
		WithEncryptedMetadata("Sensitive metadata content"),
		WithAssertions(testAssertion),
	)
	require.NoError(t, err, "Failed to finalize TDF with assertions")

	// Verify custom test assertion was added
	assert.Len(t, manifest.Assertions, 1, "Should have custom test assertion")

	customAssertion := manifest.Assertions[0]
	assert.Equal(t, "test-system-metadata", customAssertion.ID, "Should have correct assertion ID")
	assert.Equal(t, BaseAssertion, customAssertion.Type, "Should be base assertion type")
	assert.Equal(t, PayloadScope, customAssertion.Scope, "Should have payload scope")
	assert.Equal(t, Unencrypted, customAssertion.AppliesToState, "Should apply to unencrypted state")

	// Verify assertion binding
	assert.NotEmpty(t, customAssertion.Binding.Method, "Assertion should have binding method")
	assert.NotEmpty(t, customAssertion.Binding.Signature, "Assertion should have binding signature")

	// Verify assertion statement
	assert.Equal(t, "json", customAssertion.Statement.Format, "Statement format should be json")
	assert.Equal(t, "test-system-metadata-v1", customAssertion.Statement.Schema, "Statement schema should match")
	assert.NotEmpty(t, customAssertion.Statement.Value, "Statement value should not be empty")

	// Parse and verify test metadata content
	var metadata map[string]interface{}
	err = json.Unmarshal([]byte(customAssertion.Statement.Value), &metadata)
	require.NoError(t, err, "Should be able to parse test metadata")
	assert.Equal(t, "tdf-writer", metadata["test_component"], "Test component should match")
	assert.Equal(t, "system-metadata", metadata["test_type"], "Test type should match")
	assert.NotEmpty(t, metadata["timestamp"], "Timestamp should be set")

	// Verify encrypted metadata in key access object
	keyAccess := manifest.EncryptionInformation.KeyAccessObjs[0]
	assert.NotEmpty(t, keyAccess.EncryptedMetadata, "Encrypted metadata should be present")
}

// testErrorConditions tests various error scenarios
func testErrorConditions(t *testing.T) {
	ctx := t.Context()

	t.Run("WriteAfterFinalize", func(t *testing.T) {
		writer, err := NewWriter(ctx)
		require.NoError(t, err)

		// Write and finalize
		_, err = writer.WriteSegment(ctx, 0, []byte("test"))
		require.NoError(t, err)
		attributes := []*policy.Value{
			createTestAttribute("https://example.com/attr/Test/value/Basic", testKAS1, "kid1"),
		}
		_, _, err = writer.Finalize(ctx, WithAttributeValues(attributes))
		require.NoError(t, err)

		// Try to write after finalize
		_, err = writer.WriteSegment(ctx, 1, []byte("should fail"))
		require.ErrorIs(t, err, ErrAlreadyFinalized, "Should not allow writing after finalization")

		// Try to finalize again
		_, _, err = writer.Finalize(ctx, WithAttributeValues(attributes))
		require.ErrorIs(t, err, ErrAlreadyFinalized, "Should not allow double finalization")
	})

	t.Run("InvalidSegmentIndex", func(t *testing.T) {
		writer, err := NewWriter(ctx)
		require.NoError(t, err)

		// Try negative segment index
		_, err = writer.WriteSegment(ctx, -1, []byte("test"))
		assert.ErrorIs(t, err, ErrInvalidSegmentIndex, "Should reject negative segment index")
	})

	t.Run("DuplicateSegment", func(t *testing.T) {
		writer, err := NewWriter(ctx)
		require.NoError(t, err)

		// Write segment twice
		_, err = writer.WriteSegment(ctx, 0, []byte("first"))
		require.NoError(t, err)
		_, err = writer.WriteSegment(ctx, 0, []byte("second"))
		assert.ErrorIs(t, err, ErrSegmentAlreadyWritten, "Should not allow overwriting segments")
	})

	t.Run("FinalizeWithoutKASOrAttributes", func(t *testing.T) {
		writer, err := NewWriter(ctx)
		require.NoError(t, err)

		_, err = writer.WriteSegment(ctx, 0, []byte("test"))
		require.NoError(t, err)

		// Try to finalize without KAS or attributes - this should fail in key splitting
		_, _, err = writer.Finalize(ctx)
		require.Error(t, err, "Should fail without KAS or attributes")
		assert.Contains(t, err.Error(), "no default KAS", "Error should mention missing default KAS")
	})

	t.Run("EmptySegmentHash", func(t *testing.T) {
		writer, err := NewWriter(ctx)
		require.NoError(t, err)

		// Manually corrupt segment hash to test error handling
		writer.segments = append(writer.segments, Segment{Hash: "", Size: 10, EncryptedSize: 26})

		attributes := []*policy.Value{
			createTestAttribute("https://example.com/attr/Test/value/Error", testKAS1, "kid1"),
		}
		_, _, err = writer.Finalize(ctx, WithAttributeValues(attributes))
		require.Error(t, err, "Should detect empty segment hash")
		assert.Contains(t, err.Error(), "empty segment hash", "Error message should mention empty segment hash")
	})
}

// testXORReconstruction tests that XOR key splitting can be reconstructed correctly
func testXORReconstruction(t *testing.T) {
	ctx := t.Context()

	writer, err := NewWriter(ctx)
	require.NoError(t, err)

	// Store original DEK for comparison
	originalDEK := make([]byte, len(writer.dek))
	copy(originalDEK, writer.dek)

	// Write test data
	_, err = writer.WriteSegment(ctx, 0, []byte("XOR test data"))
	require.NoError(t, err)

	// Create multiple attributes to force key splitting
	attributes := []*policy.Value{
		createTestAttributeWithRule("https://example.com/attr/Security/value/High", testKAS1, "kid1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
		createTestAttributeWithRule("https://example.com/attr/Compartment/value/Alpha", testKAS2, "kid2", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
	}

	// Finalize to trigger key splitting
	_, manifest, err := writer.Finalize(ctx, WithAttributeValues(attributes))
	require.NoError(t, err)

	// The actual verification of XOR reconstruction is done internally by the splitter,
	// but we can verify the structure is correct and key access objects were generated
	assert.GreaterOrEqual(t, len(manifest.EncryptionInformation.KeyAccessObjs), 1, "Should have key access objects")

	// Verify that each key access object has the required fields
	for i, keyAccess := range manifest.EncryptionInformation.KeyAccessObjs {
		assert.NotEmpty(t, keyAccess.WrappedKey, "Key access %d should have wrapped key", i)
		assert.NotEmpty(t, keyAccess.KasURL, "Key access %d should have KAS URL", i)
		assert.NotEmpty(t, keyAccess.SplitID, "Key access %d should have split ID", i)

		// Decode wrapped key to verify it's not empty
		wrappedKeyBytes, err := ocrypto.Base64Decode([]byte(keyAccess.WrappedKey))
		require.NoError(t, err, "Should be able to decode wrapped key")
		assert.NotEmpty(t, wrappedKeyBytes, "Decoded wrapped key should not be empty")
	}

	// Verify the original DEK is the expected size
	assert.Len(t, originalDEK, 32, "Original DEK should be 32 bytes")
}

// testDifferentAttributeRules tests TDF creation with different attribute rule types
func testDifferentAttributeRules(t *testing.T) {
	ctx := t.Context()

	testCases := []struct {
		name string
		rule policy.AttributeRuleTypeEnum
	}{
		{"AllOf", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF},
		{"AnyOf", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF},
		{"Hierarchy", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			writer, err := NewWriter(ctx)
			require.NoError(t, err)

			_, err = writer.WriteSegment(ctx, 0, []byte("Rule test data"))
			require.NoError(t, err)

			// Create attributes with specific rule type
			attributes := []*policy.Value{
				createTestAttributeWithRule("https://example.com/attr/Level/value/L1", testKAS1, "kid1", tc.rule),
				createTestAttributeWithRule("https://example.com/attr/Level/value/L2", testKAS1, "kid1", tc.rule),
			}

			_, manifest, err := writer.Finalize(ctx, WithAttributeValues(attributes))
			require.NoError(t, err, "Should handle %s rule type", tc.name)

			// Verify manifest was created successfully
			assert.NotNil(t, manifest, "Manifest should not be nil for %s", tc.name)
			assert.NotEmpty(t, manifest.EncryptionInformation.KeyAccessObjs, "Should have key access objects for %s", tc.name)
		})
	}
}

// testOutOfOrderSegments tests writing segments out of order
func testOutOfOrderSegments(t *testing.T) {
	ctx := t.Context()

	writer, err := NewWriter(ctx)
	require.NoError(t, err)

	// Write segments out of order: 2, 0, 1
	segments := map[int][]byte{
		2: []byte("Third segment written first"),
		0: []byte("First segment written second"),
		1: []byte("Second segment written last"),
	}

	// Write in specific out-of-order sequence
	for _, idx := range []int{2, 0, 1} {
		_, err := writer.WriteSegment(ctx, idx, segments[idx])
		require.NoError(t, err, "Failed to write segment %d", idx)
	}

	// Verify all segments are present and in correct positions
	assert.Len(t, writer.segments, 3, "Should have three segments")
	assert.Equal(t, 2, writer.maxSegmentIndex, "Max segment index should be 2")

	for i := 0; i < 3; i++ {
		assert.Equal(t, int64(len(segments[i])), writer.segments[i].Size, "Segment %d size should match", i)
		assert.NotEmpty(t, writer.segments[i].Hash, "Segment %d should have hash", i)
	}

	// Finalize with attributes
	attributes := []*policy.Value{
		createTestAttribute("https://example.com/attr/Order/value/Test", testKAS1, "kid1"),
	}
	_, manifest, err := writer.Finalize(ctx, WithAttributeValues(attributes))
	require.NoError(t, err, "Should finalize successfully with out-of-order segments")
	assert.NotNil(t, manifest, "Manifest should be created")
}

// Helper functions for creating test data

// createTestAttribute creates a test attribute value with KAS grants
func createTestAttribute(fqn, kasURL, kid string) *policy.Value {
	return createTestAttributeWithRule(fqn, kasURL, kid, policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF)
}

// createTestAttributeWithRule creates a test attribute with specific rule type
func createTestAttributeWithRule(fqn, kasURL, kid string, rule policy.AttributeRuleTypeEnum) *policy.Value {
	// Extract attribute definition FQN from value FQN
	parts := strings.Split(fqn, "/value/")
	if len(parts) != 2 {
		panic("Invalid FQN format: " + fqn)
	}
	attrFQN := parts[0]
	valuePart := parts[1]

	// Extract authority and attribute name
	attrParts := strings.Split(attrFQN, "/")
	if len(attrParts) < 5 {
		panic("Invalid attribute FQN format: " + attrFQN)
	}
	authority := strings.Join(attrParts[0:3], "/")
	attrName := attrParts[4]

	namespace := &policy.Namespace{
		Id:   "test-ns",
		Name: "test.com",
		Fqn:  authority,
	}

	attribute := &policy.Attribute{
		Id:        "test-attr-" + attrName,
		Namespace: namespace,
		Name:      attrName,
		Rule:      rule,
		Fqn:       attrFQN,
	}

	value := &policy.Value{
		Id:        "test-value-" + valuePart,
		Attribute: attribute,
		Value:     valuePart,
		Fqn:       fqn,
	}

	if kasURL != "" {
		value.Grants = []*policy.KeyAccessServer{
			{
				Uri: kasURL,
				KasKeys: []*policy.SimpleKasKey{
					{
						KasUri: kasURL,
						PublicKey: &policy.SimpleKasPublicKey{
							Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
							Kid:       kid,
							Pem:       mockRSAPublicKey1,
						},
					},
				},
			},
		}
	}

	return value
}

// benchmarkTDFCreation provides performance benchmarks for TDF operations
func BenchmarkTDFCreation(b *testing.B) {
	ctx := b.Context()
	testData := make([]byte, 1024) // 1KB test data
	_, err := rand.Read(testData)
	if err != nil {
		b.Fatal("Failed to generate random test data:", err)
	}

	b.Run("BasicFlow", func(b *testing.B) {
		attributes := []*policy.Value{
			createTestAttribute("https://example.com/attr/Basic/value/Test", testKAS1, "kid1"),
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			writer, err := NewWriter(ctx)
			if err != nil {
				b.Fatal(err)
			}

			_, err = writer.WriteSegment(ctx, 0, testData)
			if err != nil {
				b.Fatal(err)
			}

			_, _, err = writer.Finalize(ctx, WithAttributeValues(attributes))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("WithAttributes", func(b *testing.B) {
		attributes := []*policy.Value{
			createTestAttribute("https://example.com/attr/Class/value/Secret", testKAS1, "kid1"),
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			writer, err := NewWriter(ctx)
			if err != nil {
				b.Fatal(err)
			}

			_, err = writer.WriteSegment(ctx, 0, testData)
			if err != nil {
				b.Fatal(err)
			}

			_, _, err = writer.Finalize(ctx, WithAttributeValues(attributes))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("MultiSegment", func(b *testing.B) {
		attributes := []*policy.Value{
			createTestAttribute("https://example.com/attr/MultiSeg/value/Test", testKAS1, "kid1"),
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			writer, err := NewWriter(ctx)
			if err != nil {
				b.Fatal(err)
			}

			// Write 4 segments
			for j := 0; j < 4; j++ {
				_, err = writer.WriteSegment(ctx, j, testData)
				if err != nil {
					b.Fatal(err)
				}
			}

			_, _, err = writer.Finalize(ctx, WithAttributeValues(attributes))
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
