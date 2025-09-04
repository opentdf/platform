package keysplit

import (
	"crypto/rand"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration tests that mirror the test cases from granter_test.go
func TestKeySplittingIntegration(t *testing.T) {
	tests := []struct {
		name              string
		policy            []*policy.Value
		defaultKAS        *policy.SimpleKasKey
		expectedSplits    int
		expectedKASInKAOs []string
		description       string
	}{
		{
			name:              "empty policy uses default KAS",
			policy:            []*policy.Value{},
			defaultKAS:        &policy.SimpleKasKey{KasUri: kasUs},
			expectedSplits:    1,
			expectedKASInKAOs: []string{kasUs},
			description:       "Empty policy should result in single split with default KAS",
		},
		{
			name: "single attribute with grant",
			policy: []*policy.Value{
				createMockValue("https://example.com/attr/Department/value/Engineering", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY),
			},
			defaultKAS:        &policy.SimpleKasKey{KasUri: kasUs},
			expectedSplits:    1,
			expectedKASInKAOs: []string{kasUk},
			description:       "Single attribute with grant should use attribute's KAS",
		},
		{
			name: "multiple attributes with anyOf rule",
			policy: []*policy.Value{
				createMockValue("https://example.com/attr/Region/value/Europe", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
				createMockValue("https://example.com/attr/Region/value/Americas", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			},
			defaultKAS:     &policy.SimpleKasKey{KasUri: kasUs},
			expectedSplits: 1, // anyOf means they share a split
			// Both KAS should be available for the single split
			expectedKASInKAOs: []string{kasUk, kasUs},
			description:       "Multiple values with anyOf should share split but have multiple KAS options",
		},
		{
			name: "multiple attributes with allOf rule",
			policy: []*policy.Value{
				createMockValue("https://example.com/attr/Project/value/Alpha", kasUsHCS, "r2", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
				createMockValue("https://example.com/attr/Project/value/Beta", kasUsSA, "r2", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
			},
			defaultKAS:        &policy.SimpleKasKey{KasUri: kasUs},
			expectedSplits:    2, // allOf means each gets its own split
			expectedKASInKAOs: []string{kasUsHCS, kasUsSA},
			description:       "Multiple values with allOf should each get their own split",
		},
		{
			name: "mixed rules - hierarchy and anyOf",
			policy: []*policy.Value{
				createMockValue("https://example.com/attr/Level/value/Manager", "", "", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY), // uses default
				createMockValue("https://example.com/attr/Office/value/Toronto", kasCa, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			},
			defaultKAS:        &policy.SimpleKasKey{KasUri: kasUs},
			expectedSplits:    1,               // Should merge based on boolean logic
			expectedKASInKAOs: []string{kasCa}, // Only the specific KAS since it's more specific
			description:       "Mixed rules should apply boolean logic correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			splitter := NewXORSplitter(WithDefaultKAS(tt.defaultKAS))

			// Generate random DEK
			dek := make([]byte, 32)
			_, err := rand.Read(dek)
			require.NoError(t, err)

			// Generate splits
			result, err := splitter.GenerateSplits(t.Context(), tt.policy, dek)
			require.NoError(t, err, tt.description)
			require.NotNil(t, result)

			assert.Len(t, result.Splits, tt.expectedSplits, tt.description)

			// Verify XOR reconstruction if multiple splits
			if len(result.Splits) > 1 {
				reconstructed := make([]byte, len(dek))
				for _, split := range result.Splits {
					for i, b := range split.Data {
						reconstructed[i] ^= b
					}
				}
				assert.Equal(t, dek, reconstructed, "XOR reconstruction should work")
			}

			// Verify expected KAS are represented in the splits
			kasInSplits := make(map[string]bool)
			for _, split := range result.Splits {
				for _, kasURL := range split.KASURLs {
					kasInSplits[kasURL] = true
				}
			}

			// Verify all expected KAS are represented in splits
			for _, expectedKAS := range tt.expectedKASInKAOs {
				assert.True(t, kasInSplits[expectedKAS], "Expected KAS %s should be found in splits", expectedKAS)
			}

			// Verify public keys are collected for KAS that have embedded keys in policy
			// For empty policy case, no public keys should be present
			if len(tt.policy) == 0 {
				assert.Empty(t, result.KASPublicKeys, "Empty policy should not have embedded public keys")
			} else {
				// For non-empty policies with embedded grants, verify public keys are collected
				for kasURL := range kasInSplits {
					if pubKey, exists := result.KASPublicKeys[kasURL]; exists {
						assert.NotEmpty(t, pubKey.PEM, "Public key PEM should not be empty")
						assert.NotEmpty(t, pubKey.KID, "Public key KID should not be empty")
					}
				}
			}
		})
	}
}

// Test scenarios that match the specificity tests from granter_test.go
func TestKeySplittingSpecificity(t *testing.T) {
	tests := []struct {
		name        string
		setupValue  func() *policy.Value
		defaultKAS  *policy.SimpleKasKey
		expectedKAS *policy.SimpleKasKey
		description string
	}{
		{
			name: "no grants anywhere uses default",
			setupValue: func() *policy.Value {
				return createMockValue("https://other.com/attr/unspecified/value/unspecked", "", "", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
			},
			defaultKAS:  &policy.SimpleKasKey{KasUri: kasUs},
			expectedKAS: &policy.SimpleKasKey{KasUri: kasUs},
			description: "No grants at any level should use default KAS",
		},
		{
			name: "value grant takes precedence over attribute grant",
			setupValue: func() *policy.Value {
				v := createMockValue("https://other.com/attr/specified/value/specked", evenMoreSpecificKas, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
				// Add attribute-level grant that should be overridden
				v.Attribute.Grants = []*policy.KeyAccessServer{
					{Uri: specifiedKas},
				}
				return v
			},
			defaultKAS:  &policy.SimpleKasKey{KasUri: kasUs},
			expectedKAS: &policy.SimpleKasKey{KasUri: evenMoreSpecificKas},
			description: "Value-level grants should take precedence over attribute-level grants",
		},
		{
			name: "attribute grant used when no value grant",
			setupValue: func() *policy.Value {
				v := createMockValue("https://other.com/attr/specified/value/unspecked", "", "", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
				v.Attribute.Grants = []*policy.KeyAccessServer{
					{Uri: specifiedKas},
				}
				return v
			},
			defaultKAS:  &policy.SimpleKasKey{KasUri: kasUs},
			expectedKAS: &policy.SimpleKasKey{KasUri: specifiedKas},
			description: "Attribute-level grants should be used when no value-level grants",
		},
		{
			name: "namespace grant used when no attribute or value grants",
			setupValue: func() *policy.Value {
				v := createMockValue("https://hasgrants.com/attr/unspecified/value/unspecked", "", "", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
				v.Attribute.Namespace.Grants = []*policy.KeyAccessServer{
					{Uri: lessSpecificKas},
				}
				return v
			},
			defaultKAS:  &policy.SimpleKasKey{KasUri: kasUs},
			expectedKAS: &policy.SimpleKasKey{KasUri: lessSpecificKas},
			description: "Namespace-level grants should be used when no more specific grants",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			splitter := NewXORSplitter(WithDefaultKAS(tt.defaultKAS))

			// Generate random DEK
			dek := make([]byte, 32)
			_, err := rand.Read(dek)
			require.NoError(t, err)

			// Generate splits
			value := tt.setupValue()
			result, err := splitter.GenerateSplits(t.Context(), []*policy.Value{value}, dek)
			require.NoError(t, err, tt.description)
			require.NotNil(t, result)

			// Find the KAS that was actually used
			var actualKAS string
			for _, split := range result.Splits {
				for _, kasURL := range split.KASURLs {
					if kasURL == tt.expectedKAS.GetKasUri() {
						actualKAS = kasURL
						break
					}
				}
				if actualKAS != "" {
					break
				}
			}

			assert.Equal(t, tt.expectedKAS.GetKasUri(), actualKAS, tt.description)
		})
	}
}

func TestKeySplittingComplexPolicies(t *testing.T) {
	t.Run("compartmentalized attributes", func(t *testing.T) {
		splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))

		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		// Create complex policy with multiple rules
		policy := []*policy.Value{
			// Level (hierarchy) - uses default
			createMockValue("https://example.com/attr/Level/value/Senior", "", "", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY),
			// Region (anyOf) - multiple regions
			createMockValue("https://example.com/attr/Region/value/Europe", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			createMockValue("https://example.com/attr/Region/value/Americas", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			// Project (allOf) - project access
			createMockValue("https://example.com/attr/Project/value/Alpha", kasUsHCS, "r2", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
			createMockValue("https://example.com/attr/Project/value/Beta", kasUsSA, "r2", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
		}

		result, err := splitter.GenerateSplits(t.Context(), policy, dek)
		require.NoError(t, err)
		require.NotNil(t, result)

		// Should have multiple splits due to allOf rules
		assert.Greater(t, len(result.Splits), 1, "Complex policy should result in multiple splits")

		// Verify XOR reconstruction
		reconstructed := make([]byte, len(dek))
		for _, split := range result.Splits {
			for i, b := range split.Data {
				reconstructed[i] ^= b
			}
		}
		assert.Equal(t, dek, reconstructed, "XOR reconstruction should work for complex policies")

		// Verify that project KAS are present
		kasInSplits := make(map[string]bool)
		for _, split := range result.Splits {
			for _, kasURL := range split.KASURLs {
				kasInSplits[kasURL] = true
			}
		}

		assert.True(t, kasInSplits[kasUsHCS] || kasInSplits[kasUsSA], "Project KAS should be present")
	})

	t.Run("key mapping specificity", func(t *testing.T) {
		splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))

		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		// Create values with different levels of key mapping
		policy := []*policy.Value{
			// Value with specific key mapping
			func() *policy.Value {
				v := createMockValue("https://example.com/attr/Team/value/DevOps", "", "", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
				v.KasKeys = []*policy.SimpleKasKey{
					{
						KasUri: evenMoreSpecificKas,
						PublicKey: &policy.SimpleKasPublicKey{
							Algorithm: policy.Algorithm_ALGORITHM_RSA_4096,
							Kid:       "r2",
							Pem:       mockRSAPublicKey2,
						},
					},
				}
				return v
			}(),
			// Value using attribute-level mapping
			func() *policy.Value {
				v := createMockValue("https://example.com/attr/Team/value/Support", "", "", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
				v.Attribute.Grants = []*policy.KeyAccessServer{
					{Uri: specifiedKas},
				}
				return v
			}(),
		}

		result, err := splitter.GenerateSplits(t.Context(), policy, dek)
		require.NoError(t, err)
		require.NotNil(t, result)

		// Should prioritize value-specific mapping
		kasInSplits := make(map[string]bool)
		for _, split := range result.Splits {
			for _, kasURL := range split.KASURLs {
				kasInSplits[kasURL] = true
			}
		}

		assert.True(t, kasInSplits[evenMoreSpecificKas], "Value-specific KAS should be used")
	})
}

func TestKeySplittingErrorConditions(t *testing.T) {
	t.Run("malformed attribute", func(t *testing.T) {
		splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))

		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		// Create malformed attribute (nil namespace)
		attr := &policy.Value{
			Id:    "test",
			Value: "test",
			Fqn:   "malformed",
			Attribute: &policy.Attribute{
				Id:        "test",
				Name:      "test",
				Namespace: nil, // This should cause issues
			},
		}

		// Should handle gracefully without panicking
		result, err := splitter.GenerateSplits(t.Context(), []*policy.Value{attr}, dek)

		// Depending on implementation, this might error or fall back to defaults
		if err == nil {
			require.NotNil(t, result)
			assert.NotEmpty(t, result.Splits, "Should at least have default split")
		} else {
			// Error is acceptable for malformed input
			assert.Error(t, err)
		}
	})

	t.Run("missing public key for KAS", func(t *testing.T) {
		splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))

		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		// Create an attribute with grants but no public key embedded
		attr := createMockValue("https://test.com/attr/test/value/test", "", "", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
		attr.Grants = []*policy.KeyAccessServer{
			{Uri: kasUs}, // No KasKeys or PublicKey fields
		}

		result, err := splitter.GenerateSplits(t.Context(), []*policy.Value{attr}, dek)
		require.NoError(t, err)
		require.NotNil(t, result)

		// Verify that splits were generated despite missing public keys
		assert.NotEmpty(t, result.Splits, "Should generate splits even without public keys")

		// Verify that no public keys were collected (since none were embedded in grants)
		assert.Empty(t, result.KASPublicKeys, "Should not collect public keys when none are embedded")

		// Verify the split references the KAS URL correctly
		found := false
		for _, split := range result.Splits {
			for _, kasURL := range split.KASURLs {
				if kasURL == kasUs {
					found = true
					break
				}
			}
		}
		assert.True(t, found, "Should reference KAS URL even without embedded public key")
	})
}
