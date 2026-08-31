// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package keysplit

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	kasAu               = "https://kas.au/"
	kasCa               = "https://kas.ca/"
	kasUk               = "https://kas.uk/"
	kasNz               = "https://kas.nz/"
	kasUs               = "https://kas.us/"
	kasUsHCS            = "https://hcs.kas.us/"
	kasUsSA             = "https://si.kas.us/"
	specifiedKas        = "https://attr.kas.com/"
	evenMoreSpecificKas = "https://value.kas.com/"
	lessSpecificKas     = "https://namespace.kas.com/"

	// Mock public keys for testing (real RSA-2048 keys)
	mockRSAPublicKey1 = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtQ2ZuyT/p32SFmWTj+wQ
huQwR4IJSzlJ7CqZ4fOXw90rA2joK27dIGiHrtkQHGhS4SK1mvkYyJaREoppMFRc
AyZWCgixbSdwYJS/KN0hjLIdhtkdBlZDaZN2ayTf2sZjWzOLL2cYzzVsAy9tGL8a
bMqf91DEHv+l58fPxmbJ/i6YFFQoOEsyWnPhXdiExe6poQDCHJFYYOp6iu5kOPWr
jKFj9eGXuFR/CJQ/uxTSM+8/7Ejmi8Oa52TQAUhMPH0U1CRFm/NuiFoFissa0jJC
J3k6syxvf45mPrbtlhcELskXrquDtJOpIMQmEwfuV4j8iLNwVlsR2tAbClJi6UOy
SQIDAQAB
-----END PUBLIC KEY-----`

	mockRSAPublicKey2 = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqTQAfdLrf+Kdd+Sk8dH0
mSk57jtkdJ8TNs2VOEs1UWXj8KBOyWckzfV/vXbKWH6NuKAQ2rMGaHB4lUpZ7G30
7IAvVbFn38zGhcpsGK2PiT/LE0QNU8+ZNWB1ai0YNE4My9FYr3Kz+ow+UqzMWl70
ijPXa5tNVb8AWWvXJfzMJczVIzUAu9lUu7ZYhe3ILI4gtc9dHKvrnA5nSBOkGmtL
AZNLLMd8SyacVMMHheZmcFwfPlMwxjE+5txpE2DAVdUbPhiDevXOojXWjTqCIctL
Pg+MdeACAlGz8h3E1TrlqCTqiGXR8vhN2AmybfYn0OMOEcsLlINsgxkzDhRYA1Dv
awIDAQAB
-----END PUBLIC KEY-----`
)

// splitKASURLs lists the servers a split may be unwrapped at. A split
// carries keys rather than bare URLs, and one server can appear under
// several key IDs, so duplicates are collapsed.
func splitKASURLs(s Split) []string {
	seen := make(map[string]bool, len(s.Keys))
	urls := make([]string, 0, len(s.Keys))
	for _, k := range s.Keys {
		if !seen[k.URL] {
			seen[k.URL] = true
			urls = append(urls, k.URL)
		}
	}
	return urls
}

// grantWithKey builds a legacy grant carrying its own key. Splitting is
// offline, so a grant that names only a URL leaves no way to resolve a
// wrapping key and is now an error rather than a keyless split.
func grantWithKey(kasURL string) *policy.KeyAccessServer {
	return &policy.KeyAccessServer{
		Uri: kasURL,
		KasKeys: []*policy.SimpleKasKey{{
			KasUri: kasURL,
			PublicKey: &policy.SimpleKasPublicKey{
				Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
				Kid:       "r1",
				Pem:       mockRSAPublicKey1,
			},
		}},
	}
}

// defaultKASWithKey builds the fallback KAS. It too must carry a key,
// for the same reason.
func defaultKASWithKey(kasURL string) *policy.SimpleKasKey {
	return &policy.SimpleKasKey{
		KasUri: kasURL,
		PublicKey: &policy.SimpleKasPublicKey{
			Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
			Kid:       "default-key",
			Pem:       mockRSAPublicKey1,
		},
	}
}

func createMockValue(fqn, grantKas, kid string, rule policy.AttributeRuleTypeEnum) *policy.Value {
	// Extract attribute definition FQN from value FQN
	// https://example.com/attr/Region/value/Europe -> https://example.com/attr/Region
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
		Id:   "test",
		Name: "test.com",
		Fqn:  authority,
	}

	attribute := &policy.Attribute{
		Id:        "test-attr-" + attrName,
		Namespace: namespace,
		Name:      attrName,
		Rule:      rule,
		Fqn:       attrFQN, // This is the key - use attribute FQN, not value FQN
	}

	value := &policy.Value{
		Id:        "test-value-" + valuePart,
		Attribute: attribute,
		Value:     valuePart,
		Fqn:       fqn,
	}

	if grantKas != "" {
		value.Grants = []*policy.KeyAccessServer{
			{
				Uri: grantKas,
				KasKeys: []*policy.SimpleKasKey{
					{
						KasUri: grantKas,
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

func TestXORSplitter_GenerateSplits_BasicCases(t *testing.T) {
	tests := []struct {
		name     string
		attrs    []*policy.Value
		dek      []byte
		expected int // expected number of splits
		wantErr  bool
	}{
		{
			name:     "empty attributes with default KAS",
			attrs:    []*policy.Value{},
			dek:      make([]byte, 32),
			expected: 1, // default KAS
			wantErr:  false,
		},
		{
			name: "single attribute with grant",
			attrs: []*policy.Value{
				createMockValue("https://test.com/attr/test/value/test", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			},
			dek:      make([]byte, 32),
			expected: 1,
			wantErr:  false,
		},
		{
			name:    "invalid DEK length",
			attrs:   []*policy.Value{},
			dek:     make([]byte, 16), // wrong length
			wantErr: true,
		},
		{
			name:    "nil DEK",
			attrs:   []*policy.Value{},
			dek:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			splitter := NewXORSplitter(WithDefaultKAS(defaultKASWithKey(kasUs)))

			result, err := splitter.GenerateSplits(t.Context(), tt.attrs, tt.dek)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Len(t, result.Splits, tt.expected)

			// Verify XOR reconstruction
			if len(result.Splits) > 1 {
				verifyXORReconstruction(t, tt.dek, result.Splits)
			}
		})
	}
}

func TestXORSplitter_AttributeHierarchy(t *testing.T) {
	tests := []struct {
		name           string
		createValue    func() *policy.Value
		defaultKAS     string
		expectedKAS    string
		expectedSplits int
	}{
		{
			name: "value-level grants take precedence",
			createValue: func() *policy.Value {
				v := createMockValue("https://test.com/attr/test/value/test", evenMoreSpecificKas, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
				// Add definition-level grants that should be overridden
				v.Attribute.Grants = []*policy.KeyAccessServer{
					grantWithKey(specifiedKas),
				}
				return v
			},
			defaultKAS:     kasUs,
			expectedKAS:    evenMoreSpecificKas,
			expectedSplits: 1,
		},
		{
			name: "definition-level grants when no value grants",
			createValue: func() *policy.Value {
				v := createMockValue("https://test.com/attr/test/value/test", "", "", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
				v.Attribute.Grants = []*policy.KeyAccessServer{
					grantWithKey(specifiedKas),
				}
				return v
			},
			defaultKAS:     kasUs,
			expectedKAS:    specifiedKas,
			expectedSplits: 1,
		},
		{
			name: "namespace-level grants when no definition or value grants",
			createValue: func() *policy.Value {
				v := createMockValue("https://test.com/attr/test/value/test", "", "", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
				v.Attribute.Namespace.Grants = []*policy.KeyAccessServer{
					grantWithKey(lessSpecificKas),
				}
				return v
			},
			defaultKAS:     kasUs,
			expectedKAS:    lessSpecificKas,
			expectedSplits: 1,
		},
		{
			name: "default KAS when no grants at any level",
			createValue: func() *policy.Value {
				return createMockValue("https://test.com/attr/test/value/test", "", "", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
			},
			defaultKAS:     kasUs,
			expectedKAS:    kasUs,
			expectedSplits: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			splitter := NewXORSplitter(WithDefaultKAS(defaultKASWithKey(tt.defaultKAS)))
			dek := make([]byte, 32)
			_, err := rand.Read(dek)
			require.NoError(t, err)

			attrs := []*policy.Value{tt.createValue()}

			result, err := splitter.GenerateSplits(t.Context(), attrs, dek)
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Len(t, result.Splits, tt.expectedSplits)

			// Check that the expected KAS is used
			found := false
			for _, split := range result.Splits {
				for _, kasURL := range splitKASURLs(split) {
					if kasURL == tt.expectedKAS {
						found = true
						break
					}
				}
			}
			assert.True(t, found, "Expected KAS %s not found in splits", tt.expectedKAS)
		})
	}
}

func TestXORSplitter_AttributeRules(t *testing.T) {
	tests := []struct {
		name           string
		rule           policy.AttributeRuleTypeEnum
		values         []string
		kasURLs        []string
		expectedSplits int
		description    string
	}{
		{
			name:           "anyOf rule - values share split",
			rule:           policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			values:         []string{"value1", "value2"},
			kasURLs:        []string{kasUs, kasCa},
			expectedSplits: 1, // anyOf means they share the same split
			description:    "anyOf: all values should share the same split",
		},
		{
			name:           "allOf rule - each value gets own split",
			rule:           policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			values:         []string{"value1", "value2"},
			kasURLs:        []string{kasUs, kasCa},
			expectedSplits: 2, // allOf means each gets its own split
			description:    "allOf: each value should get its own split",
		},
		{
			name:    "hierarchy rule - ordered evaluation",
			rule:    policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			values:  []string{"value1", "value2"},
			kasURLs: []string{kasUs, kasCa},
			// A hierarchy rule is an AND, as it is in SDK.CreateTDF:
			// every value in the clause must be satisfied, so each gets
			// its own share. This package used to treat it as an OR,
			// which handed out access the policy did not grant.
			expectedSplits: 2,
			description:    "hierarchy: each value should get its own split",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			splitter := NewXORSplitter(WithDefaultKAS(defaultKASWithKey(kasUs)))
			dek := make([]byte, 32)
			_, err := rand.Read(dek)
			require.NoError(t, err)

			// Create attributes with the specified rule
			var attrs []*policy.Value
			for i, value := range tt.values {
				kasURL := tt.kasURLs[i%len(tt.kasURLs)]
				fqn := "https://test.com/attr/test-attr/value/" + value
				attr := createMockValue(fqn, kasURL, "r1", tt.rule)
				attrs = append(attrs, attr)
			}

			result, err := splitter.GenerateSplits(t.Context(), attrs, dek)
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Len(t, result.Splits, tt.expectedSplits, tt.description)

			// Verify XOR reconstruction works
			if len(result.Splits) > 1 {
				verifyXORReconstruction(t, dek, result.Splits)
			}
		})
	}
}

func TestXORSplitter_SplitResultContent(t *testing.T) {
	splitter := NewXORSplitter(WithDefaultKAS(defaultKASWithKey(kasUs)))
	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	require.NoError(t, err)

	// Create a simple attribute with grant
	attr := createMockValue("https://test.com/attr/test/value/test", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)

	// Generate splits
	result, err := splitter.GenerateSplits(t.Context(), []*policy.Value{attr}, dek)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify split result structure
	assert.Len(t, result.Splits, 1, "Should have one split")
	split := result.Splits[0]
	assert.Equal(t, dek, split.Data, "Single split should contain original DEK")
	assert.Contains(t, splitKASURLs(split), kasUs, "Split should reference the KAS URL")

	// The key rides on the split rather than in a result-wide map, so
	// one KAS can hold several keys for the same split.
	require.Len(t, split.Keys, 1)
	pubKey := split.Keys[0]
	assert.Equal(t, kasUs, pubKey.URL)
	assert.Equal(t, "r1", pubKey.KID)
	assert.NotEmpty(t, pubKey.PEM)
}

func TestXORSplitter_ErrorHandling(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() (*XORSplitter, []*policy.Value, []byte)
		wantErr string
	}{
		{
			name: "no default KAS configured",
			setup: func() (*XORSplitter, []*policy.Value, []byte) {
				splitter := NewXORSplitter() // no default KAS
				return splitter, []*policy.Value{}, make([]byte, 32)
			},
			wantErr: "no default KAS",
		},
		{
			name: "invalid DEK size",
			setup: func() (*XORSplitter, []*policy.Value, []byte) {
				splitter := NewXORSplitter(WithDefaultKAS(defaultKASWithKey(kasUs)))
				return splitter, []*policy.Value{}, make([]byte, 16) // wrong size
			},
			wantErr: "invalid DEK",
		},
		{
			name: "empty DEK",
			setup: func() (*XORSplitter, []*policy.Value, []byte) {
				splitter := NewXORSplitter(WithDefaultKAS(defaultKASWithKey(kasUs)))
				return splitter, []*policy.Value{}, []byte{}
			},
			wantErr: "DEK cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			splitter, attrs, dek := tt.setup()

			_, err := splitter.GenerateSplits(t.Context(), attrs, dek)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// verifyXORReconstruction is a shared helper to verify XOR reconstruction works
func verifyXORReconstruction(t *testing.T, originalDEK []byte, splits []Split) {
	t.Helper()

	if len(splits) == 1 {
		assert.Equal(t, originalDEK, splits[0].Data, "Single split should contain original DEK")
		return
	}

	reconstructed := make([]byte, len(originalDEK))
	for _, split := range splits {
		for i, b := range split.Data {
			reconstructed[i] ^= b
		}
	}
	assert.Equal(t, originalDEK, reconstructed, "XOR reconstruction should match original DEK")
}

func TestXORSplitter_ConfigurationOptions(t *testing.T) {
	t.Run("WithDefaultKAS option", func(t *testing.T) {
		defaultKAS := &policy.SimpleKasKey{
			KasUri: kasUs,
			PublicKey: &policy.SimpleKasPublicKey{
				Kid:       "default-key",
				Pem:       mockRSAPublicKey1,
				Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
			},
		}

		splitter := NewXORSplitter(WithDefaultKAS(defaultKAS))

		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		// Test with empty attributes (should use default KAS)
		result, err := splitter.GenerateSplits(t.Context(), []*policy.Value{}, dek)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Len(t, result.Splits, 1, "Empty attributes should use default KAS")
		assert.Contains(t, splitKASURLs(result.Splits[0]), kasUs, "Should use configured default KAS")

		require.Len(t, result.Splits[0].Keys, 1, "Should include default KAS public key")
		pubKey := result.Splits[0].Keys[0]
		assert.Equal(t, kasUs, pubKey.URL)
		assert.Equal(t, "default-key", pubKey.KID)
		assert.Equal(t, mockRSAPublicKey1, pubKey.PEM)
	})

	t.Run("split ID generation", func(t *testing.T) {
		splitter := NewXORSplitter(WithDefaultKAS(defaultKASWithKey(kasUs)))

		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		result, err := splitter.GenerateSplits(t.Context(), []*policy.Value{}, dek)
		require.NoError(t, err)
		require.NotNil(t, result)

		// An unsplit DEK carries no split ID, matching SDK.CreateTDF.
		// This package used to stamp a random one on it, which made an
		// otherwise identical manifest compare unequal.
		assert.Len(t, result.Splits, 1)
		assert.Empty(t, result.Splits[0].ID, "A single split needs no ID")
	})

	t.Run("no options - minimal configuration", func(t *testing.T) {
		splitter := NewXORSplitter()

		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		// Should error with empty attributes and no default KAS
		_, err = splitter.GenerateSplits(t.Context(), []*policy.Value{}, dek)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no default KAS")
	})
}

func TestXORSplitter_ComplexScenarios(t *testing.T) {
	t.Run("multiple attributes with different KAS", func(t *testing.T) {
		splitter := NewXORSplitter(WithDefaultKAS(defaultKASWithKey(kasUs)))
		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		attrs := []*policy.Value{
			createMockValue("https://test.com/attr/level/value/manager", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			createMockValue("https://test.com/attr/region/value/europe", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			createMockValue("https://test.com/attr/project/value/alpha", kasUsHCS, "r2", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
		}

		result, err := splitter.GenerateSplits(t.Context(), attrs, dek)
		require.NoError(t, err)
		require.NotNil(t, result)

		// Should have multiple splits due to different KAS requirements
		assert.Greater(t, len(result.Splits), 1, "Should have multiple splits for different KAS")

		// Verify XOR reconstruction
		verifyXORReconstruction(t, dek, result.Splits)
	})

	t.Run("attribute with multiple KAS in grants", func(t *testing.T) {
		splitter := NewXORSplitter(WithDefaultKAS(defaultKASWithKey(kasUs)))
		dek := make([]byte, 32)
		_, err := rand.Read(dek)
		require.NoError(t, err)

		// Create attribute with multiple KAS grants
		attr := createMockValue("https://test.com/attr/multi/value/test", "", "", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
		attr.Grants = []*policy.KeyAccessServer{
			grantWithKey(kasUs),
			grantWithKey(kasUk),
			grantWithKey(kasCa),
		}

		result, err := splitter.GenerateSplits(t.Context(), []*policy.Value{attr}, dek)
		require.NoError(t, err)
		require.NotNil(t, result)

		// Should create a split that includes all the KAS URLs
		found := false
		for _, split := range result.Splits {
			if len(splitKASURLs(split)) > 1 {
				found = true
				assert.Contains(t, splitKASURLs(split), kasUs)
				assert.Contains(t, splitKASURLs(split), kasUk)
				assert.Contains(t, splitKASURLs(split), kasCa)
			}
		}
		assert.True(t, found, "Should find split with multiple KAS URLs")
	})
}
