package keysplit

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateKASSetKey(t *testing.T) {
	tests := []struct {
		name     string
		kasURLs  []string
		expected string
	}{
		{
			name:     "empty KAS URLs",
			kasURLs:  []string{},
			expected: "[]",
		},
		{
			name:     "single KAS URL",
			kasURLs:  []string{"https://kas1.com"},
			expected: "[https://kas1.com]",
		},
		{
			name:     "multiple KAS URLs already sorted",
			kasURLs:  []string{"https://kas1.com", "https://kas2.com", "https://kas3.com"},
			expected: "[https://kas1.com https://kas2.com https://kas3.com]",
		},
		{
			name:     "multiple KAS URLs unsorted",
			kasURLs:  []string{"https://kas3.com", "https://kas1.com", "https://kas2.com"},
			expected: "[https://kas1.com https://kas2.com https://kas3.com]",
		},
		{
			name:     "duplicate KAS URLs",
			kasURLs:  []string{"https://kas2.com", "https://kas1.com", "https://kas2.com"},
			expected: "[https://kas1.com https://kas2.com https://kas2.com]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := createKASSetKey(tt.kasURLs)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMergeAssignments(t *testing.T) {
	tests := []struct {
		name        string
		assignments []SplitAssignment
		expected    SplitAssignment
	}{
		{
			name:        "empty assignments",
			assignments: []SplitAssignment{},
			expected:    SplitAssignment{},
		},
		{
			name: "single assignment",
			assignments: []SplitAssignment{
				{
					SplitID: "split1",
					KASURLs: []string{"https://kas1.com"},
					Keys: map[string]*policy.SimpleKasPublicKey{
						"https://kas1.com": {
							Kid: "key1",
							Pem: "-----BEGIN PUBLIC KEY-----\nKEY1\n-----END PUBLIC KEY-----",
						},
					},
				},
			},
			expected: SplitAssignment{
				SplitID: "split1",
				KASURLs: []string{"https://kas1.com"},
				Keys: map[string]*policy.SimpleKasPublicKey{
					"https://kas1.com": {
						Kid: "key1",
						Pem: "-----BEGIN PUBLIC KEY-----\nKEY1\n-----END PUBLIC KEY-----",
					},
				},
			},
		},
		{
			name: "multiple assignments with overlapping keys",
			assignments: []SplitAssignment{
				{
					SplitID: "split1",
					KASURLs: []string{"https://kas1.com"},
					Keys: map[string]*policy.SimpleKasPublicKey{
						"https://kas1.com": {
							Kid: "key1",
							Pem: "-----BEGIN PUBLIC KEY-----\nKEY1\n-----END PUBLIC KEY-----",
						},
					},
				},
				{
					SplitID: "split2",
					KASURLs: []string{"https://kas2.com"},
					Keys: map[string]*policy.SimpleKasPublicKey{
						"https://kas2.com": {
							Kid: "key2",
							Pem: "-----BEGIN PUBLIC KEY-----\nKEY2\n-----END PUBLIC KEY-----",
						},
					},
				},
			},
			expected: SplitAssignment{
				SplitID: "split1", // Uses first assignment as base
				KASURLs: []string{"https://kas1.com"},
				Keys: map[string]*policy.SimpleKasPublicKey{
					"https://kas1.com": {
						Kid: "key1",
						Pem: "-----BEGIN PUBLIC KEY-----\nKEY1\n-----END PUBLIC KEY-----",
					},
					"https://kas2.com": {
						Kid: "key2",
						Pem: "-----BEGIN PUBLIC KEY-----\nKEY2\n-----END PUBLIC KEY-----",
					},
				},
			},
		},
		{
			name: "assignments with duplicate KAS URLs",
			assignments: []SplitAssignment{
				{
					SplitID: "split1",
					KASURLs: []string{"https://kas1.com"},
					Keys: map[string]*policy.SimpleKasPublicKey{
						"https://kas1.com": {
							Kid: "key1-old",
							Pem: "-----BEGIN PUBLIC KEY-----\nOLD\n-----END PUBLIC KEY-----",
						},
					},
				},
				{
					SplitID: "split2",
					KASURLs: []string{"https://kas1.com"},
					Keys: map[string]*policy.SimpleKasPublicKey{
						"https://kas1.com": {
							Kid: "key1-new",
							Pem: "-----BEGIN PUBLIC KEY-----\nNEW\n-----END PUBLIC KEY-----",
						},
					},
				},
			},
			expected: SplitAssignment{
				SplitID: "split1",
				KASURLs: []string{"https://kas1.com"},
				Keys: map[string]*policy.SimpleKasPublicKey{
					"https://kas1.com": {
						Kid: "key1-old", // First key is kept when duplicates exist
						Pem: "-----BEGIN PUBLIC KEY-----\nOLD\n-----END PUBLIC KEY-----",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeAssignments(tt.assignments)
			assert.Equal(t, tt.expected.SplitID, result.SplitID)
			assert.Equal(t, tt.expected.KASURLs, result.KASURLs)
			assert.Equal(t, len(tt.expected.Keys), len(result.Keys))

			for kasURL, expectedKey := range tt.expected.Keys {
				actualKey, exists := result.Keys[kasURL]
				require.True(t, exists, "Expected KAS %s not found in result", kasURL)
				assert.Equal(t, expectedKey.Kid, actualKey.Kid)
				assert.Equal(t, expectedKey.Pem, actualKey.Pem)
			}
		})
	}
}

func TestOptimizeSplitAssignments(t *testing.T) {
	tests := []struct {
		name        string
		assignments []SplitAssignment
		expectedLen int
		description string
	}{
		{
			name:        "empty assignments",
			assignments: []SplitAssignment{},
			expectedLen: 0,
			description: "Empty input should return empty output",
		},
		{
			name: "single assignment",
			assignments: []SplitAssignment{
				{
					SplitID: "split1",
					KASURLs: []string{"https://kas1.com"},
					Keys:    map[string]*policy.SimpleKasPublicKey{},
				},
			},
			expectedLen: 1,
			description: "Single assignment should be preserved",
		},
		{
			name: "assignments with different KAS sets",
			assignments: []SplitAssignment{
				{
					SplitID: "split1",
					KASURLs: []string{"https://kas1.com"},
					Keys:    map[string]*policy.SimpleKasPublicKey{},
				},
				{
					SplitID: "split2",
					KASURLs: []string{"https://kas2.com"},
					Keys:    map[string]*policy.SimpleKasPublicKey{},
				},
			},
			expectedLen: 2,
			description: "Different KAS sets should remain separate",
		},
		{
			name: "assignments with identical KAS sets should merge",
			assignments: []SplitAssignment{
				{
					SplitID: "split1",
					KASURLs: []string{"https://kas1.com", "https://kas2.com"},
					Keys: map[string]*policy.SimpleKasPublicKey{
						"https://kas1.com": {Kid: "key1"},
					},
				},
				{
					SplitID: "split2",
					KASURLs: []string{"https://kas1.com", "https://kas2.com"},
					Keys: map[string]*policy.SimpleKasPublicKey{
						"https://kas2.com": {Kid: "key2"},
					},
				},
			},
			expectedLen: 1,
			description: "Identical KAS sets should merge into single assignment",
		},
		{
			name: "assignments with differently ordered but identical KAS sets",
			assignments: []SplitAssignment{
				{
					SplitID: "split1",
					KASURLs: []string{"https://kas1.com", "https://kas2.com"},
					Keys:    map[string]*policy.SimpleKasPublicKey{},
				},
				{
					SplitID: "split2",
					KASURLs: []string{"https://kas2.com", "https://kas1.com"}, // Different order
					Keys:    map[string]*policy.SimpleKasPublicKey{},
				},
			},
			expectedLen: 1,
			description: "KAS sets with different order should still be recognized as identical",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := optimizeSplitAssignments(tt.assignments)
			assert.Len(t, result, tt.expectedLen, tt.description)

			// Verify deterministic ordering of results
			for i := 1; i < len(result); i++ {
				assert.LessOrEqual(t, result[i-1].SplitID, result[i].SplitID, "Results should be sorted by SplitID")
			}
		})
	}
}

func TestCreateDefaultSplitPlan(t *testing.T) {
	tests := []struct {
		name        string
		defaultKAS  string
		expectedLen int
		description string
	}{
		{
			name:        "empty default KAS",
			defaultKAS:  "",
			expectedLen: 0,
			description: "Empty default KAS should return nil plan",
		},
		{
			name:        "valid default KAS",
			defaultKAS:  "https://default.kas.com",
			expectedLen: 1,
			description: "Valid default KAS should create single assignment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := createDefaultSplitPlan(tt.defaultKAS)

			if tt.expectedLen == 0 {
				assert.Nil(t, result, tt.description)
				return
			}

			require.Len(t, result, tt.expectedLen, tt.description)
			assignment := result[0]
			assert.Equal(t, "", assignment.SplitID, "Default split should have empty ID")
			assert.Equal(t, []string{tt.defaultKAS}, assignment.KASURLs)
			assert.Empty(t, assignment.Keys, "Default split should have empty keys map")
		})
	}
}

func TestGenerateSplitID(t *testing.T) {
	// Test that split IDs are unique
	ids := make(map[string]bool)
	const numIDs = 100

	for i := 0; i < numIDs; i++ {
		id := generateSplitID()
		assert.NotEmpty(t, id, "Split ID should not be empty")
		assert.False(t, ids[id], "Split ID %s was generated twice", id)
		ids[id] = true
	}

	assert.Len(t, ids, numIDs, "All generated IDs should be unique")
}

func TestCreateSplitPlan(t *testing.T) {
	tests := []struct {
		name        string
		expr        *BooleanExpression
		defaultKAS  string
		expectedLen int
		wantErr     bool
		description string
	}{
		{
			name:        "empty expression with default KAS",
			expr:        &BooleanExpression{Clauses: []AttributeClause{}},
			defaultKAS:  "https://default.kas.com",
			expectedLen: 1,
			wantErr:     false,
			description: "Empty expression should use default KAS",
		},
		{
			name:        "empty expression without default KAS",
			expr:        &BooleanExpression{Clauses: []AttributeClause{}},
			defaultKAS:  "",
			expectedLen: 0,
			wantErr:     false,
			description: "Empty expression without default should return empty plan",
		},
		{
			name: "single anyOf clause",
			expr: &BooleanExpression{
				Clauses: []AttributeClause{
					{
						Definition: &policy.Attribute{
							Fqn: "https://test.com/attr/Dept",
						},
						Values: []*policy.Value{
							createMockValue("https://test.com/attr/Dept/value/Eng", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
						},
						Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
					},
				},
			},
			defaultKAS:  "https://default.kas.com",
			expectedLen: 1,
			wantErr:     false,
			description: "Single anyOf clause should create one assignment",
		},
		{
			name: "single allOf clause with multiple values",
			expr: &BooleanExpression{
				Clauses: []AttributeClause{
					{
						Definition: &policy.Attribute{
							Fqn: "https://test.com/attr/Project",
						},
						Values: []*policy.Value{
							createMockValue("https://test.com/attr/Project/value/Alpha", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
							createMockValue("https://test.com/attr/Project/value/Beta", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
						},
						Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					},
				},
			},
			defaultKAS:  "https://default.kas.com",
			expectedLen: 2,
			wantErr:     false,
			description: "AllOf clause should create separate assignments for each value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := createSplitPlan(tt.expr, tt.defaultKAS)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err, tt.description)
			assert.Len(t, result, tt.expectedLen, tt.description)

			// Verify all assignments have valid structure
			for i, assignment := range result {
				assert.NotEmpty(t, assignment.KASURLs, "Assignment %d should have KAS URLs", i)
				assert.NotNil(t, assignment.Keys, "Assignment %d should have Keys map", i)
			}
		})
	}
}

func TestProcessBooleanClause(t *testing.T) {
	tests := []struct {
		name        string
		clause      AttributeClause
		expectedLen int
		wantErr     bool
		description string
	}{
		{
			name: "anyOf clause",
			clause: AttributeClause{
				Definition: &policy.Attribute{
					Fqn: "https://test.com/attr/Dept",
				},
				Values: []*policy.Value{
					createMockValue("https://test.com/attr/Dept/value/Eng", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
					createMockValue("https://test.com/attr/Dept/value/Marketing", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
				},
				Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			},
			expectedLen: 1,
			wantErr:     false,
			description: "anyOf should create single assignment",
		},
		{
			name: "allOf clause",
			clause: AttributeClause{
				Definition: &policy.Attribute{
					Fqn: "https://test.com/attr/Project",
				},
				Values: []*policy.Value{
					createMockValue("https://test.com/attr/Project/value/Alpha", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
					createMockValue("https://test.com/attr/Project/value/Beta", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
				},
				Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			},
			expectedLen: 2,
			wantErr:     false,
			description: "allOf should create separate assignments",
		},
		{
			name: "hierarchy clause",
			clause: AttributeClause{
				Definition: &policy.Attribute{
					Fqn: "https://test.com/attr/Level",
				},
				Values: []*policy.Value{
					createMockValue("https://test.com/attr/Level/value/Senior", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY),
				},
				Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			},
			expectedLen: 1,
			wantErr:     false,
			description: "hierarchy should be processed like anyOf",
		},
		{
			name: "unspecified rule treated as allOf",
			clause: AttributeClause{
				Definition: &policy.Attribute{
					Fqn: "https://test.com/attr/Test",
				},
				Values: []*policy.Value{
					createMockValue("https://test.com/attr/Test/value/Value1", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED),
					createMockValue("https://test.com/attr/Test/value/Value2", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED),
				},
				Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
			},
			expectedLen: 2,
			wantErr:     false,
			description: "unspecified rule should be treated as allOf",
		},
		{
			name: "unsupported rule type",
			clause: AttributeClause{
				Definition: &policy.Attribute{
					Fqn: "https://test.com/attr/Test",
				},
				Values: []*policy.Value{
					createMockValue("https://test.com/attr/Test/value/Value", kasUs, "r1", policy.AttributeRuleTypeEnum(999)),
				},
				Rule: policy.AttributeRuleTypeEnum(999),
			},
			wantErr:     true,
			description: "Unsupported rule should return error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := processBooleanClause(tt.clause)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported rule")
				return
			}

			require.NoError(t, err, tt.description)
			assert.Len(t, result, tt.expectedLen, tt.description)
		})
	}
}

func TestExtractKASURLs(t *testing.T) {
	grants := []KASGrant{
		{URL: "https://kas3.com"},
		{URL: "https://kas1.com"},
		{URL: "https://kas2.com"},
	}

	result := extractKASURLs(grants)
	expected := []string{"https://kas1.com", "https://kas2.com", "https://kas3.com"}

	assert.Equal(t, expected, result, "URLs should be sorted for deterministic ordering")
}

func TestExtractKASKeys(t *testing.T) {
	grants := []KASGrant{
		{
			URL: "https://kas1.com",
			PublicKey: &policy.SimpleKasPublicKey{
				Kid: "key1",
				Pem: "-----BEGIN PUBLIC KEY-----\nKEY1\n-----END PUBLIC KEY-----",
			},
		},
		{
			URL:       "https://kas2.com",
			PublicKey: nil, // Should be filtered out
		},
		{
			URL: "https://kas3.com",
			PublicKey: &policy.SimpleKasPublicKey{
				Kid: "key3",
				Pem: "-----BEGIN PUBLIC KEY-----\nKEY3\n-----END PUBLIC KEY-----",
			},
		},
	}

	result := extractKASKeys(grants)

	expected := map[string]*policy.SimpleKasPublicKey{
		"https://kas1.com": {
			Kid: "key1",
			Pem: "-----BEGIN PUBLIC KEY-----\nKEY1\n-----END PUBLIC KEY-----",
		},
		"https://kas3.com": {
			Kid: "key3",
			Pem: "-----BEGIN PUBLIC KEY-----\nKEY3\n-----END PUBLIC KEY-----",
		},
	}

	assert.Equal(t, expected, result, "Should only include grants with valid public keys")
}
