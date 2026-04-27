package enumnormalize

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var allLookup = buildRuleLookup([]EnumFieldRule{
	{JSONField: "operator", Prefix: "SUBJECT_MAPPING_OPERATOR_ENUM_"},
	{JSONField: "booleanOperator", Prefix: "CONDITION_BOOLEAN_TYPE_ENUM_"},
	{JSONField: "rule", Prefix: "ATTRIBUTE_RULE_TYPE_ENUM_"},
	{JSONField: "state", Prefix: "ACTIVE_STATE_ENUM_"},
})

func TestNormalizeJSON_ShorthandOperators(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "IN shorthand",
			input:    `{"operator":"IN"}`,
			expected: `{"operator":"SUBJECT_MAPPING_OPERATOR_ENUM_IN"}`,
		},
		{
			name:     "NOT_IN shorthand",
			input:    `{"operator":"NOT_IN"}`,
			expected: `{"operator":"SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN"}`,
		},
		{
			name:     "IN_CONTAINS shorthand",
			input:    `{"operator":"IN_CONTAINS"}`,
			expected: `{"operator":"SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := normalizeJSON([]byte(tt.input), allLookup)
			require.NoError(t, err)
			assert.JSONEq(t, tt.expected, string(out))
		})
	}
}

func TestNormalizeJSON_ShorthandBooleanOperators(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "AND shorthand",
			input:    `{"booleanOperator":"AND"}`,
			expected: `{"booleanOperator":"CONDITION_BOOLEAN_TYPE_ENUM_AND"}`,
		},
		{
			name:     "OR shorthand",
			input:    `{"booleanOperator":"OR"}`,
			expected: `{"booleanOperator":"CONDITION_BOOLEAN_TYPE_ENUM_OR"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := normalizeJSON([]byte(tt.input), allLookup)
			require.NoError(t, err)
			assert.JSONEq(t, tt.expected, string(out))
		})
	}
}

func TestNormalizeJSON_ShorthandAttributeRuleType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "ALL_OF shorthand",
			input:    `{"rule":"ALL_OF"}`,
			expected: `{"rule":"ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF"}`,
		},
		{
			name:     "ANY_OF shorthand",
			input:    `{"rule":"ANY_OF"}`,
			expected: `{"rule":"ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF"}`,
		},
		{
			name:     "HIERARCHY shorthand",
			input:    `{"rule":"HIERARCHY"}`,
			expected: `{"rule":"ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := normalizeJSON([]byte(tt.input), allLookup)
			require.NoError(t, err)
			assert.JSONEq(t, tt.expected, string(out))
		})
	}
}

func TestNormalizeJSON_ShorthandActiveState(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "ACTIVE shorthand",
			input:    `{"state":"ACTIVE"}`,
			expected: `{"state":"ACTIVE_STATE_ENUM_ACTIVE"}`,
		},
		{
			name:     "INACTIVE shorthand",
			input:    `{"state":"INACTIVE"}`,
			expected: `{"state":"ACTIVE_STATE_ENUM_INACTIVE"}`,
		},
		{
			name:     "ANY shorthand",
			input:    `{"state":"ANY"}`,
			expected: `{"state":"ACTIVE_STATE_ENUM_ANY"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := normalizeJSON([]byte(tt.input), allLookup)
			require.NoError(t, err)
			assert.JSONEq(t, tt.expected, string(out))
		})
	}
}

func TestNormalizeJSON_CaseInsensitive(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase in",
			input:    `{"operator":"in"}`,
			expected: `{"operator":"SUBJECT_MAPPING_OPERATOR_ENUM_IN"}`,
		},
		{
			name:     "lowercase and",
			input:    `{"booleanOperator":"and"}`,
			expected: `{"booleanOperator":"CONDITION_BOOLEAN_TYPE_ENUM_AND"}`,
		},
		{
			name:     "mixed case Not_In",
			input:    `{"operator":"Not_In"}`,
			expected: `{"operator":"SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := normalizeJSON([]byte(tt.input), allLookup)
			require.NoError(t, err)
			assert.JSONEq(t, tt.expected, string(out))
		})
	}
}

func TestNormalizeJSON_FullCanonicalNamesPassThrough(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "full operator name",
			input: `{"operator":"SUBJECT_MAPPING_OPERATOR_ENUM_IN"}`,
		},
		{
			name:  "full boolean operator name",
			input: `{"booleanOperator":"CONDITION_BOOLEAN_TYPE_ENUM_AND"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := normalizeJSON([]byte(tt.input), allLookup)
			require.NoError(t, err)
			assert.JSONEq(t, tt.input, string(out))
		})
	}
}

func TestNormalizeJSON_NumericValuesPassThrough(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "operator 1 (IN) and booleanOperator 2 (OR)",
			input: `{"operator":1,"booleanOperator":2}`,
		},
		{
			name:  "operator 3 (IN_CONTAINS) and booleanOperator 1 (AND)",
			input: `{"operator":3,"booleanOperator":1}`,
		},
		{
			name:  "operator 2 (NOT_IN)",
			input: `{"operator":2}`,
		},
		{
			name:  "rule 1 (ALL_OF)",
			input: `{"rule":1}`,
		},
		{
			name:  "state 1 (ACTIVE)",
			input: `{"state":1}`,
		},
		{
			name:  "numeric zero (UNSPECIFIED) passes through",
			input: `{"operator":0}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := normalizeJSON([]byte(tt.input), allLookup)
			require.NoError(t, err)
			assert.JSONEq(t, tt.input, string(out))
		})
	}
}

func TestNormalizeJSON_NumericValuesInNestedStructure(t *testing.T) {
	// Simulates the JSON format that was previously used in documentation:
	// numeric enum codes instead of string names.
	input := `{
		"subjectConditionSet": {
			"subjectSets": [{
				"conditionGroups": [{
					"booleanOperator": 1,
					"conditions": [
						{
							"subjectExternalSelectorValue": ".email",
							"operator": 3,
							"subjectExternalValues": ["@example.com"]
						},
						{
							"subjectExternalSelectorValue": ".role",
							"operator": 1,
							"subjectExternalValues": ["admin"]
						}
					]
				}]
			}]
		}
	}`

	out, err := normalizeJSON([]byte(input), allLookup)
	require.NoError(t, err)
	// Numeric values should pass through unchanged — protojson natively
	// accepts numeric enum representations.
	assert.JSONEq(t, input, string(out))
}

func TestNormalizeJSON_UnknownValuesGetPrefixed(t *testing.T) {
	// Unknown shorthand values get the prefix prepended; downstream
	// protovalidate will reject them.
	input := `{"operator":"FOOBAR"}`
	expected := `{"operator":"SUBJECT_MAPPING_OPERATOR_ENUM_FOOBAR"}`
	out, err := normalizeJSON([]byte(input), allLookup)
	require.NoError(t, err)
	assert.JSONEq(t, expected, string(out))
}

func TestNormalizeJSON_UnrelatedFieldsUntouched(t *testing.T) {
	input := `{"name":"test","description":"IN","operator":"IN"}`
	out, err := normalizeJSON([]byte(input), allLookup)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, json.Unmarshal(out, &result))

	// "description" should NOT be prefixed — only "operator" is a rule field
	assert.Equal(t, "IN", result["description"])
	assert.Equal(t, "SUBJECT_MAPPING_OPERATOR_ENUM_IN", result["operator"])
}

func TestNormalizeJSON_DeeplyNestedStructure(t *testing.T) {
	// Simulates a CreateSubjectConditionSetRequest with nested condition groups
	input := `{
		"subjectConditionSet": {
			"subjectSets": [{
				"conditionGroups": [{
					"booleanOperator": "AND",
					"conditions": [
						{
							"subjectExternalSelectorValue": ".email",
							"operator": "IN",
							"subjectExternalValues": ["user@example.com"]
						},
						{
							"subjectExternalSelectorValue": ".groups",
							"operator": "NOT_IN",
							"subjectExternalValues": ["banned"]
						}
					]
				}]
			}]
		}
	}`

	expected := `{
		"subjectConditionSet": {
			"subjectSets": [{
				"conditionGroups": [{
					"booleanOperator": "CONDITION_BOOLEAN_TYPE_ENUM_AND",
					"conditions": [
						{
							"subjectExternalSelectorValue": ".email",
							"operator": "SUBJECT_MAPPING_OPERATOR_ENUM_IN",
							"subjectExternalValues": ["user@example.com"]
						},
						{
							"subjectExternalSelectorValue": ".groups",
							"operator": "SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN",
							"subjectExternalValues": ["banned"]
						}
					]
				}]
			}]
		}
	}`

	out, err := normalizeJSON([]byte(input), allLookup)
	require.NoError(t, err)
	assert.JSONEq(t, expected, string(out))
}

func TestNormalizeJSON_MixedShorthandAndFullNames(t *testing.T) {
	input := `{
		"conditionGroups": [{
			"booleanOperator": "CONDITION_BOOLEAN_TYPE_ENUM_OR",
			"conditions": [
				{"operator": "IN"},
				{"operator": "SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN"}
			]
		}]
	}`

	expected := `{
		"conditionGroups": [{
			"booleanOperator": "CONDITION_BOOLEAN_TYPE_ENUM_OR",
			"conditions": [
				{"operator": "SUBJECT_MAPPING_OPERATOR_ENUM_IN"},
				{"operator": "SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN"}
			]
		}]
	}`

	out, err := normalizeJSON([]byte(input), allLookup)
	require.NoError(t, err)
	assert.JSONEq(t, expected, string(out))
}

func TestNormalizeJSON_EmptyBody(t *testing.T) {
	out, err := normalizeJSON([]byte{}, allLookup)
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestNormalizeJSON_NoRules(t *testing.T) {
	input := `{"operator":"IN"}`
	out, err := normalizeJSON([]byte(input), ruleLookup{})
	require.NoError(t, err)
	assert.Equal(t, input, string(out))
}

func TestNormalizeJSON_InvalidJSON(t *testing.T) {
	input := `not json at all`
	out, err := normalizeJSON([]byte(input), allLookup)
	require.NoError(t, err)
	// Invalid JSON passes through unchanged
	assert.Equal(t, input, string(out))
}

// Parent-scoped rule tests

var scopedLookup = buildRuleLookup([]EnumFieldRule{
	// Different prefixes for the same "type" field, scoped by parent key
	{JSONField: "type", Prefix: "CONTENT_EXTRACTOR_TYPE_", ParentField: "contentExtractors"},
	{JSONField: "type", Prefix: "TAG_PROCESSOR_TYPE_", ParentField: "tagProcessors"},
	// A global rule (no parent scope) for a different field
	{JSONField: "state", Prefix: "ACTIVE_STATE_ENUM_"},
})

func TestNormalizeJSON_ParentScopedRules(t *testing.T) {
	input := `{
		"config": {
			"v1": {
				"contentExtractors": [{"type": "TIKA_CONTENT_EXTRACTION", "id": "ce1"}],
				"tagProcessors": [{"type": "REQUIRED_TAGS", "id": "tp1"}]
			}
		}
	}`
	expected := `{
		"config": {
			"v1": {
				"contentExtractors": [{"type": "CONTENT_EXTRACTOR_TYPE_TIKA_CONTENT_EXTRACTION", "id": "ce1"}],
				"tagProcessors": [{"type": "TAG_PROCESSOR_TYPE_REQUIRED_TAGS", "id": "tp1"}]
			}
		}
	}`

	out, err := normalizeJSON([]byte(input), scopedLookup)
	require.NoError(t, err)
	assert.JSONEq(t, expected, string(out))
}

func TestNormalizeJSON_ParentScopedDoesNotMatchGlobally(t *testing.T) {
	// "type" at top level should NOT be rewritten — it only matches under
	// "contentExtractors" or "tagProcessors".
	input := `{"type": "SOME_VALUE"}`

	out, err := normalizeJSON([]byte(input), scopedLookup)
	require.NoError(t, err)
	assert.JSONEq(t, input, string(out))
}

func TestNormalizeJSON_GlobalAndScopedRulesCoexist(t *testing.T) {
	// "state" is a global rule; "type" is parent-scoped.
	input := `{
		"state": "ACTIVE",
		"contentExtractors": [{"type": "TIKA_CONTENT_EXTRACTION"}]
	}`
	expected := `{
		"state": "ACTIVE_STATE_ENUM_ACTIVE",
		"contentExtractors": [{"type": "CONTENT_EXTRACTOR_TYPE_TIKA_CONTENT_EXTRACTION"}]
	}`

	out, err := normalizeJSON([]byte(input), scopedLookup)
	require.NoError(t, err)
	assert.JSONEq(t, expected, string(out))
}

func TestNormalizeJSON_ParentScopedFullCanonicalPassthrough(t *testing.T) {
	// Already-prefixed values pass through unchanged
	input := `{
		"contentExtractors": [{"type": "CONTENT_EXTRACTOR_TYPE_TIKA_CONTENT_EXTRACTION"}]
	}`

	out, err := normalizeJSON([]byte(input), scopedLookup)
	require.NoError(t, err)
	assert.JSONEq(t, input, string(out))
}

func TestNormalizeJSON_ParentScopedCaseInsensitive(t *testing.T) {
	input := `{
		"tagProcessors": [{"type": "required_tags"}]
	}`
	expected := `{
		"tagProcessors": [{"type": "TAG_PROCESSOR_TYPE_REQUIRED_TAGS"}]
	}`

	out, err := normalizeJSON([]byte(input), scopedLookup)
	require.NoError(t, err)
	assert.JSONEq(t, expected, string(out))
}
