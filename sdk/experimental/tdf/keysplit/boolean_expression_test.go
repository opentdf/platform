// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package keysplit

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAttributeFQN(t *testing.T) {
	tests := []struct {
		name    string
		fqn     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid FQN",
			fqn:     "https://example.com/attr/Department/value/Engineering",
			wantErr: false,
		},
		{
			name:    "valid FQN with subdomain",
			fqn:     "https://auth.example.com/attr/Level/value/Manager",
			wantErr: false,
		},
		{
			name:    "valid FQN with port",
			fqn:     "https://localhost:8080/attr/Test/value/Value1",
			wantErr: false,
		},
		{
			name:    "valid FQN with path",
			fqn:     "https://api.example.com/v1/attr/Role/value/Admin",
			wantErr: false,
		},
		{
			name:    "valid FQN with URL-encoded attribute name",
			fqn:     "https://example.com/attr/My%20Department/value/Engineering",
			wantErr: false,
		},
		{
			name:    "valid FQN with URL-encoded value",
			fqn:     "https://example.com/attr/Department/value/Software%20Engineering",
			wantErr: false,
		},
		{
			name:    "empty FQN",
			fqn:     "",
			wantErr: true,
			errMsg:  "FQN is empty",
		},
		{
			name:    "invalid format - missing attr",
			fqn:     "https://example.com/Department/value/Engineering",
			wantErr: true,
			errMsg:  "invalid FQN format",
		},
		{
			name:    "invalid format - missing value",
			fqn:     "https://example.com/attr/Department/Engineering",
			wantErr: true,
			errMsg:  "invalid FQN format",
		},
		{
			name:    "invalid format - no domain",
			fqn:     "/attr/Department/value/Engineering",
			wantErr: true,
			errMsg:  "invalid FQN format",
		},
		{
			name:    "invalid format - missing scheme",
			fqn:     "example.com/attr/Department/value/Engineering",
			wantErr: true,
			errMsg:  "invalid FQN format",
		},
		{
			name:    "empty authority",
			fqn:     "/attr/Department/value/Engineering",
			wantErr: true,
			errMsg:  "invalid FQN format",
		},
		{
			name:    "empty attribute name",
			fqn:     "https://example.com/attr//value/Engineering",
			wantErr: true,
			errMsg:  "FQN has empty components",
		},
		{
			name:    "empty value",
			fqn:     "https://example.com/attr/Department/value/",
			wantErr: true,
			errMsg:  "FQN has empty components",
		},
		{
			name:    "invalid URL encoding in attribute name",
			fqn:     "https://example.com/attr/Invalid%ZZ/value/Test",
			wantErr: true,
			errMsg:  "invalid attribute name encoding",
		},
		{
			name:    "invalid URL encoding in value",
			fqn:     "https://example.com/attr/Test/value/Invalid%ZZ",
			wantErr: true,
			errMsg:  "invalid attribute value encoding",
		},
		{
			name:    "http scheme allowed",
			fqn:     "http://example.com/attr/Department/value/Engineering",
			wantErr: false,
		},
		{
			name:    "special characters in domain",
			fqn:     "https://sub-domain.example-site.com/attr/Test/value/Value",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAttributeFQN(tt.fqn)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateAttributeRule(t *testing.T) {
	tests := []struct {
		name    string
		rule    policy.AttributeRuleTypeEnum
		wantErr bool
	}{
		{
			name:    "all of rule",
			rule:    policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			wantErr: false,
		},
		{
			name:    "any of rule",
			rule:    policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			wantErr: false,
		},
		{
			name:    "hierarchy rule",
			rule:    policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			wantErr: false,
		},
		{
			name:    "unspecified rule treated as valid",
			rule:    policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
			wantErr: false,
		},
		{
			name:    "unknown rule value",
			rule:    policy.AttributeRuleTypeEnum(999),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAttributeRule(tt.rule)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported rule type")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestBuildBooleanExpression(t *testing.T) {
	tests := []struct {
		name        string
		values      []*policy.Value
		expectedLen int
		wantErr     bool
		errMsg      string
	}{
		{
			name:        "empty values",
			values:      []*policy.Value{},
			expectedLen: 0,
			wantErr:     false,
		},
		{
			name: "single attribute with one value",
			values: []*policy.Value{
				createMockValue("https://test.com/attr/Dept/value/Eng", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			},
			expectedLen: 1,
			wantErr:     false,
		},
		{
			name: "single attribute with multiple values",
			values: []*policy.Value{
				createMockValue("https://test.com/attr/Dept/value/Eng", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
				createMockValue("https://test.com/attr/Dept/value/Marketing", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			},
			expectedLen: 1, // Same attribute definition, so one clause
			wantErr:     false,
		},
		{
			name: "multiple attributes",
			values: []*policy.Value{
				createMockValue("https://test.com/attr/Dept/value/Eng", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
				createMockValue("https://test.com/attr/Level/value/Manager", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
			},
			expectedLen: 2, // Different attribute definitions
			wantErr:     false,
		},
		{
			name: "value with nil attribute",
			values: []*policy.Value{
				{
					Id:        "test",
					Fqn:       "https://test.com/attr/Test/value/Value",
					Attribute: nil,
				},
			},
			wantErr: true,
			errMsg:  "attribute definition missing",
		},
		{
			name: "invalid FQN format",
			values: []*policy.Value{
				{
					Id:  "test",
					Fqn: "invalid-fqn",
					Attribute: &policy.Attribute{
						Id:   "test-attr",
						Name: "test",
						Fqn:  "https://test.com/attr/Test",
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid attribute FQN",
		},
		{
			name: "unsupported rule type",
			values: []*policy.Value{
				{
					Id:  "test",
					Fqn: "https://test.com/attr/Test/value/Value",
					Attribute: &policy.Attribute{
						Id:   "test-attr",
						Name: "Test",
						Fqn:  "https://test.com/attr/Test",
						Rule: policy.AttributeRuleTypeEnum(999), // Invalid rule
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid attribute rule type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := buildBooleanExpression(tt.values)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, expr)
			assert.Len(t, expr.Clauses, tt.expectedLen)
		})
	}
}

func TestBooleanExpressionString(t *testing.T) {
	tests := []struct {
		name     string
		expr     *BooleanExpression
		expected string
	}{
		{
			name:     "empty expression",
			expr:     &BooleanExpression{Clauses: []AttributeClause{}},
			expected: "∅",
		},
		{
			name: "single clause with single value",
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
			expected: "https://test.com/attr/Dept/value/Eng",
		},
		{
			name: "single clause with multiple values",
			expr: &BooleanExpression{
				Clauses: []AttributeClause{
					{
						Definition: &policy.Attribute{
							Fqn: "https://test.com/attr/Dept",
						},
						Values: []*policy.Value{
							createMockValue("https://test.com/attr/Dept/value/Eng", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
							createMockValue("https://test.com/attr/Dept/value/Marketing", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
						},
						Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
					},
				},
			},
			expected: "anyOf(https://test.com/attr/Dept: {Eng, Marketing})",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.expr.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAttributeClauseString(t *testing.T) {
	tests := []struct {
		name     string
		clause   AttributeClause
		expected string
	}{
		{
			name: "empty clause",
			clause: AttributeClause{
				Definition: &policy.Attribute{
					Fqn: "https://test.com/attr/Empty",
				},
				Values: []*policy.Value{},
				Rule:   policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			},
			expected: "https://test.com/attr/Empty",
		},
		{
			name: "single value clause",
			clause: AttributeClause{
				Definition: &policy.Attribute{
					Fqn: "https://test.com/attr/Dept",
				},
				Values: []*policy.Value{
					createMockValue("https://test.com/attr/Dept/value/Engineering", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
				},
				Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			},
			expected: "https://test.com/attr/Dept/value/Engineering",
		},
		{
			name: "anyOf clause with multiple values",
			clause: AttributeClause{
				Definition: &policy.Attribute{
					Fqn: "https://test.com/attr/Department",
				},
				Values: []*policy.Value{
					createMockValue("https://test.com/attr/Department/value/Engineering", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
					createMockValue("https://test.com/attr/Department/value/Marketing", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
				},
				Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			},
			expected: "anyOf(https://test.com/attr/Department: {Engineering, Marketing})",
		},
		{
			name: "allOf clause with multiple values",
			clause: AttributeClause{
				Definition: &policy.Attribute{
					Fqn: "https://test.com/attr/Project",
				},
				Values: []*policy.Value{
					createMockValue("https://test.com/attr/Project/value/Alpha", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
					createMockValue("https://test.com/attr/Project/value/Beta", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
				},
				Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			},
			expected: "allOf(https://test.com/attr/Project: {Alpha, Beta})",
		},
		{
			name: "hierarchy clause",
			clause: AttributeClause{
				Definition: &policy.Attribute{
					Fqn: "https://test.com/attr/Level",
				},
				Values: []*policy.Value{
					createMockValue("https://test.com/attr/Level/value/Junior", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY),
					createMockValue("https://test.com/attr/Level/value/Senior", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY),
				},
				Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			},
			expected: "hierarchy(https://test.com/attr/Level: {Junior, Senior})",
		},
		{
			name: "URL-encoded value names in clause",
			clause: AttributeClause{
				Definition: &policy.Attribute{
					Fqn: "https://test.com/attr/Department",
				},
				Values: []*policy.Value{
					createMockValue("https://test.com/attr/Department/value/Software%20Engineering", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
					createMockValue("https://test.com/attr/Department/value/Product%20Management", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
				},
				Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			},
			expected: "anyOf(https://test.com/attr/Department: {Software Engineering, Product Management})",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.clause.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRuleToString(t *testing.T) {
	tests := []struct {
		name     string
		rule     policy.AttributeRuleTypeEnum
		expected string
	}{
		{
			name:     "all of",
			rule:     policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			expected: "allOf",
		},
		{
			name:     "any of",
			rule:     policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			expected: "anyOf",
		},
		{
			name:     "hierarchy",
			rule:     policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			expected: "hierarchy",
		},
		{
			name:     "unspecified",
			rule:     policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
			expected: "unspecified",
		},
		{
			name:     "unknown rule",
			rule:     policy.AttributeRuleTypeEnum(999),
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ruleToString(tt.rule)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildBooleanExpression_GroupingLogic(t *testing.T) {
	t.Run("values grouped by attribute definition", func(t *testing.T) {
		values := []*policy.Value{
			createMockValue("https://test.com/attr/Dept/value/Eng", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			createMockValue("https://test.com/attr/Level/value/Manager", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
			createMockValue("https://test.com/attr/Dept/value/Marketing", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
		}

		expr, err := buildBooleanExpression(values)
		require.NoError(t, err)
		require.NotNil(t, expr)

		// Should have 2 clauses: one for Dept (2 values), one for Level (1 value)
		assert.Len(t, expr.Clauses, 2)

		// Find Department clause
		var deptClause *AttributeClause
		for i := range expr.Clauses {
			if expr.Clauses[i].Definition.GetName() == "Dept" {
				deptClause = &expr.Clauses[i]
				break
			}
		}
		require.NotNil(t, deptClause, "Should find Department clause")
		assert.Len(t, deptClause.Values, 2, "Department should have 2 values")

		// Find Level clause
		var levelClause *AttributeClause
		for i := range expr.Clauses {
			if expr.Clauses[i].Definition.GetName() == "Level" {
				levelClause = &expr.Clauses[i]
				break
			}
		}
		require.NotNil(t, levelClause, "Should find Level clause")
		assert.Len(t, levelClause.Values, 1, "Level should have 1 value")
	})

	t.Run("clauses sorted deterministically", func(t *testing.T) {
		// Create values that would sort differently depending on order
		values := []*policy.Value{
			createMockValue("https://test.com/attr/ZZZ/value/Last", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			createMockValue("https://test.com/attr/AAA/value/First", kasUk, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF),
			createMockValue("https://test.com/attr/MMM/value/Middle", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
		}

		expr1, err := buildBooleanExpression(values)
		require.NoError(t, err)

		// Reverse the order and build again
		reversedValues := make([]*policy.Value, len(values))
		for i, v := range values {
			reversedValues[len(values)-1-i] = v
		}

		expr2, err := buildBooleanExpression(reversedValues)
		require.NoError(t, err)

		// Should be identical regardless of input order
		assert.Len(t, expr2.Clauses, len(expr1.Clauses))
		for i := range expr1.Clauses {
			assert.Equal(t, expr1.Clauses[i].Definition.GetFqn(), expr2.Clauses[i].Definition.GetFqn())
		}
	})
}
