package access

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fqnBuilder(n string, a string, v string) string {
	fqn := "https://"
	switch {
	case n != "" && a != "" && v != "":
		return fqn + n + "/attr/" + a + "/value/" + v
	case n != "" && a != "" && v == "":
		return fqn + n + "/attr/" + a
	case n != "" && a == "":
		return fqn + n
	default:
		panic("Invalid FQN")
	}
}

func createMockEntityAttributes(entityID, namespace, name string, values []string) map[string][]string {
	attrs := make(map[string][]string)
	for _, value := range values {
		attrs[entityID] = append(attrs[entityID], fqnBuilder(namespace, name, value))
	}
	return attrs
}

func createMockAttribute(namespace, name string, rule policy.AttributeRuleTypeEnum, values []string) *policy.Attribute {
	attr := &policy.Attribute{
		Name: name,
		Namespace: &policy.Namespace{
			Name: namespace,
		},
		Rule: rule,
		Fqn:  fqnBuilder(namespace, name, ""),
	}
	for _, value := range values {
		attr.Values = append(attr.Values, &policy.Value{
			Value: value,
			Fqn:   fqnBuilder(namespace, name, value),
		})
	}
	return attr
}

// Refactored test structure to use table-driven tests and group related tests logically
func Test_AccessPDP_AnyOf(t *testing.T) {
	values := []string{"value1", "value2", "value3"}
	definition := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, values)
	tests := []struct {
		name           string
		entityAttrs    map[string][]string
		dataAttrs      []*policy.Value
		expectedAccess bool
		expectedPass   bool
	}{
		{
			name:           "Pass - all definition values, all entitlements",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), values),
			dataAttrs:      definition.Values,
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - subset of definition values, all entitlements",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), values),
			dataAttrs:      definition.Values[1:],
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - subset of definition values, matching entititlements",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), values[1:]),
			dataAttrs:      definition.Values[1:],
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - subset definition values, matching entitlements + extraneous entitlement",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"random_value", values[0]}),
			dataAttrs:      []*policy.Value{definition.Values[0]},
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name: "Pass - all definition values, matching entitlements + extraneous entitlement",
			entityAttrs: map[string][]string{"entity1": {
				fqnBuilder("example.org", "myattr", "random_value"),
				fqnBuilder(definition.GetNamespace().GetName(), definition.GetName(), values[0]),
			}},
			dataAttrs:      definition.Values,
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Fail - all definition values, no matching entitlements, extraneous definition entitlement value",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"random_value"}),
			dataAttrs:      definition.Values,
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - all definition values, wrong definition name",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), "random_definition_name", values),
			dataAttrs:      definition.Values,
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - all definition values, wrong namespace",
			entityAttrs:    createMockEntityAttributes("entity1", "wrong.namespace", definition.GetName(), values),
			dataAttrs:      definition.Values,
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - all definition values, no entitlements at all",
			entityAttrs:    map[string][]string{"entity1": {}},
			dataAttrs:      definition.Values,
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - subset definition values, no entitlements at all",
			entityAttrs:    map[string][]string{"entity1": {}},
			dataAttrs:      definition.Values[1:],
			expectedAccess: false,
			expectedPass:   false,
		},
		// {
		// 	name:           "Fail - no data attributes",
		// 	entityAttrs:    createMockEntityAttributes("entity1", "example.org", "myattr", []string{"value1"}),
		// 	dataAttrs:      []*policy.Value{},
		// 	expectedAccess: false,
		// 	expectedPass:   false,
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdp := NewPdp(logger.CreateTestLogger())
			decisions, err := pdp.DetermineAccess(t.Context(), tt.dataAttrs, tt.entityAttrs, []*policy.Attribute{definition})

			require.NoError(t, err)
			if tt.expectedAccess {
				assert.True(t, decisions["entity1"].Access)
			} else {
				assert.False(t, decisions["entity1"].Access)
			}
			if len(decisions["entity1"].Results) > 0 {
				assert.Equal(t, tt.expectedPass, decisions["entity1"].Results[0].Passed)
			}
		})
	}
}

func Test_AccessPDP_Hierarchy(t *testing.T) {
	values := []string{"highest", "middle", "lowest"}
	definition := createMockAttribute("somewhere.net", "theirattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, values)
	tests := []struct {
		name           string
		entityAttrs    map[string][]string
		dataAttrs      []*policy.Value
		expectedAccess bool
		expectedPass   bool
	}{
		{
			name:           "Pass - highest privilege level data, highest entitlement",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"highest"}),
			dataAttrs:      definition.Values,
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - middle privilege level data, middle entitlement",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"middle"}),
			dataAttrs:      []*policy.Value{definition.Values[1]},
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - middle privilege level data, highest entitlement",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"highest"}),
			dataAttrs:      []*policy.Value{definition.Values[1]},
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - lowest privilege level data, lowest entitlement",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"lowest"}),
			dataAttrs:      []*policy.Value{definition.Values[2]},
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - lowest privilege level data, middle entitlement",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"lowest"}),
			dataAttrs:      []*policy.Value{definition.Values[2]},
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - lowest privilege level data, highest entitlement",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"lowest"}),
			dataAttrs:      []*policy.Value{definition.Values[2]},
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Fail - wrong namespace",
			entityAttrs:    createMockEntityAttributes("entity1", "wrongnamespace.net", definition.GetName(), []string{"highest"}),
			dataAttrs:      definition.Values,
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - wrong definition name",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), "wrong_definition_name", []string{"highest"}),
			dataAttrs:      definition.Values,
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - no matching entitlements",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"random_value"}),
			dataAttrs:      definition.Values,
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - no entitlements at all",
			entityAttrs:    map[string][]string{"entity1": {}},
			dataAttrs:      definition.Values,
			expectedAccess: false,
			expectedPass:   false,
		},
		// {
		// 	name:           "Fail - no data attributes",
		// 	entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"highest"}),
		// 	dataAttrs:      []*policy.Value{},
		// 	expectedAccess: false,
		// 	expectedPass:   false,
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdp := NewPdp(logger.CreateTestLogger())
			decisions, err := pdp.DetermineAccess(t.Context(), tt.dataAttrs, tt.entityAttrs, []*policy.Attribute{definition})

			require.NoError(t, err)
			if tt.expectedAccess {
				assert.True(t, decisions["entity1"].Access)
			} else {
				assert.False(t, decisions["entity1"].Access)
			}
			if len(decisions["entity1"].Results) > 0 {
				assert.Equal(t, tt.expectedPass, decisions["entity1"].Results[0].Passed)
			}
		})
	}
}

func Test_AccessPDP_AllOf(t *testing.T) {
	values := []string{"value1", "value2", "value3"}
	definition := createMockAttribute("example.com", "allofattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF, values)
	tests := []struct {
		name           string
		entityAttrs    map[string][]string
		dataAttrs      []*policy.Value
		expectedAccess bool
		expectedPass   bool
	}{
		{
			name:           "Pass - all definition values match entitlements",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), values),
			dataAttrs:      definition.Values,
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Fail - missing one definition value in entitlements",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), values[:2]),
			dataAttrs:      definition.Values,
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - no matching entitlements",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"random_value"}),
			dataAttrs:      definition.Values,
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - wrong namespace",
			entityAttrs:    createMockEntityAttributes("entity1", "wrongnamespace.com", definition.GetName(), values),
			dataAttrs:      definition.Values,
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - no entitlements at all",
			entityAttrs:    map[string][]string{"entity1": {}},
			dataAttrs:      definition.Values,
			expectedAccess: false,
			expectedPass:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdp := NewPdp(logger.CreateTestLogger())
			decisions, err := pdp.DetermineAccess(t.Context(), tt.dataAttrs, tt.entityAttrs, []*policy.Attribute{definition})

			require.NoError(t, err)
			if tt.expectedAccess {
				assert.True(t, decisions["entity1"].Access)
			} else {
				assert.False(t, decisions["entity1"].Access)
			}
			if len(decisions["entity1"].Results) > 0 {
				assert.Equal(t, tt.expectedPass, decisions["entity1"].Results[0].Passed)
			}
		})
	}
}

func Test_DetermineAccess_EmptyDataAttributes(t *testing.T) {
	pdp := NewPdp(logger.CreateTestLogger())
	decisions, err := pdp.DetermineAccess(t.Context(), []*policy.Value{}, map[string][]string{}, []*policy.Attribute{})

	require.NoError(t, err)
	assert.Empty(t, decisions)
}

// func Test_DetermineAccess_EmptyAttributeDefinitions(t *testing.T) {
// 	pdp := NewPdp(logger.CreateTestLogger())
// 	dataAttrs := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{"value1"}).Values
// 	entityAttrs := createMockEntityAttributes("entity1", "example.org", "myattr", []string{"value1"})

// 	decisions, err := pdp.DetermineAccess(t.Context(), dataAttrs, entityAttrs, []*policy.Attribute{})

// 	require.NoError(t, err)
// 	assert.Empty(t, decisions)
// }

func Test_GroupDataAttributesByDefinition(t *testing.T) {
	dataAttrs := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{"value1", "value2"}).Values
	pdp := NewPdp(logger.CreateTestLogger())

	grouped, err := pdp.groupDataAttributesByDefinition(t.Context(), dataAttrs)

	require.NoError(t, err)
	assert.Len(t, grouped, 1)
	assert.Contains(t, grouped, "https://example.org/attr/myattr")
}

func Test_MapFqnToDefinitions(t *testing.T) {
	attr := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{"value1"})
	pdp := NewPdp(logger.CreateTestLogger())

	mapped, err := pdp.mapFqnToDefinitions([]*policy.Attribute{attr})

	require.NoError(t, err)
	assert.Len(t, mapped, 1)
	assert.Contains(t, mapped, "https://example.org/attr/myattr")
}

func Test_GetHighestRankedInstanceFromDataAttributes(t *testing.T) {
	order := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, []string{"high", "medium", "low"}).Values
	dataAttrs := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, []string{"medium"}).Values
	pdp := NewPdp(logger.CreateTestLogger())

	highest, err := pdp.getHighestRankedInstanceFromDataAttributes(t.Context(), order, dataAttrs, logger.CreateTestLogger())

	require.NoError(t, err)
	assert.NotNil(t, highest)
	assert.Equal(t, "medium", highest.GetValue())
}

func Test_GetIsValueFoundInFqnValuesSet(t *testing.T) {
	value := &policy.Value{
		Value: "value1",
		Fqn:   "https://example.org/attr/myattr/value/value1",
	}
	fqns := []string{"https://example.org/attr/myattr/value/value1", "https://example.org/attr/myattr/value/value2"}

	found := getIsValueFoundInFqnValuesSet(value, fqns, logger.CreateTestLogger())
	assert.True(t, found)
}

// func Test_EntityRankGreaterThanOrEqualToDataRank(t *testing.T) {
// 	order := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, []string{"low", "medium", "high"}).Values
// 	dataAttr := &policy.Value{
// 		Value: "medium",
// 		Fqn:   "https://example.org/attr/myattr/value/medium",
// 	}
// 	entityFqns := []string{"https://example.org/attr/myattr/value/high"}

// 	result, err := entityRankGreaterThanOrEqualToDataRank(order, dataAttr, entityFqns, logger.CreateTestLogger())

// 	require.NoError(t, err)
// 	assert.True(t, result)
// }

func Test_RollUpDecisions(t *testing.T) {
	tests := []struct {
		name               string
		entityRuleDecision map[string]DataRuleResult
		attrDefinition     *policy.Attribute
		existingDecisions  map[string]*Decision
		expectedDecisions  map[string]*Decision
	}{
		{
			name: "New entity decision",
			entityRuleDecision: map[string]DataRuleResult{
				"entity1": {
					Passed:         true,
					RuleDefinition: createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{}),
					ValueFailures:  nil,
				},
			},
			attrDefinition:    createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{}),
			existingDecisions: map[string]*Decision{},
			expectedDecisions: map[string]*Decision{
				"entity1": {
					Access: true,
					Results: []DataRuleResult{
						{
							Passed:         true,
							RuleDefinition: createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{}),
							ValueFailures:  nil,
						},
					},
				},
			},
		},
		{
			name: "Update existing entity decision",
			entityRuleDecision: map[string]DataRuleResult{
				"entity1": {
					Passed:         false,
					RuleDefinition: createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{}),
					ValueFailures:  nil,
				},
			},
			attrDefinition: createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{}),
			existingDecisions: map[string]*Decision{
				"entity1": {
					Access: true,
					Results: []DataRuleResult{
						{
							Passed:         true,
							RuleDefinition: createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{}),
							ValueFailures:  nil,
						},
					},
				},
			},
			expectedDecisions: map[string]*Decision{
				"entity1": {
					Access: false,
					Results: []DataRuleResult{
						{
							Passed:         true,
							RuleDefinition: createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{}),
							ValueFailures:  nil,
						},
						{
							Passed:         false,
							RuleDefinition: createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{}),
							ValueFailures:  nil,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decisions := tt.existingDecisions
			pdp := NewPdp(logger.CreateTestLogger())
			pdp.rollUpDecisions(tt.entityRuleDecision, tt.attrDefinition, decisions)

			assert.Equal(t, tt.expectedDecisions, decisions)
		})
	}
}
