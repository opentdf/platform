package access

import (
	"context"
	"fmt"
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

func createTestLogger() *logger.Logger {
	l, _ := logger.NewLogger(
		logger.Config{
			Level:  "info", // debug is too noisy for benchmarks
			Output: "stdout",
			Type:   "json",
		},
	)
	return l
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
		attr.Values = append(attr.GetValues(), &policy.Value{
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
			dataAttrs:      definition.GetValues(),
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - subset of definition values, all entitlements",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), values),
			dataAttrs:      definition.GetValues()[1:],
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - subset of definition values, matching entititlements",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), values[1:]),
			dataAttrs:      definition.GetValues()[1:],
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - subset definition values, matching entitlements + extraneous entitlement",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"random_value", values[0]}),
			dataAttrs:      []*policy.Value{definition.GetValues()[0]},
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name: "Pass - all definition values, matching entitlements + extraneous entitlement",
			entityAttrs: map[string][]string{"entity1": {
				fqnBuilder("example.org", "myattr", "random_value"),
				fqnBuilder(definition.GetNamespace().GetName(), definition.GetName(), values[0]),
			}},
			dataAttrs:      definition.GetValues(),
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Fail - all definition values, no matching entitlements, extraneous definition entitlement value",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"random_value"}),
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - all definition values, wrong definition name",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), "random_definition_name", values),
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - all definition values, wrong namespace",
			entityAttrs:    createMockEntityAttributes("entity1", "wrong.namespace", definition.GetName(), values),
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - all definition values, no entitlements at all",
			entityAttrs:    map[string][]string{"entity1": {}},
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - subset definition values, no entitlements at all",
			entityAttrs:    map[string][]string{"entity1": {}},
			dataAttrs:      definition.GetValues()[1:],
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
			pdp := NewPdp(createTestLogger())
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
			dataAttrs:      definition.GetValues(),
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - middle privilege level data, middle entitlement",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"middle"}),
			dataAttrs:      []*policy.Value{definition.GetValues()[1]},
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - middle privilege level data, highest entitlement",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"highest"}),
			dataAttrs:      []*policy.Value{definition.GetValues()[1]},
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - lowest privilege level data, lowest entitlement",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"lowest"}),
			dataAttrs:      []*policy.Value{definition.GetValues()[2]},
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - lowest privilege level data, middle entitlement",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"lowest"}),
			dataAttrs:      []*policy.Value{definition.GetValues()[2]},
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - lowest privilege level data, highest entitlement",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"lowest"}),
			dataAttrs:      []*policy.Value{definition.GetValues()[2]},
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Fail - wrong namespace",
			entityAttrs:    createMockEntityAttributes("entity1", "wrongnamespace.net", definition.GetName(), []string{"highest"}),
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - wrong definition name",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), "wrong_definition_name", []string{"highest"}),
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - no matching entitlements",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"random_value"}),
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - no entitlements at all",
			entityAttrs:    map[string][]string{"entity1": {}},
			dataAttrs:      definition.GetValues(),
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
			pdp := NewPdp(createTestLogger())
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
			dataAttrs:      definition.GetValues(),
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Fail - missing one definition value in entitlements",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), values[:2]),
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - no matching entitlements",
			entityAttrs:    createMockEntityAttributes("entity1", definition.GetNamespace().GetName(), definition.GetName(), []string{"random_value"}),
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - wrong namespace",
			entityAttrs:    createMockEntityAttributes("entity1", "wrongnamespace.com", definition.GetName(), values),
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - no entitlements at all",
			entityAttrs:    map[string][]string{"entity1": {}},
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdp := NewPdp(createTestLogger())
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
	pdp := NewPdp(createTestLogger())
	decisions, err := pdp.DetermineAccess(t.Context(), []*policy.Value{}, map[string][]string{}, []*policy.Attribute{})

	require.NoError(t, err)
	assert.Empty(t, decisions)
}

// func Test_DetermineAccess_EmptyAttributeDefinitions(t *testing.T) {
// 	pdp := NewPdp(createTestLogger())
// 	dataAttrs := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{"value1"}).GetValues()
// 	entityAttrs := createMockEntityAttributes("entity1", "example.org", "myattr", []string{"value1"})

// 	decisions, err := pdp.DetermineAccess(t.Context(), dataAttrs, entityAttrs, []*policy.Attribute{})

// 	require.NoError(t, err)
// 	assert.Empty(t, decisions)
// }

func Test_GroupDataAttributesByDefinition(t *testing.T) {
	dataAttrs := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{"value1", "value2"}).GetValues()
	pdp := NewPdp(createTestLogger())

	grouped, err := pdp.groupDataAttributesByDefinition(t.Context(), dataAttrs)

	require.NoError(t, err)
	assert.Len(t, grouped, 1)
	assert.Contains(t, grouped, "https://example.org/attr/myattr")
}

func Test_MapFqnToDefinitions(t *testing.T) {
	attr := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{"value1"})
	pdp := NewPdp(createTestLogger())

	mapped, err := pdp.mapFqnToDefinitions([]*policy.Attribute{attr})

	require.NoError(t, err)
	assert.Len(t, mapped, 1)
	assert.Contains(t, mapped, "https://example.org/attr/myattr")
}

func Test_GetHighestRankedInstanceFromDataAttributes(t *testing.T) {
	order := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, []string{"high", "medium", "low"}).GetValues()
	dataAttrs := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, []string{"medium"}).GetValues()
	pdp := NewPdp(createTestLogger())

	highest, err := pdp.getHighestRankedInstanceFromDataAttributes(order, dataAttrs)

	require.NoError(t, err)
	assert.NotNil(t, highest)
	assert.Equal(t, "medium", highest.GetValue())
}

// func Test_EntityRankGreaterThanOrEqualToDataRank(t *testing.T) {
// 	order := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, []string{"low", "medium", "high"}).GetValues()
// 	dataAttr := &policy.Value{
// 		Value: "medium",
// 		Fqn:   "https://example.org/attr/myattr/value/medium",
// 	}
// 	entityFqns := []string{"https://example.org/attr/myattr/value/high"}

// 	result, err := entityRankGreaterThanOrEqualToDataRank(order, dataAttr, entityFqns, createTestLogger())

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
			pdp := NewPdp(createTestLogger())
			pdp.rollUpDecisions(tt.entityRuleDecision, tt.attrDefinition, decisions)

			assert.Equal(t, tt.expectedDecisions, decisions)
		})
	}
}

func BenchmarkPdp(b *testing.B) {
	benchmarks := []struct {
		name        string
		dataAttrs   []*policy.Value
		entityAttrs map[string][]string
		attrDefs    []*policy.Attribute
	}{
		// AnyOf benchmarks
		{
			name: "small_anyof",
			dataAttrs: createMockAttribute("example.org", "myattr",
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
				[]string{"value1", "value2"}).GetValues(),
			entityAttrs: createMockEntityAttributes("entity1", "example.org", "myattr",
				[]string{"value1"}),
			attrDefs: []*policy.Attribute{
				createMockAttribute("example.org", "myattr",
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
					[]string{"value1", "value2"}),
			},
		},
		{
			name: "medium_anyof",
			dataAttrs: createMockAttribute("example.org", "myattr",
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
				[]string{"value1", "value2", "value3", "value4", "value5"}).GetValues(),
			entityAttrs: func() map[string][]string {
				attrs := make(map[string][]string)
				for i := range 10 {
					entityID := fmt.Sprintf("entity%d", i)
					attrs[entityID] = []string{
						fqnBuilder("example.org", "myattr", "value1"),
						fqnBuilder("example.org", "myattr", "value2"),
					}
				}
				return attrs
			}(),
			attrDefs: []*policy.Attribute{
				createMockAttribute("example.org", "myattr",
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
					[]string{"value1", "value2", "value3", "value4", "value5"}),
			},
		},
		{
			name: "large_anyof",
			dataAttrs: createMockAttribute("example.org", "myattr",
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
				[]string{"value1", "value2", "value3", "value4", "value5", "value6", "value7", "value8", "value9", "value10"}).GetValues(),
			entityAttrs: func() map[string][]string {
				attrs := make(map[string][]string)
				for i := range 100 {
					entityID := fmt.Sprintf("entity%d", i)
					attrs[entityID] = []string{
						fqnBuilder("example.org", "myattr", "value1"),
						fqnBuilder("example.org", "myattr", "value2"),
						fqnBuilder("example.org", "myattr", "value3"),
					}
				}
				return attrs
			}(),
			attrDefs: []*policy.Attribute{
				createMockAttribute("example.org", "myattr",
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
					[]string{"value1", "value2", "value3", "value4", "value5", "value6", "value7", "value8", "value9", "value10"}),
			},
		},

		// AllOf benchmarks
		{
			name: "small_allof",
			dataAttrs: createMockAttribute("authority.gov", "allofattr",
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
				[]string{"value1", "value2"}).GetValues(),
			entityAttrs: createMockEntityAttributes("entity1", "authority.gov", "allofattr",
				[]string{"value1", "value2"}),
			attrDefs: []*policy.Attribute{
				createMockAttribute("authority.gov", "allofattr",
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					[]string{"value1", "value2"}),
			},
		},
		{
			name: "medium_allof",
			dataAttrs: createMockAttribute("authority.gov", "allofattr",
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
				[]string{"value1", "value2", "value3", "value4", "value5"}).GetValues(),
			entityAttrs: func() map[string][]string {
				attrs := make(map[string][]string)
				for i := range 10 {
					entityID := fmt.Sprintf("entity%d", i)
					attrs[entityID] = []string{
						fqnBuilder("authority.gov", "allofattr", "value1"),
						fqnBuilder("authority.gov", "allofattr", "value2"),
						fqnBuilder("authority.gov", "allofattr", "value3"),
						fqnBuilder("authority.gov", "allofattr", "value4"),
						fqnBuilder("authority.gov", "allofattr", "value5"),
					}
				}
				return attrs
			}(),
			attrDefs: []*policy.Attribute{
				createMockAttribute("authority.gov", "allofattr",
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					[]string{"value1", "value2", "value3", "value4", "value5"}),
			},
		},
		{
			name: "large_allof",
			dataAttrs: createMockAttribute("authority.gov", "allofattr",
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
				[]string{"value1", "value2", "value3", "value4", "value5", "value6", "value7", "value8", "value9", "value10"}).GetValues(),
			entityAttrs: func() map[string][]string {
				attrs := make(map[string][]string)
				for i := range 100 {
					entityID := fmt.Sprintf("entity%d", i)
					values := []string{"value1", "value2", "value3", "value4", "value5", "value6", "value7", "value8", "value9", "value10"}
					for _, v := range values {
						attrs[entityID] = append(attrs[entityID], fqnBuilder("authority.gov", "allofattr", v))
					}
				}
				return attrs
			}(),
			attrDefs: []*policy.Attribute{
				createMockAttribute("authority.gov", "allofattr",
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					[]string{"value1", "value2", "value3", "value4", "value5", "value6", "value7", "value8", "value9", "value10"}),
			},
		},

		// Hierarchy benchmarks
		{
			name: "small_hierarchy",
			dataAttrs: createMockAttribute("somewhere.net", "theirattr",
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
				[]string{"level1", "level2"}).GetValues(),
			entityAttrs: createMockEntityAttributes("entity1", "somewhere.net", "theirattr",
				[]string{"level1"}),
			attrDefs: []*policy.Attribute{
				createMockAttribute("somewhere.net", "theirattr",
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
					[]string{"level1", "level2"}),
			},
		},
		{
			name: "medium_hierarchy",
			dataAttrs: createMockAttribute("somewhere.net", "theirattr",
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
				[]string{"level1", "level2", "level3", "level4", "level5"}).GetValues(),
			entityAttrs: func() map[string][]string {
				attrs := make(map[string][]string)
				for i := range 10 {
					entityID := fmt.Sprintf("entity%d", i)
					attrs[entityID] = []string{
						fqnBuilder("somewhere.net", "theirattr", "level1"),
					}
				}
				return attrs
			}(),
			attrDefs: []*policy.Attribute{
				createMockAttribute("somewhere.net", "theirattr",
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
					[]string{"level1", "level2", "level3", "level4", "level5"}),
			},
		},
		{
			name: "large_hierarchy",
			dataAttrs: createMockAttribute("somewhere.net", "theirattr",
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
				[]string{"level1", "level2", "level3", "level4", "level5", "level6", "level7", "level8", "level9", "level10"}).GetValues(),
			entityAttrs: func() map[string][]string {
				attrs := make(map[string][]string)
				for i := range 100 {
					entityID := fmt.Sprintf("entity%d", i)
					attrs[entityID] = []string{
						fqnBuilder("somewhere.net", "theirattr", "level1"),
					}
				}
				return attrs
			}(),
			attrDefs: []*policy.Attribute{
				createMockAttribute("somewhere.net", "theirattr",
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
					[]string{"level1", "level2", "level3", "level4", "level5", "level6", "level7", "level8", "level9", "level10"}),
			},
		},
	}
	pdp := NewPdp(createTestLogger())
	ctx := context.Background()

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, err := pdp.DetermineAccess(ctx, bm.dataAttrs, bm.entityAttrs, bm.attrDefs)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDetermineAccessFailures(b *testing.B) {
	benchmarks := []struct {
		name        string
		dataAttrs   []*policy.Value
		entityAttrs map[string][]string
		attrDefs    []*policy.Attribute
	}{
		// AnyOf failure benchmarks
		{
			name: "small_anyof_failure",
			dataAttrs: createMockAttribute("example.org", "myattr",
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
				[]string{"value1", "value2"}).GetValues(),
			entityAttrs: createMockEntityAttributes("entity1", "example.org", "myattr",
				[]string{"value3", "value4"}), // No match with data attributes
			attrDefs: []*policy.Attribute{
				createMockAttribute("example.org", "myattr",
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
					[]string{"value1", "value2"}),
			},
		},
		{
			name: "medium_anyof_failure",
			dataAttrs: createMockAttribute("example.org", "myattr",
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
				[]string{"value1", "value2", "value3", "value4", "value5"}).GetValues(),
			entityAttrs: func() map[string][]string {
				attrs := make(map[string][]string)
				for i := 0; i < 10; i++ {
					entityID := fmt.Sprintf("entity%d", i)
					attrs[entityID] = []string{
						fqnBuilder("example.org", "myattr", "value6"),
						fqnBuilder("example.org", "myattr", "value7"),
					}
				}
				return attrs
			}(),
			attrDefs: []*policy.Attribute{
				createMockAttribute("example.org", "myattr",
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
					[]string{"value1", "value2", "value3", "value4", "value5"}),
			},
		},

		// AllOf failure benchmarks
		{
			name: "small_allof_failure",
			dataAttrs: createMockAttribute("authority.gov", "allofattr",
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
				[]string{"value1", "value2"}).GetValues(),
			entityAttrs: createMockEntityAttributes("entity1", "authority.gov", "allofattr",
				[]string{"value1"}), // Missing value2
			attrDefs: []*policy.Attribute{
				createMockAttribute("authority.gov", "allofattr",
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					[]string{"value1", "value2"}),
			},
		},
		{
			name: "medium_allof_failure",
			dataAttrs: createMockAttribute("authority.gov", "allofattr",
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
				[]string{"value1", "value2", "value3", "value4", "value5"}).GetValues(),
			entityAttrs: func() map[string][]string {
				attrs := make(map[string][]string)
				for i := 0; i < 10; i++ {
					entityID := fmt.Sprintf("entity%d", i)
					attrs[entityID] = []string{
						fqnBuilder("authority.gov", "allofattr", "value1"),
						fqnBuilder("authority.gov", "allofattr", "value2"),
						fqnBuilder("authority.gov", "allofattr", "value3"),
						// Missing value4 and value5
					}
				}
				return attrs
			}(),
			attrDefs: []*policy.Attribute{
				createMockAttribute("authority.gov", "allofattr",
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					[]string{"value1", "value2", "value3", "value4", "value5"}),
			},
		},

		// Hierarchy failure benchmarks
		{
			name: "small_hierarchy_failure",
			dataAttrs: createMockAttribute("somewhere.net", "theirattr",
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
				[]string{"level1", "level2"}).GetValues(),
			entityAttrs: createMockEntityAttributes("entity1", "somewhere.net", "theirattr",
				[]string{"level2"}), // Lower level than required
			attrDefs: []*policy.Attribute{
				createMockAttribute("somewhere.net", "theirattr",
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
					[]string{"level1", "level2"}),
			},
		},
		{
			name: "medium_hierarchy_failure",
			dataAttrs: createMockAttribute("somewhere.net", "theirattr",
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
				[]string{"level1", "level2", "level3", "level4", "level5"}).GetValues()[0:1], // Just level1
			entityAttrs: func() map[string][]string {
				attrs := make(map[string][]string)
				for i := 0; i < 10; i++ {
					entityID := fmt.Sprintf("entity%d", i)
					attrs[entityID] = []string{
						fqnBuilder("somewhere.net", "theirattr", "level3"),
					}
				}
				return attrs
			}(),
			attrDefs: []*policy.Attribute{
				createMockAttribute("somewhere.net", "theirattr",
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
					[]string{"level1", "level2", "level3", "level4", "level5"}),
			},
		},

		// Wrong namespace/attribute failure
		{
			name: "wrong_namespace_failure",
			dataAttrs: createMockAttribute("example.org", "myattr",
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
				[]string{"value1", "value2"}).GetValues(),
			entityAttrs: createMockEntityAttributes("entity1", "wrong.org", "myattr",
				[]string{"value1", "value2"}),
			attrDefs: []*policy.Attribute{
				createMockAttribute("example.org", "myattr",
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
					[]string{"value1", "value2"}),
			},
		},
		{
			name: "no_matching_attributes_failure",
			dataAttrs: createMockAttribute("example.org", "myattr",
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
				[]string{"value1", "value2"}).GetValues(),
			entityAttrs: map[string][]string{"entity1": {}}, // No attributes at all
			attrDefs: []*policy.Attribute{
				createMockAttribute("example.org", "myattr",
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
					[]string{"value1", "value2"}),
			},
		},
	}

	pdp := NewPdp(createTestLogger())
	ctx := context.Background()

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := pdp.DetermineAccess(ctx, bm.dataAttrs, bm.entityAttrs, bm.attrDefs)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Add benchmarks for individual rule function failure cases
func BenchmarkAnyOfRuleFail(b *testing.B) {
	pdp := NewPdp(createTestLogger())
	ctx := context.Background()

	// Create test data - values that won't match
	dataAttrs := createMockAttribute("example.org", "myattr",
		policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		[]string{"value1", "value2", "value3", "value4", "value5"}).GetValues()

	entityAttrs := make(map[string][]string)
	for i := 0; i < 100; i++ {
		entityID := fmt.Sprintf("entity%d", i)
		entityAttrs[entityID] = []string{
			fqnBuilder("example.org", "myattr", "value6"),
			fqnBuilder("example.org", "myattr", "value7"),
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := pdp.anyOfRule(ctx, dataAttrs, entityAttrs)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAllOfRuleFail(b *testing.B) {
	pdp := NewPdp(createTestLogger())
	ctx := context.Background()

	// Create test data - missing some required values
	dataAttrs := createMockAttribute("authority.gov", "allofattr",
		policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		[]string{"value1", "value2", "value3", "value4", "value5"}).GetValues()

	entityAttrs := make(map[string][]string)
	for i := 0; i < 100; i++ {
		entityID := fmt.Sprintf("entity%d", i)
		values := []string{"value1", "value2"} // Missing values 3, 4, 5
		entityAttrs[entityID] = []string{}
		for _, v := range values {
			entityAttrs[entityID] = append(entityAttrs[entityID], fqnBuilder("authority.gov", "allofattr", v))
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := pdp.allOfRule(ctx, dataAttrs, entityAttrs)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHierarchyRuleFail(b *testing.B) {
	pdp := NewPdp(createTestLogger())
	ctx := context.Background()

	// Create test data
	attr := createMockAttribute("somewhere.net", "theirattr",
		policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		[]string{"level1", "level2", "level3", "level4", "level5"})

	dataAttrs := attr.GetValues()[:1] // Only get level1 (highest privilege)
	order := attr.GetValues()

	entityAttrs := make(map[string][]string)
	for i := 0; i < 100; i++ {
		entityID := fmt.Sprintf("entity%d", i)
		entityAttrs[entityID] = []string{
			fqnBuilder("somewhere.net", "theirattr", "level3"), // Lower privilege than needed
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := pdp.hierarchyRule(ctx, dataAttrs, entityAttrs, order)
		if err != nil {
			b.Fatal(err)
		}
	}
}
