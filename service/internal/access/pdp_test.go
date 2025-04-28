package access

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const mockEntityID = "entity1"

func createTestLogger() *logger.Logger {
	// use defaults - debug is too noisy
	l, err := logger.NewLogger(logger.Config{
		Level:  "info",
		Type:   "json",
		Output: "stdout",
	})
	if err != nil {
		panic("Failed to create logger")
	}
	return l
}

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

func createMockEntity1Attributes(namespace, name string, values []string) map[string][]string {
	attrs := make(map[string][]string)
	for _, value := range values {
		attrs[mockEntityID] = append(attrs[mockEntityID], fqnBuilder(namespace, name, value))
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
			entityAttrs:    createMockEntity1Attributes(definition.GetNamespace().GetName(), definition.GetName(), values),
			dataAttrs:      definition.GetValues(),
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - subset of definition values, all entitlements",
			entityAttrs:    createMockEntity1Attributes(definition.GetNamespace().GetName(), definition.GetName(), values),
			dataAttrs:      definition.GetValues()[1:],
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - subset of definition values, matching entititlements",
			entityAttrs:    createMockEntity1Attributes(definition.GetNamespace().GetName(), definition.GetName(), values[1:]),
			dataAttrs:      definition.GetValues()[1:],
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - subset definition values, matching entitlements + extraneous entitlement",
			entityAttrs:    createMockEntity1Attributes(definition.GetNamespace().GetName(), definition.GetName(), []string{"random_value", values[0]}),
			dataAttrs:      []*policy.Value{definition.GetValues()[0]},
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name: "Pass - all definition values, matching entitlements + extraneous entitlement",
			entityAttrs: map[string][]string{mockEntityID: {
				fqnBuilder("example.org", "myattr", "random_value"),
				fqnBuilder(definition.GetNamespace().GetName(), definition.GetName(), values[0]),
			}},
			dataAttrs:      definition.GetValues(),
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Fail - all definition values, no matching entitlements, extraneous definition entitlement value",
			entityAttrs:    createMockEntity1Attributes(definition.GetNamespace().GetName(), definition.GetName(), []string{"random_value"}),
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - all definition values, wrong definition name",
			entityAttrs:    createMockEntity1Attributes(definition.GetNamespace().GetName(), "random_definition_name", values),
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - all definition values, wrong namespace",
			entityAttrs:    createMockEntity1Attributes("wrong.namespace", definition.GetName(), values),
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - all definition values, no entitlements at all",
			entityAttrs:    map[string][]string{mockEntityID: {}},
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - subset definition values, no entitlements at all",
			entityAttrs:    map[string][]string{mockEntityID: {}},
			dataAttrs:      definition.GetValues()[1:],
			expectedAccess: false,
			expectedPass:   false,
		},
	}

	pdp := NewPdp(createTestLogger())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decisions, err := pdp.DetermineAccess(t.Context(), tt.dataAttrs, tt.entityAttrs, []*policy.Attribute{definition})

			require.NoError(t, err)
			if tt.expectedAccess {
				assert.True(t, decisions[mockEntityID].Access)
			} else {
				assert.False(t, decisions[mockEntityID].Access)
			}
			if len(decisions[mockEntityID].Results) > 0 {
				assert.Equal(t, tt.expectedPass, decisions[mockEntityID].Results[0].Passed)
			}
		})
	}

	// Test for empty data attributes
	entityAttrs := createMockEntity1Attributes(definition.GetNamespace().GetName(), definition.GetName(), []string{"highest"})
	emptyDataAttrs := []*policy.Value{}
	decisions, err := pdp.DetermineAccess(t.Context(), emptyDataAttrs, entityAttrs, []*policy.Attribute{definition})
	require.Error(t, err)
	assert.Empty(t, decisions)
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
			entityAttrs:    createMockEntity1Attributes(definition.GetNamespace().GetName(), definition.GetName(), []string{"highest"}),
			dataAttrs:      definition.GetValues(),
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - middle privilege level data, middle entitlement",
			entityAttrs:    createMockEntity1Attributes(definition.GetNamespace().GetName(), definition.GetName(), []string{"middle"}),
			dataAttrs:      []*policy.Value{definition.GetValues()[1]},
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - middle privilege level data, highest entitlement",
			entityAttrs:    createMockEntity1Attributes(definition.GetNamespace().GetName(), definition.GetName(), []string{"highest"}),
			dataAttrs:      []*policy.Value{definition.GetValues()[1]},
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - lowest privilege level data, lowest entitlement",
			entityAttrs:    createMockEntity1Attributes(definition.GetNamespace().GetName(), definition.GetName(), []string{"lowest"}),
			dataAttrs:      []*policy.Value{definition.GetValues()[2]},
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - lowest privilege level data, middle entitlement",
			entityAttrs:    createMockEntity1Attributes(definition.GetNamespace().GetName(), definition.GetName(), []string{"lowest"}),
			dataAttrs:      []*policy.Value{definition.GetValues()[2]},
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Pass - lowest privilege level data, highest entitlement",
			entityAttrs:    createMockEntity1Attributes(definition.GetNamespace().GetName(), definition.GetName(), []string{"lowest"}),
			dataAttrs:      []*policy.Value{definition.GetValues()[2]},
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Fail - wrong namespace",
			entityAttrs:    createMockEntity1Attributes("wrongnamespace.net", definition.GetName(), []string{"highest"}),
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - wrong definition name",
			entityAttrs:    createMockEntity1Attributes(definition.GetNamespace().GetName(), "wrong_definition_name", []string{"highest"}),
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - no matching entitlements",
			entityAttrs:    createMockEntity1Attributes(definition.GetNamespace().GetName(), definition.GetName(), []string{"random_value"}),
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - no entitlements at all",
			entityAttrs:    map[string][]string{mockEntityID: {}},
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
	}

	pdp := NewPdp(createTestLogger())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decisions, err := pdp.DetermineAccess(t.Context(), tt.dataAttrs, tt.entityAttrs, []*policy.Attribute{definition})

			require.NoError(t, err)
			if tt.expectedAccess {
				assert.True(t, decisions[mockEntityID].Access)
			} else {
				assert.False(t, decisions[mockEntityID].Access)
			}
			if len(decisions[mockEntityID].Results) > 0 {
				assert.Equal(t, tt.expectedPass, decisions[mockEntityID].Results[0].Passed)
			}
		})
	}

	// Test for empty data attributes
	entityAttrs := createMockEntity1Attributes(definition.GetNamespace().GetName(), definition.GetName(), []string{"highest"})
	emptyDataAttrs := []*policy.Value{}
	decisions, err := pdp.DetermineAccess(t.Context(), emptyDataAttrs, entityAttrs, []*policy.Attribute{definition})
	require.Error(t, err)
	assert.Empty(t, decisions)
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
			entityAttrs:    createMockEntity1Attributes(definition.GetNamespace().GetName(), definition.GetName(), values),
			dataAttrs:      definition.GetValues(),
			expectedAccess: true,
			expectedPass:   true,
		},
		{
			name:           "Fail - missing one definition value in entitlements",
			entityAttrs:    createMockEntity1Attributes(definition.GetNamespace().GetName(), definition.GetName(), values[:2]),
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - no matching entitlements",
			entityAttrs:    createMockEntity1Attributes(definition.GetNamespace().GetName(), definition.GetName(), []string{"random_value"}),
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - wrong namespace",
			entityAttrs:    createMockEntity1Attributes("wrongnamespace.com", definition.GetName(), values),
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
		{
			name:           "Fail - no entitlements at all",
			entityAttrs:    map[string][]string{mockEntityID: {}},
			dataAttrs:      definition.GetValues(),
			expectedAccess: false,
			expectedPass:   false,
		},
	}

	pdp := NewPdp(createTestLogger())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decisions, err := pdp.DetermineAccess(t.Context(), tt.dataAttrs, tt.entityAttrs, []*policy.Attribute{definition})

			require.NoError(t, err)
			if tt.expectedAccess {
				assert.True(t, decisions[mockEntityID].Access)
			} else {
				assert.False(t, decisions[mockEntityID].Access)
			}
			if len(decisions[mockEntityID].Results) > 0 {
				assert.Equal(t, tt.expectedPass, decisions[mockEntityID].Results[0].Passed)
			}
		})
	}

	// Test for empty data attributes
	entityAttrs := createMockEntity1Attributes(definition.GetNamespace().GetName(), definition.GetName(), []string{"highest"})
	emptyDataAttrs := []*policy.Value{}
	decisions, err := pdp.DetermineAccess(t.Context(), emptyDataAttrs, entityAttrs, []*policy.Attribute{definition})
	require.Error(t, err)
	assert.Empty(t, decisions)
}

func Test_DetermineAccess_EmptyDataAttributes(t *testing.T) {
	pdp := NewPdp(createTestLogger())
	decisions, err := pdp.DetermineAccess(t.Context(), []*policy.Value{}, map[string][]string{}, []*policy.Attribute{})

	require.Error(t, err)
	assert.Empty(t, decisions)
}

func Test_DetermineAccess_EmptyAttributeDefinitions(t *testing.T) {
	pdp := NewPdp(createTestLogger())
	dataAttrs := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{"value1"}).GetValues()
	entityAttrs := createMockEntity1Attributes("example.org", "myattr", []string{"value1"})

	decisions, err := pdp.DetermineAccess(t.Context(), dataAttrs, entityAttrs, []*policy.Attribute{})

	require.Error(t, err)
	assert.Empty(t, decisions)
}

func Test_GroupDataAttributesByDefinition(t *testing.T) {
	// Test case 1: Basic grouping
	dataAttrs := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{"value1", "value2"}).GetValues()
	pdp := NewPdp(createTestLogger())

	grouped, err := pdp.groupDataAttributesByDefinition(t.Context(), dataAttrs)
	require.NoError(t, err)
	assert.Len(t, grouped, 1)
	assert.Contains(t, grouped, "https://example.org/attr/myattr")
	assert.Len(t, grouped["https://example.org/attr/myattr"], 2)

	// Test case 2: Multiple attributes with same definition
	multiAttr := append(dataAttrs,
		createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{"value3"}).GetValues()...)
	grouped, err = pdp.groupDataAttributesByDefinition(t.Context(), multiAttr)
	require.NoError(t, err)
	assert.Len(t, grouped, 1)
	assert.Contains(t, grouped, "https://example.org/attr/myattr")
	assert.Len(t, grouped["https://example.org/attr/myattr"], 3)

	// Test case 3: Multiple attributes with different definitions
	multiDefAttrs := append(dataAttrs,
		createMockAttribute("example.org", "otherattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{"other1"}).GetValues()...)
	grouped, err = pdp.groupDataAttributesByDefinition(t.Context(), multiDefAttrs)
	require.NoError(t, err)
	assert.Len(t, grouped, 2)
	assert.Contains(t, grouped, "https://example.org/attr/myattr")
	assert.Contains(t, grouped, "https://example.org/attr/otherattr")
	assert.Len(t, grouped["https://example.org/attr/myattr"], 2)
	assert.Len(t, grouped["https://example.org/attr/otherattr"], 1)

	// Test case 4: Malformed FQN
	malformedAttrs := []*policy.Value{
		{Value: "bad", Fqn: "malformed-url"},
	}
	grouped, err = pdp.groupDataAttributesByDefinition(t.Context(), malformedAttrs)
	require.Error(t, err)
	assert.Empty(t, grouped)
}

func Test_MapFqnToDefinitions(t *testing.T) {
	// Test case 1: Basic mapping
	attr := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{"value1"})
	pdp := NewPdp(createTestLogger())

	mapped, err := pdp.mapFqnToDefinitions(t.Context(), []*policy.Attribute{attr})
	require.NoError(t, err)
	assert.Len(t, mapped, 1)
	assert.Contains(t, mapped, "https://example.org/attr/myattr")
	assert.Equal(t, attr, mapped["https://example.org/attr/myattr"])

	// Test case 2: Multiple attributes
	attr2 := createMockAttribute("example.com", "otherattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF, []string{"otherval"})
	mapped, err = pdp.mapFqnToDefinitions(t.Context(), []*policy.Attribute{attr, attr2})
	require.NoError(t, err)
	assert.Len(t, mapped, 2)
	assert.Contains(t, mapped, "https://example.org/attr/myattr")
	assert.Contains(t, mapped, "https://example.com/attr/otherattr")
	assert.Equal(t, attr, mapped["https://example.org/attr/myattr"])
	assert.Equal(t, attr2, mapped["https://example.com/attr/otherattr"])

	// Test case 3: Nil attribute
	mapped, err = pdp.mapFqnToDefinitions(t.Context(), []*policy.Attribute{nil})
	require.Error(t, err)
	assert.Empty(t, mapped)
}

func Test_GetHighestRankedInstanceFromDataAttributes(t *testing.T) {
	// Test case 1: Basic hierarchy with medium rank
	order := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, []string{"high", "medium", "low"}).GetValues()
	dataAttrs := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, []string{"medium"}).GetValues()
	pdp := NewPdp(createTestLogger())
	logger := createTestLogger()

	highest, err := pdp.getHighestRankedInstanceFromDataAttributes(t.Context(), order, dataAttrs, logger)
	require.NoError(t, err)
	assert.NotNil(t, highest)
	assert.Equal(t, "medium", highest.GetValue())

	// Test case 2: Multiple data attributes, should return highest
	dataAttrs = createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		[]string{"high", "medium", "low"}).GetValues()
	highest, err = pdp.getHighestRankedInstanceFromDataAttributes(t.Context(), order, dataAttrs, logger)
	require.NoError(t, err)
	assert.NotNil(t, highest)
	assert.Equal(t, "high", highest.GetValue())
}

func Test_GetIsValueFoundInFqnValuesSet(t *testing.T) {
	// Test case 1: Value exists in FQN set
	value := &policy.Value{
		Value: "value1",
		Fqn:   "https://example.org/attr/myattr/value/value1",
	}
	fqns := []string{"https://example.org/attr/myattr/value/value1", "https://example.org/attr/myattr/value/value2"}

	found := getIsValueFoundInFqnValuesSet(value, fqns, createTestLogger())
	assert.True(t, found)

	// Test case 2: Value does not exist in FQN set
	valueNotFound := &policy.Value{
		Value: "value3",
		Fqn:   "https://example.org/attr/myattr/value/value3",
	}
	found = getIsValueFoundInFqnValuesSet(valueNotFound, fqns, createTestLogger())
	assert.False(t, found)

	// Test case 3: Empty FQN set
	found = getIsValueFoundInFqnValuesSet(value, []string{}, createTestLogger())
	assert.False(t, found)

	// Test case 4: Different namespace but same value
	valueDiffNamespace := &policy.Value{
		Value: "value1",
		Fqn:   "https://different.org/attr/myattr/value/value1",
	}
	found = getIsValueFoundInFqnValuesSet(valueDiffNamespace, fqns, createTestLogger())
	assert.False(t, found)

	// Test case 5: Nil value
	found = getIsValueFoundInFqnValuesSet(nil, fqns, createTestLogger())
	assert.False(t, found)
}
