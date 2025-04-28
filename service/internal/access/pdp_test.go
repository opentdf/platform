package access

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const mockEntityID = "entity1"

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

	pdp := NewPdp(logger.CreateTestLogger())
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

	pdp := NewPdp(logger.CreateTestLogger())
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

	pdp := NewPdp(logger.CreateTestLogger())
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
	pdp := NewPdp(logger.CreateTestLogger())
	decisions, err := pdp.DetermineAccess(t.Context(), []*policy.Value{}, map[string][]string{}, []*policy.Attribute{})

	require.NoError(t, err)
	assert.Empty(t, decisions)
}

func Test_DetermineAccess_EmptyAttributeDefinitions(t *testing.T) {
	pdp := NewPdp(logger.CreateTestLogger())
	dataAttrs := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{"value1"}).GetValues()
	entityAttrs := createMockEntity1Attributes("example.org", "myattr", []string{"value1"})

	decisions, err := pdp.DetermineAccess(t.Context(), dataAttrs, entityAttrs, []*policy.Attribute{})

	require.Error(t, err)
	assert.Empty(t, decisions)
}

func Test_GroupDataAttributesByDefinition(t *testing.T) {
	dataAttrs := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{"value1", "value2"}).GetValues()
	pdp := NewPdp(logger.CreateTestLogger())

	grouped, err := pdp.groupDataAttributesByDefinition(t.Context(), dataAttrs)

	require.NoError(t, err)
	assert.Len(t, grouped, 1)
	assert.Contains(t, grouped, "https://example.org/attr/myattr")
}

func Test_MapFqnToDefinitions(t *testing.T) {
	attr := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, []string{"value1"})
	pdp := NewPdp(logger.CreateTestLogger())

	mapped, err := pdp.mapFqnToDefinitions(t.Context(), []*policy.Attribute{attr})

	require.NoError(t, err)
	assert.Len(t, mapped, 1)
	assert.Contains(t, mapped, "https://example.org/attr/myattr")
}

func Test_GetHighestRankedInstanceFromDataAttributes(t *testing.T) {
	order := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, []string{"high", "medium", "low"}).GetValues()
	dataAttrs := createMockAttribute("example.org", "myattr", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, []string{"medium"}).GetValues()
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
