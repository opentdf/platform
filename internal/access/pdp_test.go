package access

import (
	ctx "context"
	"github.com/opentdf/opentdf-v2-poc/sdk/common"
	"testing"

	attrs "github.com/opentdf/opentdf-v2-poc/sdk/attributes"
	"github.com/stretchr/testify/assert"
)

// AnyOf tests
func Test_AccessPDP_AnyOf_Pass(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Descriptor_: &common.ResourceDescriptor{
				Namespace: attrAuthorities[0],
			},
			Name:   "MyAttr",
			Rule:   attrs.AttributeDefinition_ATTRIBUTE_RULE_TYPE_ANY_OF,
			Values: []string{"Value1", "Value2"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Values[1].Value,
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Values[0].Value,
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Value2",
			},
			{
				Authority: "https://meep.org",
				Name:      "meep",
				Value:     "beepbeep",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()

	decisions, err := accessPDP.DetermineAccess(
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions,
		&context,
	)

	assert.Nil(t, err)
	assert.True(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.True(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockDataAttrs[1], decisions[entityID].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_AnyOf_FailMissingValue(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "anyOf",
			Order:     []string{"Value1", "Value2"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Value4",
			},
			{
				Authority: "https://meep.org",
				Name:      "meep",
				Value:     "beepbeep",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()

	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 2, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockDataAttrs[0], decisions[entityID].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_AnyOf_FailMissingAttr(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "anyOf",
			Order:     []string{"Value1", "Value2"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://dank.org",
				Name:      "noop",
				Value:     "Value4",
			},
			{
				Authority: "https://meep.org",
				Name:      "meep",
				Value:     "beepbeep",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()

	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 2, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockDataAttrs[0], decisions[entityID].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_AnyOf_FailAttrWrongNamespace(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "anyOf",
			Order:     []string{"Value1", "Value2"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://dank.org",
				Name:      "MyAttr",
				Value:     "Value1",
			},
			{
				Authority: "https://meep.org",
				Name:      "meep",
				Value:     "beepbeep",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()

	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 2, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockDataAttrs[0], decisions[entityID].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_AnyOf_GroupBy(t *testing.T) {
	entityID1 := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	entityID2 := "bubble@squeak.biz"
	attrAuthorities := []string{"https://example.org", "https://loop.doop"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "anyOf",
			Order:     []string{"Value1", "Value2"},
			GroupBy: &attributeInstance{
				Authority: attrAuthorities[0],
				Name:      "AttrToGroupBy",
				Value:     "GroupByWithThisValue",
			},
		},
		{
			Authority: attrAuthorities[1],
			Name:      "MySecondAttr",
			Rule:      "anyOf",
			Order:     []string{"Value1", "Value2"},
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
		{
			Authority: attrAuthorities[1],
			Name:      mockAttrDefinitions[1].Name,
			Value:     mockAttrDefinitions[1].Order[0],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID1: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Value2",
			},
			{
				Authority: attrAuthorities[1],
				Name:      mockAttrDefinitions[1].Name,
				Value:     mockAttrDefinitions[1].Order[0],
			},
			//For one of these entities, give them a third
			//entity attribute, which is the same (canonical name + value)
			//as the groupby attribute instance on the definition
			*mockAttrDefinitions[0].GroupBy,
		},
		entityID2: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Value2",
			},
			{
				Authority: attrAuthorities[1],
				Name:      mockAttrDefinitions[1].Name,
				Value:     mockAttrDefinitions[1].Order[0],
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()

	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)

	//Overall for entity 1 should be YES
	assert.True(t, decisions[entityID1].Access)
	//Entity 1 has the GroupBy attribute, so it should
	//have been evaluated against both data attributes
	//we had definitions for.
	assert.Equal(t, 2, len(decisions[entityID1].Results))

	//Overall for entity 1 should be YES
	assert.True(t, decisions[entityID2].Access)
	//Entity 2 lacks the GroupBy attribute, so it should
	//have been evaluated against only one of data attributes
	//we had definitions for.
	assert.Equal(t, 1, len(decisions[entityID2].Results))
}

func Test_AccessPDP_AnyOf_NoEntityAttributes_Fails(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "anyOf",
			Order:     []string{"Value1", "Value2"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {},
	}
	accessPDP := NewPdp()
	context := ctx.Background()

	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 2, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockDataAttrs[0], decisions[entityID].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_AnyOf_NoDataAttributes_NoDecisions(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	//There are no data attribute instances in this test so the data attribute definitions
	// are useless, and should be ignored, but supply the definitions anyway to test that assumption
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "anyOf",
			Order:     []string{"Value1", "Value2"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://dank.org",
				Name:      "MyAttr",
				Value:     "Value1",
			},
			{
				Authority: "https://meep.org",
				Name:      "meep",
				Value:     "beepbeep",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()

	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.Nil(t, decisions[entityID])
	//No data attributes -> no decisions to make -> no decisions per-entity
	//(PDP Caller can do what it wants with this info - infer this means access for all, or infer this means failure)
	assert.Equal(t, 0, len(decisions))
}

func Test_AccessPDP_AnyOf_AllEntitiesFilteredOutOfDataAttributeComparison_NoDecisions(t *testing.T) {
	entityID1 := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	entityID2 := "bubble@squeak.biz"
	attrAuthorities := []string{"https://example.org", "https://loop.doop"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "anyOf",
			Order:     []string{"Value1", "Value2"},
			GroupBy: &attributeInstance{
				Authority: attrAuthorities[0],
				Name:      "AttrToGroupBy",
				Value:     "GroupByWithThisValue",
			},
		},
		{
			Authority: attrAuthorities[1],
			Name:      "MySecondAttr",
			Rule:      "anyOf",
			Order:     []string{"Value1", "Value2"},
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID1: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Value2",
			},
			{
				Authority: attrAuthorities[1],
				Name:      mockAttrDefinitions[1].Name,
				Value:     mockAttrDefinitions[1].Order[0],
			},
		},
		entityID2: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Value2",
			},
			{
				Authority: attrAuthorities[1],
				Name:      mockAttrDefinitions[1].Name,
				Value:     mockAttrDefinitions[1].Order[0],
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()

	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)

	//Both the entities lack the necessary GroupBy Attribute for the only data attribute we're comparing them against,
	//so neither of them get a Decision -> no decisions to be made here.
	assert.Nil(t, decisions[entityID1])
	assert.Nil(t, decisions[entityID2])
	//No data attributes -> no decisions to make -> no decisions per-entity
	//(PDP Caller can do what it wants with this info - infer this means access for all, or infer this means failure)
	assert.Equal(t, 0, len(decisions))
}

// AllOf tests
func Test_AccessPDP_AllOf_Pass(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "allOf",
			Order:     []string{"Value1", "Value2"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Value1",
			},
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Value2",
			},
			{
				Authority: "https://meep.org",
				Name:      "meep",
				Value:     "beepbeep",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()

	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.True(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.True(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 0, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_AllOf_FailMissingValue(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "allOf",
			Order:     []string{"Value1", "Value2"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Value1",
			},
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Value4",
			},
			{
				Authority: "https://meep.org",
				Name:      "meep",
				Value:     "beepbeep",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()

	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockDataAttrs[0], decisions[entityID].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_AllOf_FailMissingAttr(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "allOf",
			Order:     []string{"Value1", "Value2"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://dank.org",
				Name:      "noop",
				Value:     "Value4",
			},
			{
				Authority: "https://meep.org",
				Name:      "meep",
				Value:     "beepbeep",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()
	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 2, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockDataAttrs[0], decisions[entityID].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_AllOf_FailAttrWrongNamespace(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "allOf",
			Order:     []string{"Value1", "Value2"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://dank.org",
				Name:      "MyAttr",
				Value:     "Value1",
			},
			{
				Authority: "https://dank.org",
				Name:      "MyAttr",
				Value:     "Value2",
			},
			{
				Authority: "https://meep.org",
				Name:      "meep",
				Value:     "beepbeep",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()
	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 2, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockDataAttrs[0], decisions[entityID].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_AllOf_GroupBy(t *testing.T) {
	entityID1 := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	entityID2 := "bubble@squeak.biz"
	attrAuthorities := []string{"https://example.org", "https://loop.doop"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "allOf",
			Order:     []string{"Value1", "Value2"},
			GroupBy: &attributeInstance{
				Authority: attrAuthorities[0],
				Name:      "AttrToGroupBy",
				Value:     "GroupByWithThisValue",
			},
		},
		{
			Authority: attrAuthorities[1],
			Name:      "MySecondAttr",
			Rule:      "allOf",
			Order:     []string{"Value1", "Value2"},
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
		{
			Authority: attrAuthorities[1],
			Name:      mockAttrDefinitions[1].Name,
			Value:     mockAttrDefinitions[1].Order[0],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID1: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Value2",
			},
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Value1",
			},
			{
				Authority: attrAuthorities[1],
				Name:      mockAttrDefinitions[1].Name,
				Value:     mockAttrDefinitions[1].Order[0],
			},
			//For one of these entities, give them a third
			//entity attribute, which is the same (canonical name + value)
			//as the groupby attribute instance on the definition
			*mockAttrDefinitions[0].GroupBy,
		},
		entityID2: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Value1",
			},
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Value2",
			},
			{
				Authority: attrAuthorities[1],
				Name:      mockAttrDefinitions[1].Name,
				Value:     mockAttrDefinitions[1].Order[0],
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()
	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)

	//Overall for entity 1 should be YES
	assert.True(t, decisions[entityID1].Access)
	//Entity 1 has the GroupBy attribute, so it should
	//have been evaluated against both data attributes
	//we had definitions for.
	assert.Equal(t, 2, len(decisions[entityID1].Results))

	//Overall for entity 1 should be YES
	assert.True(t, decisions[entityID2].Access)
	//Entity 2 lacks the GroupBy attribute, so it should
	//have been evaluated against only one of data attributes
	//we had definitions for.
	assert.Equal(t, 1, len(decisions[entityID2].Results))
}

// Hierarchy tests
func Test_AccessPDP_Hierarchy_Pass(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "hierarchy",
			Order:     []string{"Privileged", "LessPrivileged", "NotPrivilegedAtAll"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Privileged",
			},
			{
				Authority: "https://meep.org",
				Name:      "meep",
				Value:     "beepbeep",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()
	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.True(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.True(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 0, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailEntityValueTooLow(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "hierarchy",
			Order:     []string{"Privileged", "LessPrivileged", "NotPrivilegedAtAll"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Privileged",
			},
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "LessPrivileged",
			},
			{
				Authority: "https://meep.org",
				Name:      "meep",
				Value:     "beepbeep",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()
	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailEntityValueAndDataValuesBothLowest(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "hierarchy",
			Order:     []string{"Privileged", "LessPrivileged", "NotPrivilegedAtAll"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[2],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "NotPrivilegedAtAll",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()
	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.True(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.True(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 0, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailEntityValueOrder(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "hierarchy",
			Order:     []string{"Privileged", "LessPrivileged", "NotPrivilegedAtAll"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "LessPrivileged",
			},
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Privileged",
			},
			{
				Authority: "https://meep.org",
				Name:      "meep",
				Value:     "beepbeep",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()
	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailMultipleHierarchyDataValues(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "hierarchy",
			Order:     []string{"Privileged", "LessPrivileged", "NotPrivilegedAtAll"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "LessPrivileged",
			},
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Privileged",
			},
			{
				Authority: "https://meep.org",
				Name:      "meep",
				Value:     "beepbeep",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()
	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailEntityValueNotInOrder(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "hierarchy",
			Order:     []string{"Privileged", "LessPrivileged", "NotPrivilegedAtAll"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "UberPrivileged",
			},
			{
				Authority: "https://meep.org",
				Name:      "meep",
				Value:     "beepbeep",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()
	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailDataValueNotInOrder(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "hierarchy",
			Order:     []string{"Privileged", "LessPrivileged", "NotPrivilegedAtAll"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     "UberPrivileged",
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Privileged",
			},
			{
				Authority: "https://meep.org",
				Name:      "meep",
				Value:     "beepbeep",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()
	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
	assert.Nil(t, decisions[entityID].Results[0].ValueFailures[0].DataAttribute)
}

func Test_AccessPDP_Hierarchy_PassWithMixedKnownAndUnknownDataOrder(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "hierarchy",
			Order:     []string{"Privileged", "LessPrivileged", "NotPrivilegedAtAll"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     "UberPrivileged",
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Privileged",
			},
			{
				Authority: "https://meep.org",
				Name:      "meep",
				Value:     "beepbeep",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()
	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.True(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.True(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 0, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailWithWrongNamespace(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "hierarchy",
			Order:     []string{"Privileged", "LessPrivileged", "NotPrivilegedAtAll"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://example.net",
				Name:      "MyAttr",
				Value:     "Privileged",
			},
			{
				Authority: "https://meep.org",
				Name:      "meep",
				Value:     "beepbeep",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()
	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailWithMixedKnownAndUnknownEntityOrder(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "hierarchy",
			Order:     []string{"Privileged", "LessPrivileged", "NotPrivilegedAtAll"},
			// GroupBy *AttributeInstance `json:"group_by,omitempty"`
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Privileged",
			},
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "UberPrivileged",
			},
			{
				Authority: "https://meep.org",
				Name:      "meep",
				Value:     "beepbeep",
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()
	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_GroupBy(t *testing.T) {
	entityID1 := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	entityID2 := "bubble@squeak.biz"
	attrAuthorities := []string{"https://example.org", "https://loop.doop"}
	mockAttrDefinitions := []attrs.AttributeDefinition{
		{
			Authority: attrAuthorities[0],
			Name:      "MyAttr",
			Rule:      "hierarchy",
			Order:     []string{"Privileged", "LessPrivileged", "NotPrivilegedAtAll"},
			GroupBy: &attributeInstance{
				Authority: attrAuthorities[0],
				Name:      "AttrToGroupBy",
				Value:     "GroupByWithThisValue",
			},
		},
		{
			Authority: attrAuthorities[1],
			Name:      "MySecondAttr",
			Rule:      "allOf",
			Order:     []string{"Value1", "Value2"},
		},
	}
	mockDataAttrs := []attributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[1],
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Order[0],
		},
		{
			Authority: attrAuthorities[1],
			Name:      mockAttrDefinitions[1].Name,
			Value:     mockAttrDefinitions[1].Order[0],
		},
	}
	mockEntityAttrs := map[string][]attributeInstance{
		entityID1: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Privileged",
			},
			{
				Authority: attrAuthorities[1],
				Name:      mockAttrDefinitions[1].Name,
				Value:     mockAttrDefinitions[1].Order[0],
			},
			//For one of these entities, give them a third
			//entity attribute, which is the same (canonical name + value)
			//as the groupby attribute instance on the definition
			*mockAttrDefinitions[0].GroupBy,
		},
		entityID2: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "Privileged",
			},
			{
				Authority: attrAuthorities[1],
				Name:      mockAttrDefinitions[1].Name,
				Value:     mockAttrDefinitions[1].Order[0],
			},
		},
	}
	accessPDP := NewPdp()
	context := ctx.Background()
	decisions, err := accessPDP.DetermineAccess(mockDataAttrs, mockEntityAttrs, mockAttrDefinitions, &context)

	assert.Nil(t, err)
	//Overall for entity 1 should be YES
	assert.True(t, decisions[entityID1].Access)
	//Entity 1 has the GroupBy attribute, so it should
	//have been evaluated against both data attributes
	//we had definitions for.
	assert.Equal(t, 2, len(decisions[entityID1].Results))

	//Overall for entity 1 should be YES
	assert.True(t, decisions[entityID2].Access)
	//Entity 2 lacks the GroupBy attribute, so it should
	//have been evaluated against only one of data attributes
	//we had definitions for.
	assert.Equal(t, 1, len(decisions[entityID2].Results))
}
