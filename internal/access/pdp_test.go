package access

import (
	ctx "context"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
)

// AnyOf tests
func Test_AccessPDP_AnyOf_Pass(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Values: []*policy.Value{
				{
					Value: "Value1",
				},
				{
					Value: "Value2",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
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
	mockEntityAttrs := map[string][]AttributeInstance{
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions,
	)

	assert.Nil(t, err)
	assert.True(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.True(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockDataAttrs[1], decisions[entityID].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_AnyOf_FailMissingValue(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Values: []*policy.Value{
				{
					Value: "Value1",
				},
				{
					Value: "Value2",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
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
	mockEntityAttrs := map[string][]AttributeInstance{
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 2, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockDataAttrs[0], decisions[entityID].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_AnyOf_FailMissingAttr(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Values: []*policy.Value{
				{
					Value: "Value1",
				},
				{
					Value: "Value2",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
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
	mockEntityAttrs := map[string][]AttributeInstance{
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 2, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockDataAttrs[0], decisions[entityID].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_AnyOf_FailAttrWrongNamespace(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Values: []*policy.Value{
				{
					Value: "Value1",
				},
				{
					Value: "Value2",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
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
	mockEntityAttrs := map[string][]AttributeInstance{
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 2, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockDataAttrs[0], decisions[entityID].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_AnyOf_NoEntityAttributes_Fails(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Values: []*policy.Value{
				{
					Value: "Value1",
				},
				{
					Value: "Value2",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
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
	mockEntityAttrs := map[string][]AttributeInstance{
		entityID: {},
	}
	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 2, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockDataAttrs[0], decisions[entityID].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_AnyOf_NoDataAttributes_NoDecisions(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	// There are no data attribute instances in this test so the data attribute definitions
	// are useless, and should be ignored, but supply the definitions anyway to test that assumption
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Values: []*policy.Value{
				{
					Value: "Value1",
				},
				{
					Value: "Value2",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{}
	mockEntityAttrs := map[string][]AttributeInstance{
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.Nil(t, decisions[entityID])
	// No data attributes -> no decisions to make -> no decisions per-entity
	// (PDP Caller can do what it wants with this info - infer this means access for all, or infer this means failure)
	assert.Equal(t, 0, len(decisions))
}

func Test_AccessPDP_AnyOf_AllEntitiesFilteredOutOfDataAttributeComparison_NoDecisions(t *testing.T) {
	entityID1 := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	entityID2 := "bubble@squeak.biz"
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Values: []*policy.Value{
				{
					Value: "Value1",
				},
				{
					Value: "Value2",
				},
			},
		},
		{
			Name: "YourAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Values: []*policy.Value{
				{
					Value: "Value3",
				},
				{
					Value: "Value4",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{}
	mockEntityAttrs := map[string][]AttributeInstance{
		entityID1: {
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
		entityID2: {
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)

	// Both the entities lack the necessary Attribute for the only data attribute we're comparing them against,
	// so neither of them get a Decision -> no decisions to be made here.
	assert.Nil(t, decisions[entityID1])
	assert.Nil(t, decisions[entityID2])
	// No data attributes -> no decisions to make -> no decisions per-entity
	// (PDP Caller can do what it wants with this info - infer this means access for all, or infer this means failure)
	assert.Equal(t, 0, len(decisions))
}

// AllOf tests
func Test_AccessPDP_AllOf_Pass(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			Values: []*policy.Value{
				{
					Value: "Value1",
				},
				{
					Value: "Value2",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
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
	mockEntityAttrs := map[string][]AttributeInstance{
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.True(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.True(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 0, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_AllOf_FailMissingValue(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			Values: []*policy.Value{
				{
					Value: "Value1",
				},
				{
					Value: "Value2",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
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
	mockEntityAttrs := map[string][]AttributeInstance{
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockDataAttrs[0], decisions[entityID].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_AllOf_FailMissingAttr(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			Values: []*policy.Value{
				{
					Value: "Value1",
				},
				{
					Value: "Value2",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
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
	mockEntityAttrs := map[string][]AttributeInstance{
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 2, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockDataAttrs[0], decisions[entityID].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_AllOf_FailAttrWrongNamespace(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
			Values: []*policy.Value{
				{
					Value: "Value1",
				},
				{
					Value: "Value2",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
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
	mockEntityAttrs := map[string][]AttributeInstance{
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 2, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, &mockDataAttrs[0], decisions[entityID].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

// Hierarchy tests
func Test_AccessPDP_Hierarchy_Pass(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			Values: []*policy.Value{
				{
					Value: "Privileged",
				},
				{
					Value: "LessPrivileged",
				},
				{
					Value: "NotPrivilegedAtAll",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
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
	mockEntityAttrs := map[string][]AttributeInstance{
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.True(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.True(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 0, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailEntityValueTooLow(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			Values: []*policy.Value{
				{
					Value: "Privileged",
				},
				{
					Value: "LessPrivileged",
				},
				{
					Value: "NotPrivilegedAtAll",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
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
	mockEntityAttrs := map[string][]AttributeInstance{
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailEntityValueAndDataValuesBothLowest(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			Values: []*policy.Value{
				{
					Value: "Privileged",
				},
				{
					Value: "LessPrivileged",
				},
				{
					Value: "NotPrivilegedAtAll",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Values[2].Value,
		},
	}
	mockEntityAttrs := map[string][]AttributeInstance{
		entityID: {
			{
				Authority: "https://example.org",
				Name:      "MyAttr",
				Value:     "NotPrivilegedAtAll",
			},
		},
	}
	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.True(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.True(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 0, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailEntityValueOrder(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			Values: []*policy.Value{
				{
					Value: "Privileged",
				},
				{
					Value: "LessPrivileged",
				},
				{
					Value: "NotPrivilegedAtAll",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
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
	mockEntityAttrs := map[string][]AttributeInstance{
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailMultipleHierarchyDataValues(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			Values: []*policy.Value{
				{
					Value: "Privileged",
				},
				{
					Value: "LessPrivileged",
				},
				{
					Value: "NotPrivilegedAtAll",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Values[0].Value,
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Values[1].Value,
		},
	}
	mockEntityAttrs := map[string][]AttributeInstance{
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailEntityValueNotInOrder(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			Values: []*policy.Value{
				{
					Value: "Privileged",
				},
				{
					Value: "LessPrivileged",
				},
				{
					Value: "NotPrivilegedAtAll",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
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
	mockEntityAttrs := map[string][]AttributeInstance{
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailDataValueNotInOrder(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			Values: []*policy.Value{
				{
					Value: "Privileged",
				},
				{
					Value: "LessPrivileged",
				},
				{
					Value: "NotPrivilegedAtAll",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     "UberPrivileged",
		},
	}
	mockEntityAttrs := map[string][]AttributeInstance{
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
	assert.Nil(t, decisions[entityID].Results[0].ValueFailures[0].DataAttribute)
}

func Test_AccessPDP_Hierarchy_PassWithMixedKnownAndUnknownDataOrder(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			Values: []*policy.Value{
				{
					Value: "Privileged",
				},
				{
					Value: "LessPrivileged",
				},
				{
					Value: "NotPrivilegedAtAll",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     "UberPrivileged",
		},
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Values[0].Value,
		},
	}
	mockEntityAttrs := map[string][]AttributeInstance{
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.True(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.True(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 0, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailWithWrongNamespace(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			Values: []*policy.Value{
				{
					Value: "Privileged",
				},
				{
					Value: "LessPrivileged",
				},
				{
					Value: "NotPrivilegedAtAll",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
		{
			Authority: attrAuthorities[0],
			Name:      mockAttrDefinitions[0].Name,
			Value:     mockAttrDefinitions[0].Values[1].Value,
		},
	}
	mockEntityAttrs := map[string][]AttributeInstance{
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailWithMixedKnownAndUnknownEntityOrder(t *testing.T) {
	entityID := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	attrAuthorities := []string{"https://example.org"}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
			Namespace: &policy.Namespace{
				Name: "https://example.org",
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			Values: []*policy.Value{
				{
					Value: "Privileged",
				},
				{
					Value: "LessPrivileged",
				},
				{
					Value: "NotPrivilegedAtAll",
				},
			},
		},
	}
	mockDataAttrs := []AttributeInstance{
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
	mockEntityAttrs := map[string][]AttributeInstance{
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
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[entityID].Access)
	assert.Equal(t, 1, len(decisions[entityID].Results))
	assert.False(t, decisions[entityID].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[entityID].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[entityID].Results[0].RuleDefinition)
}
