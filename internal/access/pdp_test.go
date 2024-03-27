package access

import (
	ctx "context"
	"fmt"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
)

func fqnBuilder(n string, a string, v string) string {
	fqn := "https://"
	if n != "" && a != "" && v != "" {
		return fqn + n + "/attr/" + a + "/value/" + v
	} else if n != "" && a != "" && v == "" {
		return fqn + n + "/attr/" + a
	} else if n != "" && a == "" {
		return fqn + n
	} else {
		panic("Invalid FQN")
	}
}

var (
	mockNamespaces      = []string{"example.org", "authority.gov", "somewhere.net"}
	mockAttributeNames  = []string{"MyAttr", "YourAttr", "TheirAttr"}
	mockAttributeValues = []string{"Value1", "Value2", "Value3", "Value4"}

	mockExtraneousValueFqn = fqnBuilder("meep.org", "meep", "beepbeep")
	mockEntityId           = "4f6636ca-c60c-40d1-9f3f-015086303f74"

	simpleAnyOfAttribute = policy.Attribute{
		Name: mockAttributeNames[0],
		Namespace: &policy.Namespace{
			Name: mockNamespaces[0],
		},
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values: []*policy.Value{
			{
				Value: mockAttributeValues[0],
				Fqn:   fqnBuilder(mockNamespaces[0], mockAttributeNames[0], mockAttributeValues[0]),
			},
			{
				Value: mockAttributeValues[1],
				Fqn:   fqnBuilder(mockNamespaces[0], mockAttributeNames[0], mockAttributeValues[1]),
			},
		},
	}

	simpleAllOfAttribute = policy.Attribute{
		Name: mockAttributeNames[1],
		Namespace: &policy.Namespace{
			Name: mockNamespaces[1],
		},
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values: []*policy.Value{
			{
				Value: mockAttributeValues[2],
				Fqn:   fqnBuilder(mockNamespaces[1], mockAttributeNames[1], mockAttributeValues[2]),
			},
			{
				Value: mockAttributeValues[3],
				Fqn:   fqnBuilder(mockNamespaces[1], mockAttributeNames[1], mockAttributeValues[3]),
			},
		},
	}

	simpleHierarchyAttribute = policy.Attribute{
		Name: mockAttributeNames[2],
		Namespace: &policy.Namespace{
			Name: mockNamespaces[2],
		},
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		Values: []*policy.Value{
			{
				Value: "Privileged",
				Fqn:   fqnBuilder(mockNamespaces[2], mockAttributeNames[2], "Privileged"),
			},
			{
				Value: "LessPrivileged",
				Fqn:   fqnBuilder(mockNamespaces[2], mockAttributeNames[2], "LessPrivileged"),
			},
			{
				Value: "NotPrivilegedAtAll",
				Fqn:   fqnBuilder(mockNamespaces[2], mockAttributeNames[2], "NotPrivilegedAtAll"),
			},
		},
	}
)

// AnyOf tests
func Test_AccessPDP_AnyOf_Pass(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{&simpleAnyOfAttribute}
	ns := mockAttrDefinitions[0].Namespace.Name
	name := mockAttrDefinitions[0].Name
	val1 := mockAttrDefinitions[0].Values[0].Value
	mockDataAttrs := []*policy.Value{
		mockAttrDefinitions[0].Values[1],
		mockAttrDefinitions[0].Values[0],
	}

	mockEntityAttrs := map[string][]string{}
	mockEntityAttrs[mockEntityId] = []string{
		fqnBuilder(ns, name, val1),
		mockExtraneousValueFqn,
	}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions,
	)

	assert.Nil(t, err)
	assert.True(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.True(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockDataAttrs[1], decisions[mockEntityId].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
}

// TODO: fix this test
func Test_AccessPDP_AnyOf_FailMissingValue(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{&simpleAnyOfAttribute}
	mockDataAttrs := []*policy.Value{
		mockAttrDefinitions[0].Values[1],
		mockAttrDefinitions[0].Values[0],
	}
	ns := mockAttrDefinitions[0].Namespace.Name
	name := mockAttrDefinitions[0].Name
	mockEntityAttrs := map[string][]string{}
	mockEntityAttrs[mockEntityId] = []string{
		fqnBuilder(ns, name, "randomValue"),
		mockExtraneousValueFqn,
	}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	fmt.Printf("decisions: %+v", decisions[mockEntityId])
	fmt.Println("err: ", err)

	assert.Nil(t, err)
	assert.False(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.False(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 2, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockDataAttrs[0], decisions[mockEntityId].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
}

func Test_AccessPDP_AnyOf_FailMissingAttr(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{&simpleAnyOfAttribute}

	mockDataAttrs := []*policy.Value{
		mockAttrDefinitions[0].Values[1],
		mockAttrDefinitions[0].Values[0],
	}

	mockEntityAttrs := map[string][]string{}
	mockEntityAttrs[mockEntityId] = []string{
		fqnBuilder("dank.org", "noop", "randomVal"),
		mockExtraneousValueFqn,
	}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.False(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 2, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockDataAttrs[0], decisions[mockEntityId].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
}

func Test_AccessPDP_AnyOf_FailAttrWrongNamespace(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{&simpleAnyOfAttribute}

	mockDataAttrs := []*policy.Value{
		mockAttrDefinitions[0].Values[1],
		mockAttrDefinitions[0].Values[0],
	}

	mockEntityAttrs := map[string][]string{}
	name := mockAttrDefinitions[0].Name
	val1 := mockAttrDefinitions[0].Values[0].Value
	mockEntityAttrs[mockEntityId] = []string{fqnBuilder("otherrandomnamespace.com", name, val1), mockExtraneousValueFqn}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.False(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 2, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockDataAttrs[0], decisions[mockEntityId].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
}

func Test_AccessPDP_AnyOf_NoEntityAttributes_Fails(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{&simpleAnyOfAttribute}

	mockDataAttrs := []*policy.Value{
		mockAttrDefinitions[0].Values[1],
		mockAttrDefinitions[0].Values[0],
	}

	mockEntityAttrs := map[string][]string{}
	mockEntityAttrs[mockEntityId] = []string{}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.False(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 2, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockDataAttrs[0], decisions[mockEntityId].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
}

func Test_AccessPDP_AnyOf_NoDataAttributes_NoDecisions(t *testing.T) {
	// There are no data attribute instances in this test so the data attribute definitions
	// are useless, and should be ignored, but supply the definitions anyway to test that assumption
	mockAttrDefinitions := []*policy.Attribute{&simpleAnyOfAttribute}

	mockDataAttrs := []*policy.Value{}
	mockEntityAttrs := map[string][]string{}
	mockEntityAttrs[mockEntityId] = []string{
		fqnBuilder(mockNamespaces[0], mockAttributeNames[0], mockAttributeValues[0]),
		mockExtraneousValueFqn,
	}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.Nil(t, decisions[mockEntityId])
	// No data attributes -> no decisions to make -> no decisions per-entity
	// (PDP Caller can do what it wants with this info - infer this means access for all, or infer this means failure)
	assert.Equal(t, 0, len(decisions))
}

func Test_AccessPDP_AnyOf_AllEntitiesFilteredOutOfDataAttributeComparison_NoDecisions(t *testing.T) {
	entityID1 := "4f6636ca-c60c-40d1-9f3f-015086303f74"
	entityID2 := "bubble@squeak.biz"
	mockAttrDefinitions := []*policy.Attribute{
		&simpleAnyOfAttribute,
		{
			Name: mockAttributeNames[1],
			Namespace: &policy.Namespace{
				Name: mockNamespaces[0],
			},
			Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Values: []*policy.Value{
				{
					Value: mockAttributeValues[2],
					Fqn:   fqnBuilder(mockNamespaces[0], mockAttributeNames[1], mockAttributeValues[2]),
				},
				{
					Value: mockAttributeValues[3],
					Fqn:   fqnBuilder(mockNamespaces[0], mockAttributeNames[1], mockAttributeValues[3]),
				},
			},
		},
	}
	mockDataAttrs := []*policy.Value{}
	mockEntityAttrs := map[string][]string{}
	fqn1 := fqnBuilder("dank.org", mockAttrDefinitions[0].Name, mockAttrDefinitions[0].Values[0].Value)
	fqn2 := mockExtraneousValueFqn
	mockEntityAttrs[entityID1] = []string{
		fqn1, fqn2,
	}
	mockEntityAttrs[entityID2] = []string{
		fqn1, fqn2,
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
	mockAttrDefinitions := []*policy.Attribute{&simpleAllOfAttribute}

	mockDataAttrs := []*policy.Value{
		mockAttrDefinitions[0].Values[1],
		mockAttrDefinitions[0].Values[0],
	}
	mockEntityAttrs := map[string][]string{}
	ns := mockAttrDefinitions[0].Namespace.Name
	name := mockAttrDefinitions[0].Name
	mockEntityAttrs[mockEntityId] = []string{
		fqnBuilder(ns, name, mockAttrDefinitions[0].Values[0].Value),
		fqnBuilder(ns, name, mockAttrDefinitions[0].Values[1].Value),
		mockExtraneousValueFqn,
	}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.True(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.True(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 0, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
}

// TODO: fix this test
func Test_AccessPDP_AllOf_FailMissingValue(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{&simpleAllOfAttribute}
	mockDataAttrs := []*policy.Value{
		mockAttrDefinitions[0].Values[1],
		mockAttrDefinitions[0].Values[0],
	}
	mockEntityAttrs := map[string][]string{}
	mockEntityAttrs[mockEntityId] = []string{
		fqnBuilder(mockAttrDefinitions[0].Namespace.Name, mockAttrDefinitions[0].Name, mockAttrDefinitions[0].Values[0].Value),
		mockExtraneousValueFqn,
		fqnBuilder(mockAttrDefinitions[0].Namespace.Name, mockAttrDefinitions[0].Name, "otherValue"),
	}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.False(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockDataAttrs[0], decisions[mockEntityId].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
}

func Test_AccessPDP_AllOf_FailMissingAttr(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{
		&simpleAllOfAttribute,
	}
	mockDataAttrs := []*policy.Value{
		mockAttrDefinitions[0].Values[1],
		mockAttrDefinitions[0].Values[0],
	}
	mockEntityAttrs := map[string][]string{}
	mockEntityAttrs[mockEntityId] = []string{
		fqnBuilder("dank.org", "noop", "randomVal"),
		fqnBuilder("somewhere.com", "hello", "world"),
	}
	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.False(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 2, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockDataAttrs[0], decisions[mockEntityId].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
}

func Test_AccessPDP_AllOf_FailAttrWrongNamespace(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{&simpleAnyOfAttribute}
	mockDataAttrs := []*policy.Value{
		mockAttrDefinitions[0].Values[1],
		mockAttrDefinitions[0].Values[0],
	}

	wrongNs := "wrong" + mockAttrDefinitions[0].Namespace.Name
	name := mockAttrDefinitions[0].Name
	mockEntityAttrs := map[string][]string{}
	mockEntityAttrs[mockEntityId] = []string{
		fqnBuilder(wrongNs, name, mockAttrDefinitions[0].Values[0].Value),
		fqnBuilder(wrongNs, name, mockAttrDefinitions[0].Values[1].Value),
		mockExtraneousValueFqn,
	}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.False(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 2, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockDataAttrs[0], decisions[mockEntityId].Results[0].ValueFailures[0].DataAttribute)
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
}

// Hierarchy tests
func Test_AccessPDP_Hierarchy_Pass(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{&simpleHierarchyAttribute}
	topValue := mockAttrDefinitions[0].Values[0]
	midValue := mockAttrDefinitions[0].Values[1]
	mockDataAttrs := []*policy.Value{
		midValue,
		topValue,
	}

	mockEntityAttrs := map[string][]string{}
	ns := mockAttrDefinitions[0].Namespace.Name
	name := mockAttrDefinitions[0].Name
	mockEntityAttrs[mockEntityId] = []string{
		fqnBuilder(ns, name, topValue.Value),
		mockExtraneousValueFqn,
	}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.True(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.True(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 0, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
}

// TODO: Is this test accurate? Containing the top AND a lower value results in a fail?
func Test_AccessPDP_Hierarchy_FailEntityValueTooLow(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{&simpleHierarchyAttribute}
	topValue := mockAttrDefinitions[0].Values[0]
	midValue := mockAttrDefinitions[0].Values[1]
	mockDataAttrs := []*policy.Value{
		midValue,
		topValue,
	}
	mockEntityAttrs := map[string][]string{}
	ns := mockAttrDefinitions[0].Namespace.Name
	name := mockAttrDefinitions[0].Name

	mockEntityAttrs[mockEntityId] = []string{
		fqnBuilder(ns, name, topValue.Value),
		fqnBuilder(ns, name, midValue.Value),
		mockExtraneousValueFqn,
	}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.False(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailEntityValueAndDataValuesBothLowest(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{&simpleHierarchyAttribute}
	lowValue := mockAttrDefinitions[0].Values[2]
	mockDataAttrs := []*policy.Value{
		lowValue,
	}
	mockEntityAttrs := map[string][]string{}
	ns := mockAttrDefinitions[0].Namespace.Name
	name := mockAttrDefinitions[0].Name
	mockEntityAttrs[mockEntityId] = []string{
		fqnBuilder(ns, name, lowValue.Value),
	}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.True(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.True(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 0, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailEntityValueOrder(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{&simpleHierarchyAttribute}
	topValue := mockAttrDefinitions[0].Values[0]
	midValue := mockAttrDefinitions[0].Values[1]
	mockDataAttrs := []*policy.Value{
		midValue,
		topValue,
	}

	ns := mockAttrDefinitions[0].Namespace.Name
	name := mockAttrDefinitions[0].Name
	mockEntityAttrs := map[string][]string{}
	mockEntityAttrs[mockEntityId] = []string{
		fqnBuilder(ns, name, midValue.Value),
		fqnBuilder(ns, name, topValue.Value),
		mockExtraneousValueFqn,
	}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.False(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailMultipleHierarchyDataValues(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{&simpleHierarchyAttribute}
	topValue := mockAttrDefinitions[0].Values[0]
	midValue := mockAttrDefinitions[0].Values[1]
	mockDataAttrs := []*policy.Value{
		topValue,
		midValue,
	}

	ns := mockAttrDefinitions[0].Namespace.Name
	name := mockAttrDefinitions[0].Name
	mockEntityAttrs := map[string][]string{}
	mockEntityAttrs[mockEntityId] = []string{
		fqnBuilder(ns, name, midValue.Value),
		fqnBuilder(ns, name, topValue.Value),
		mockExtraneousValueFqn,
	}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.False(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailEntityValueNotInOrder(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{&simpleHierarchyAttribute}
	topValue := mockAttrDefinitions[0].Values[0]
	midValue := mockAttrDefinitions[0].Values[1]
	mockDataAttrs := []*policy.Value{
		midValue,
		topValue,
	}
	mockEntityAttrs := map[string][]string{}
	ns := mockAttrDefinitions[0].Namespace.Name
	name := mockAttrDefinitions[0].Name
	mockEntityAttrs[mockEntityId] = []string{
		fqnBuilder(ns, name, "unknownPrivilegeValue"),
		mockExtraneousValueFqn,
	}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.False(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailDataValueNotInOrder(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{&simpleHierarchyAttribute}
	ns := mockAttrDefinitions[0].Namespace.Name
	name := mockAttrDefinitions[0].Name
	mockDataAttrs := []*policy.Value{
		{
			Value: "UberPrivileged",
			Fqn:   fqnBuilder(ns, name, "UberPrivileged"),
		},
	}

	mockEntityAttrs := map[string][]string{}
	mockEntityAttrs[mockEntityId] = []string{
		fqnBuilder(ns, name, mockAttrDefinitions[0].Values[0].Value),
		mockExtraneousValueFqn,
	}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.False(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
	assert.Nil(t, decisions[mockEntityId].Results[0].ValueFailures[0].DataAttribute)
}

func Test_AccessPDP_Hierarchy_PassWithMixedKnownAndUnknownDataOrder(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{&simpleHierarchyAttribute}
	topValue := mockAttrDefinitions[0].Values[0]
	ns := mockAttrDefinitions[0].Namespace.Name
	name := mockAttrDefinitions[0].Name
	mockDataAttrs := []*policy.Value{
		{
			Value: "UberPrivileged",
			Fqn:   fqnBuilder(ns, name, "UberPrivileged"),
		},
		topValue,
	}

	mockEntityAttrs := map[string][]string{}
	mockEntityAttrs[mockEntityId] = []string{
		fqnBuilder(ns, name, topValue.Value),
		mockExtraneousValueFqn,
	}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.True(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.True(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 0, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailWithWrongNamespace(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{&simpleHierarchyAttribute}
	midValue := mockAttrDefinitions[0].Values[1]
	mockDataAttrs := []*policy.Value{
		midValue,
	}
	mockEntityAttrs := map[string][]string{}
	mockEntityAttrs[mockEntityId] = []string{
		fqnBuilder("wrong"+mockAttrDefinitions[0].Namespace.Name, mockAttrDefinitions[0].Name, midValue.Value),
		mockExtraneousValueFqn,
	}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.False(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
}

func Test_AccessPDP_Hierarchy_FailWithMixedKnownAndUnknownEntityOrder(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{&simpleHierarchyAttribute}
	topValue := mockAttrDefinitions[0].Values[0]
	midValue := mockAttrDefinitions[0].Values[1]
	mockDataAttrs := []*policy.Value{
		midValue,
		topValue,
	}
	ns := mockAttrDefinitions[0].Namespace.Name
	name := mockAttrDefinitions[0].Name
	mockEntityAttrs := map[string][]string{}
	mockEntityAttrs[mockEntityId] = []string{
		fqnBuilder(ns, name, topValue.Value),
		fqnBuilder(ns, name, "unknownPrivilegeValue"),
		mockExtraneousValueFqn,
	}

	accessPDP := NewPdp()
	decisions, err := accessPDP.DetermineAccess(
		ctx.Background(),
		mockDataAttrs,
		mockEntityAttrs,
		mockAttrDefinitions)

	assert.Nil(t, err)
	assert.False(t, decisions[mockEntityId].Access)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results))
	assert.False(t, decisions[mockEntityId].Results[0].Passed)
	assert.Equal(t, 1, len(decisions[mockEntityId].Results[0].ValueFailures))
	assert.Equal(t, mockAttrDefinitions[0], decisions[mockEntityId].Results[0].RuleDefinition)
}

// Helper tests

// GetFqnToDefinitionMap tests
func Test_GetFqnToDefinitionMap(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{
		&simpleAnyOfAttribute,
		&simpleAllOfAttribute,
		&simpleHierarchyAttribute,
	}

	fqnToDefinitionMap, err := GetFqnToDefinitionMap(mockAttrDefinitions)
	assert.Nil(t, err)

	for _, attrDef := range mockAttrDefinitions {
		fqn := fqnBuilder(attrDef.Namespace.Name, attrDef.Name, "")
		assert.Equal(t, attrDef.GetName(), fqnToDefinitionMap[fqn].GetName())
	}
}

func Test_GetFqnToDefinitionMap_SucceedsWithDuplicateDefinitions(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{
		&simpleAnyOfAttribute,
		&simpleAnyOfAttribute,
	}

	fqnToDefinitionMap, err := GetFqnToDefinitionMap(mockAttrDefinitions)
	assert.Nil(t, err)
	expectedFqn := fqnBuilder(mockAttrDefinitions[0].Namespace.Name, mockAttrDefinitions[0].Name, "")
	v, ok := fqnToDefinitionMap[expectedFqn]
	assert.True(t, ok)
	assert.Equal(t, mockAttrDefinitions[0].GetName(), v.GetName())
}

// GroupValuesByDefinition tests
func Test_GroupValuesByDefinition_NoProvidedDefinitionFqn_Succeeds(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{
		&simpleAnyOfAttribute,
		&simpleAllOfAttribute,
		&simpleHierarchyAttribute,
	}

	// two values from each attribute definition, out of order
	mockDataAttrs := []*policy.Value{
		mockAttrDefinitions[0].Values[0],
		mockAttrDefinitions[1].Values[0],
		mockAttrDefinitions[2].Values[0],
		mockAttrDefinitions[0].Values[1],
		mockAttrDefinitions[1].Values[1],
		mockAttrDefinitions[2].Values[1],
	}

	groupedValues, err := GroupValuesByDefinition(mockDataAttrs)
	assert.Nil(t, err)

	for _, attrDef := range mockAttrDefinitions {
		fqn := fqnBuilder(attrDef.Namespace.Name, attrDef.Name, "")
		assert.Equal(t, 2, len(groupedValues[fqn]))
		assert.Equal(t, attrDef.Values[0], groupedValues[fqn][0])
		assert.Equal(t, attrDef.Values[1], groupedValues[fqn][1])
	}
}

func Test_GroupValuesByDefinition_WithProvidedDefinitionFqn_Succeeds(t *testing.T) {
	attrFqn := fqnBuilder(mockNamespaces[0], mockAttributeNames[0], "")

	mockDataAttrs := []*policy.Value{
		{
			Value: mockAttributeValues[0],
			Attribute: &policy.Attribute{
				Fqn: attrFqn,
			},
		},
		{
			Value: mockAttributeValues[1],
			Attribute: &policy.Attribute{
				Fqn: attrFqn,
			},
		},
	}

	groupedValues, err := GroupValuesByDefinition(mockDataAttrs)
	assert.Nil(t, err)

	assert.Equal(t, 1, len(groupedValues))
	for k, v := range groupedValues {
		assert.Equal(t, attrFqn, k)
		assert.Equal(t, 2, len(v))
		assert.Equal(t, mockDataAttrs[0], v[0])
		assert.Equal(t, mockDataAttrs[1], v[1])
	}
}

// GroupValueFqnsByDefinition tests
func Test_GroupValueFqnsByDefinition(t *testing.T) {
	mockFqns := []string{
		fqnBuilder(mockNamespaces[0], mockAttributeNames[0], mockAttributeValues[0]),
		fqnBuilder(mockNamespaces[0], mockAttributeNames[0], mockAttributeValues[1]),
		fqnBuilder(mockNamespaces[0], mockAttributeNames[0], mockAttributeValues[2]),
		fqnBuilder(mockNamespaces[0], mockAttributeNames[1], mockAttributeValues[0]),
		fqnBuilder("authority.gov", "YourAttr", "Value2"),
	}

	groupedFqns, err := GroupValueFqnsByDefinition(mockFqns)
	assert.Nil(t, err)

	assert.Equal(t, 3, len(groupedFqns))
	found := map[string]bool{}
	for _, v := range mockFqns {
		found[v] = false
	}

	for _, v := range groupedFqns {
		for _, fq := range v {
			assert.Contains(t, mockFqns, fq)
			assert.False(t, found[fq])
			found[fq] = true
		}
	}

	for _, v := range found {
		assert.True(t, v)
	}
}

// GetDefinitionFqnFromValue tests
func Test_GetDefinitionFqnFromValue_Succeeds(t *testing.T) {
	ns := mockNamespaces[1]
	name := mockAttributeNames[2]
	val := mockAttributeValues[2]
	attrDefFqn := fqnBuilder(ns, name, "")

	// With Attribute Def & its FQN, Attribute Def & Namespace, or Value FQN
	mockValues := []*policy.Value{
		{
			Value: val,
			Attribute: &policy.Attribute{
				Fqn: attrDefFqn,
			},
		},
		{
			Attribute: &policy.Attribute{
				Namespace: &policy.Namespace{
					Name: ns,
				},
				Name: name,
			},
		},
		{
			Fqn: fqnBuilder(ns, name, mockAttributeValues[1]),
		},
	}

	for _, val := range mockValues {
		got, err := GetDefinitionFqnFromValue(val)
		assert.Nil(t, err)
		assert.Equal(t, attrDefFqn, got)
	}
}

func Test_GetDefinitionFqnFromValue_FailsWithMissingPieces(t *testing.T) {
	mockValues := []*policy.Value{
		// missing attr def & fqn
		{
			Value: mockAttributeValues[0],
		},
		// contains attr def but no namespace
		{
			Attribute: &policy.Attribute{
				Name: mockAttributeNames[0],
			},
		},
		// contains attr def's namespace but no name
		{
			Attribute: &policy.Attribute{
				Namespace: &policy.Namespace{
					Name: mockNamespaces[0],
				},
			},
		},
	}

	for _, val := range mockValues {
		def, err := GetDefinitionFqnFromValue(val)
		assert.NotNil(t, err)
		assert.Zero(t, def)
	}
}

// GetDefinitionFqnFromValueFqn tests
func Test_GetDefinitionFqnFromValueFqn_Succeeds(t *testing.T) {
	ns := mockNamespaces[1]
	name := mockAttributeNames[2]
	val1 := mockAttributeValues[1]
	val2 := mockAttributeValues[2]
	attrDefFqn := fqnBuilder(ns, name, "")
	mockValueFqns := []string{
		fqnBuilder(ns, name, val1),
		fqnBuilder(ns, name, val2),
	}

	for _, fqn := range mockValueFqns {
		got, err := GetDefinitionFqnFromValueFqn(fqn)
		assert.Nil(t, err)
		assert.Equal(t, attrDefFqn, got)
	}
}

func Test_GetDefinitionFqnFromValueFqn_FailsWithMissingPieces(t *testing.T) {
	mockValueFqns := []string{
		"",
		"/value/hello",
		"https://namespace.org/attr/attrName/val/hello",
		"namespace.org/attr/attrName/value",
	}

	for _, fqn := range mockValueFqns {
		got, err := GetDefinitionFqnFromValueFqn(fqn)
		assert.NotNil(t, err)
		assert.Zero(t, got)
	}
}

// GetDefinitionFqnFromDefinition tests
func Test_GetDefinitionFqnFromDefinition_FromPartsSucceeds(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{
		&simpleAnyOfAttribute,
		&simpleAllOfAttribute,
		&simpleHierarchyAttribute,
	}

	for _, attrDef := range mockAttrDefinitions {
		fqn := fqnBuilder(attrDef.Namespace.Name, attrDef.Name, "")
		got, err := GetDefinitionFqnFromDefinition(attrDef)
		assert.Nil(t, err)
		assert.Equal(t, fqn, got)
	}
}

func Test_GetDefinitionFqnFromDefinition_FromDefinedFqnSucceeds(t *testing.T) {
	mockFqns := []string{
		fqnBuilder("example.org", "MyAttr", "Value1"),
		fqnBuilder("authority.gov", "YourAttr", "Value2"),
	}
	mockAttrDefinitions := []*policy.Attribute{
		{
			Fqn: mockFqns[0],
		},
		{
			Fqn: mockFqns[1],
		},
	}

	for i, attrDef := range mockAttrDefinitions {
		got, err := GetDefinitionFqnFromDefinition(attrDef)
		assert.Nil(t, err)
		assert.Equal(t, attrDef.Fqn, got)
		assert.Equal(t, mockFqns[i], got)
	}
}

func Test_GetDefinitionFqnFromDefinition_FailsWithNoNamespace(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{
		{
			Name: "MyAttr",
		},
	}

	for _, attrDef := range mockAttrDefinitions {
		_, err := GetDefinitionFqnFromDefinition(attrDef)
		assert.NotNil(t, err)
	}
}

func Test_GetDefinitionFqnFromDefinition_FailsWithNoName(t *testing.T) {
	mockAttrDefinitions := []*policy.Attribute{
		{
			Namespace: &policy.Namespace{
				Name: "example.org",
			},
		},
	}

	for _, attrDef := range mockAttrDefinitions {
		_, err := GetDefinitionFqnFromDefinition(attrDef)
		assert.NotNil(t, err)
	}
}
