package access

import (
	"testing"

	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPDPGetEntitlementsMergesDirectAndSubjectMappingActions(t *testing.T) {
	definitionFQN := "https://example.com/attr/classification"
	valueFQN := definitionFQN + "/value/confidential"
	mapping := &policy.SubjectMapping{
		Id:                  "mapping",
		AttributeValue:      &policy.Value{Fqn: valueFQN},
		SubjectConditionSet: clientIDInConditionSet("client"),
		Actions:             []*policy.Action{{Name: "read"}, {Name: "update"}},
	}
	pdp, err := NewPolicyDecisionPoint(
		t.Context(), logger.CreateTestLogger(),
		[]*policy.Attribute{{
			Fqn: definitionFQN, Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
			Values: []*policy.Value{{Fqn: valueFQN, SubjectMappings: []*policy.SubjectMapping{mapping}}},
		}}, []*policy.SubjectMapping{mapping}, nil, true, false,
	)
	require.NoError(t, err)
	entityRepresentation := entityRepWithClientID("client")
	entityRepresentation.DirectEntitlements = []*entityresolutionV2.DirectEntitlement{{
		AttributeValueFqn: valueFQN,
		Actions:           []string{"update", "delete"},
	}}

	entitlements, err := pdp.GetEntitlements(t.Context(), []*entityresolutionV2.EntityRepresentation{entityRepresentation}, []*policy.SubjectMapping{mapping}, false)
	require.NoError(t, err)
	require.Len(t, entitlements, 1)
	actions := entitlements[0].GetActionsPerAttributeValueFqn()[valueFQN].GetActions()
	assert.ElementsMatch(t, []string{"read", "update", "delete"}, actionNames(actions))
}

func TestPDPGetEntitlementsExpandsDirectHierarchy(t *testing.T) {
	definitionFQN := "https://example.com/attr/clearance"
	highFQN := definitionFQN + "/value/high"
	lowFQN := definitionFQN + "/value/low"
	pdp, err := NewPolicyDecisionPoint(
		t.Context(), logger.CreateTestLogger(),
		[]*policy.Attribute{{
			Fqn: definitionFQN, Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			Values: []*policy.Value{{Fqn: highFQN}, {Fqn: lowFQN}},
		}}, []*policy.SubjectMapping{}, nil, true, false,
	)
	require.NoError(t, err)
	entityRepresentation := &entityresolutionV2.EntityRepresentation{
		OriginalId: "entity",
		DirectEntitlements: []*entityresolutionV2.DirectEntitlement{{
			AttributeValueFqn: highFQN,
			Actions:           []string{"read"},
		}},
	}

	entitlements, err := pdp.GetEntitlements(t.Context(), []*entityresolutionV2.EntityRepresentation{entityRepresentation}, []*policy.SubjectMapping{}, true)
	require.NoError(t, err)
	require.Len(t, entitlements, 1)
	actionsByFQN := entitlements[0].GetActionsPerAttributeValueFqn()
	assert.Equal(t, []string{"read"}, actionNames(actionsByFQN[highFQN].GetActions()))
	assert.Equal(t, []string{"read"}, actionNames(actionsByFQN[lowFQN].GetActions()))
}
