package subjectmappingresolution

import (
	"testing"

	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	classIntFQN        = "https://example.com/attr/class/value/internal"
	classConfFQN       = "https://example.com/attr/class/value/conf"
	classRestrictedFQN = "https://example.com/attr/class/value/restricted"

	actionNameRead   = "read"
	actionNameCreate = "create"
	actionNameDelete = "delete"

	departmentEngineeringSM = &policy.SubjectMapping{
		SubjectConditionSet: &policy.SubjectConditionSet{
			SubjectSets: []*policy.SubjectSet{
				{
					ConditionGroups: []*policy.ConditionGroup{
						{
							BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
							Conditions: []*policy.Condition{
								{
									SubjectExternalSelectorValue: ".department",
									SubjectExternalValues:        []string{"engineering"},
									Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								},
							},
						},
					},
				},
			},
		},
		Actions: []*policy.Action{
			{
				Name: actionNameRead,
			},
			{
				Name: actionNameCreate,
			},
		},
	}

	departmentSalesSM = &policy.SubjectMapping{
		SubjectConditionSet: &policy.SubjectConditionSet{
			SubjectSets: []*policy.SubjectSet{
				{
					ConditionGroups: []*policy.ConditionGroup{
						{
							BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
							Conditions: []*policy.Condition{
								{
									SubjectExternalSelectorValue: ".department",
									SubjectExternalValues:        []string{"sales"},
									Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								},
							},
						},
					},
				},
			},
		},
		Actions: []*policy.Action{
			{
				Name: actionNameRead,
			},
		},
	}

	groupsSM = &policy.SubjectMapping{
		SubjectConditionSet: &policy.SubjectConditionSet{
			SubjectSets: []*policy.SubjectSet{
				{
					ConditionGroups: []*policy.ConditionGroup{
						{
							BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
							Conditions: []*policy.Condition{
								{
									SubjectExternalSelectorValue: ".groups[]",
									SubjectExternalValues:        []string{"org1", "org2"},
									Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								},
								{
									SubjectExternalSelectorValue: ".internalGroups[]",
									SubjectExternalValues:        []string{"org3", "org4"},
									Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								},
							},
						},
					},
				},
			},
		},
		Actions: []*policy.Action{
			{
				Name: actionNameRead,
			},
		},
	}
)

// Helper function to create an entity representation for testing
func createEntityRepresentation(originalID string, entityData map[string]interface{}) *entityresolutionV2.EntityRepresentation {
	props, _ := structpb.NewStruct(entityData)
	return &entityresolutionV2.EntityRepresentation{
		OriginalId: originalID,
		AdditionalProps: []*structpb.Struct{
			props,
		},
	}
}

// Helper function to create attribute mappings
func createAttributeMapping(attributeFQN string, subjectMappings ...*policy.SubjectMapping) *attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue {
	value := &policy.Value{
		SubjectMappings: subjectMappings,
		Fqn:             attributeFQN,
	}
	for _, sm := range subjectMappings {
		sm.AttributeValue = value
	}
	return &attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		Value: value,
	}
}

func TestEvaluateSubjectMappingMultipleEntitiesWithActions_SingleEntity(t *testing.T) {
	// Setup test data
	engineeringEntity := createEntityRepresentation("engineering-entity", map[string]interface{}{
		"department": "engineering",
	})

	attributeMappings := map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		classConfFQN: createAttributeMapping(
			classConfFQN,
			departmentEngineeringSM,
		),
	}

	result, err := EvaluateSubjectMappingMultipleEntitiesWithActions(attributeMappings, []*entityresolutionV2.EntityRepresentation{engineeringEntity})
	require.NoError(t, err)
	assert.Len(t, result, 1)

	// Check entity entitlements
	entitlements, exists := result["engineering-entity"]
	assert.True(t, exists)

	// Check actions for the attribute
	actionsList, exists := entitlements[classConfFQN]
	assert.True(t, exists)
	assert.Len(t, actionsList, 2)

	// Verify the specific actions
	actionNames := make([]string, 0, len(actionsList))
	for _, action := range actionsList {
		actionNames = append(actionNames, action.GetName())
	}
	assert.Contains(t, actionNames, actionNameRead)
	assert.Contains(t, actionNames, actionNameCreate)
}

func TestEvaluateSubjectMappingMultipleEntitiesWithActions_MultipleEntities(t *testing.T) {
	// Setup test data
	engineeringEntity := createEntityRepresentation("engineering-entity", map[string]interface{}{
		"department": "engineering",
	})

	salesEntity := createEntityRepresentation("sales-entity", map[string]interface{}{
		"department": "sales",
	})

	attributeMappings := map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		classConfFQN: createAttributeMapping(
			classConfFQN,
			departmentEngineeringSM,
			departmentSalesSM,
		),
	}

	// Execute function
	result, err := EvaluateSubjectMappingMultipleEntitiesWithActions(
		attributeMappings,
		[]*entityresolutionV2.EntityRepresentation{engineeringEntity, salesEntity},
	)

	// Validate results
	require.NoError(t, err)
	assert.Len(t, result, 2)

	// Check engineering entity entitlements
	engEntitlements, exists := result["engineering-entity"]
	assert.True(t, exists)
	engActions, exists := engEntitlements[classConfFQN]
	assert.True(t, exists)
	assert.Len(t, engActions, 2)

	engActionNames := make([]string, 0, len(engActions))
	for _, action := range engActions {
		engActionNames = append(engActionNames, action.GetName())
	}
	assert.Contains(t, engActionNames, actionNameRead)
	assert.Contains(t, engActionNames, actionNameCreate)

	// Check sales entity entitlements
	salesEntitlements, exists := result["sales-entity"]
	assert.True(t, exists)
	salesActions, exists := salesEntitlements[classConfFQN]
	assert.True(t, exists)
	// Sales entity should only have read access
	assert.Len(t, salesActions, 1)
	assert.Equal(t, actionNameRead, salesActions[0].GetName())
}

func TestEvaluateSubjectMappingMultipleEntitiesWithActions_NoMatchingEntities(t *testing.T) {
	// Setup test data - an entity that doesn't match any subject mappings
	marketingEntity := createEntityRepresentation("marketing-entity", map[string]interface{}{
		"department": "marketing",
	})

	attributeMappings := map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		classConfFQN: createAttributeMapping(
			classConfFQN,
			departmentEngineeringSM,
			departmentSalesSM,
		),
	}

	// Execute function
	result, err := EvaluateSubjectMappingMultipleEntitiesWithActions(
		attributeMappings,
		[]*entityresolutionV2.EntityRepresentation{marketingEntity},
	)

	// Validate results
	require.NoError(t, err)
	assert.Len(t, result, 1)

	// Marketing entity should exist in the result but with empty entitlements
	marketingEntitlements, exists := result["marketing-entity"]
	assert.True(t, exists)
	assert.Empty(t, marketingEntitlements)
}

func TestEvaluateSubjectMappingMultipleEntitiesWithActions_MultipleAttributes(t *testing.T) {
	// Setup test data with both department and group membership
	engineeringEntity := createEntityRepresentation("engineering-entity", map[string]interface{}{
		"department": "engineering",
		"groups":     []any{"org1", "org5"},
	})

	attributeMappings := map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		classConfFQN: createAttributeMapping(
			classConfFQN,
			departmentEngineeringSM,
		),
		classIntFQN: createAttributeMapping(
			classIntFQN,
			groupsSM,
		),
	}

	// Execute function
	result, err := EvaluateSubjectMappingMultipleEntitiesWithActions(
		attributeMappings,
		[]*entityresolutionV2.EntityRepresentation{engineeringEntity},
	)

	// Validate results
	require.NoError(t, err)
	assert.Len(t, result, 1)

	entitlements, exists := result["engineering-entity"]
	assert.True(t, exists)
	assert.Len(t, entitlements, 2)

	// Check department-based entitlements (Confidential)
	confActions, exists := entitlements[classConfFQN]
	assert.True(t, exists)
	assert.NotEmpty(t, confActions)
	assert.Len(t, confActions, 2)
	actionNames := make([]string, 0)
	for _, action := range confActions {
		actionNames = append(actionNames, action.GetName())
	}
	assert.Contains(t, actionNames, actionNameRead)
	assert.Contains(t, actionNames, actionNameCreate)

	// Check group-based entitlements (Internal)
	internalActions, exists := entitlements[classIntFQN]
	assert.True(t, exists)
	assert.NotEmpty(t, internalActions)
	assert.Len(t, internalActions, 1)
	assert.Equal(t, actionNameRead, internalActions[0].GetName())
}

func TestEvaluateSubjectMappingsWithActions_OneGoodResolution(t *testing.T) {
	tests := []struct {
		name           string
		entityID       string
		attrFQN        string
		entity         map[string]interface{}
		subjectMapping *policy.SubjectMapping
	}{
		{
			name:     "Engineering Department",
			entityID: "engineering-entity",
			attrFQN:  classConfFQN,
			entity: map[string]interface{}{
				"department": "engineering",
			},
			subjectMapping: departmentEngineeringSM,
		},
		{
			name:     "Sales Department",
			entityID: "sales-entity",
			attrFQN:  classConfFQN,
			entity: map[string]interface{}{
				"department": "sales",
			},
			subjectMapping: departmentSalesSM,
		},
		{
			name:     "Group Membership",
			entityID: "org-member",
			attrFQN:  classIntFQN,
			entity: map[string]interface{}{
				"groups": []any{"org1", "org5"},
			},
			subjectMapping: groupsSM,
		},
		{
			name:     "Internal Group Membership",
			entityID: "internal-org-member",
			attrFQN:  classIntFQN,
			entity: map[string]interface{}{
				"internalGroups": []any{"org3", "org6"},
			},
			subjectMapping: groupsSM,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test data
			entity := createEntityRepresentation(tt.entityID, tt.entity)

			attributeMappings := map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
				tt.attrFQN: createAttributeMapping(
					tt.attrFQN,
					tt.subjectMapping,
				),
			}
			// Execute function
			entitlements, err := EvaluateSubjectMappingsWithActions(attributeMappings, entity)
			require.NoError(t, err)
			assert.Len(t, entitlements, 1)

			// Check actions for the attribute
			actionsList, exists := entitlements[tt.attrFQN]
			assert.True(t, exists)
			assert.Len(t, actionsList, len(tt.subjectMapping.GetActions()))
			actionNames := make([]string, 0, len(actionsList))
			for _, action := range actionsList {
				actionNames = append(actionNames, action.GetName())
			}
			for _, expectedAction := range tt.subjectMapping.GetActions() {
				assert.Contains(t, actionNames, expectedAction.GetName())
			}
		})
	}
}

func TestEvaluateSubjectMappingsWithActions_MultipleMatchingSubjectMappings(t *testing.T) {
	// Setup test data with entity that matches both department and group conditions
	multiMatchEntity := createEntityRepresentation("multi-match-entity", map[string]interface{}{
		"department":     "engineering",
		"groups":         []any{"org1"},
		"internalGroups": []any{"org3"},
	})

	customActionSM := &policy.SubjectMapping{
		SubjectConditionSet: &policy.SubjectConditionSet{
			SubjectSets: []*policy.SubjectSet{
				{
					ConditionGroups: []*policy.ConditionGroup{
						{
							BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
							Conditions: []*policy.Condition{
								{
									SubjectExternalSelectorValue: ".internalGroups[]",
									SubjectExternalValues:        []string{"org3"},
									Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								},
							},
						},
					},
				},
			},
		},
		Actions: []*policy.Action{
			{
				Name: "custom_action",
			},
		},
	}

	attributeMappings := map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		classConfFQN: createAttributeMapping(
			classConfFQN,
			departmentEngineeringSM,
			customActionSM,
		),
		classIntFQN: createAttributeMapping(
			classIntFQN,
			groupsSM,
		),
	}

	// Execute function
	entitlements, err := EvaluateSubjectMappingsWithActions(attributeMappings, multiMatchEntity)

	// Validate results
	require.NoError(t, err)
	assert.Len(t, entitlements, 2)

	// Check confidential actions - should include read, create, and update from both subject mappings
	confActions, exists := entitlements[classConfFQN]
	assert.True(t, exists)

	// Count unique actions (should be 3: read, create, update)
	actionNameSet := make(map[string]bool)
	for _, action := range confActions {
		actionNameSet[action.GetName()] = true
	}
	assert.Len(t, actionNameSet, 3)
	assert.True(t, actionNameSet[actionNameRead])
	assert.True(t, actionNameSet[actionNameCreate])
	assert.True(t, actionNameSet["custom_action"])

	// Check internal actions
	internalActions, exists := entitlements[classIntFQN]
	assert.True(t, exists)

	assert.Len(t, internalActions, 1)
	assert.Equal(t, actionNameRead, internalActions[0].GetName())
}

func TestEvaluateSubjectMappingsWithActions_NoMatchingSubjectMappings(t *testing.T) {
	// Setup test data with entity that doesn't match any subject mappings
	marketingEntity := createEntityRepresentation("marketing-entity", map[string]interface{}{
		"department": "marketing",
		"groups":     []any{"org7"},
	})

	attributeMappings := map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		classConfFQN: createAttributeMapping(
			classConfFQN,
			departmentEngineeringSM,
			departmentSalesSM,
		),
		classIntFQN: createAttributeMapping(
			classIntFQN,
			groupsSM,
		),
	}

	// Execute function
	entitlements, err := EvaluateSubjectMappingsWithActions(attributeMappings, marketingEntity)

	// Validate results
	require.NoError(t, err)
	assert.Empty(t, entitlements)
}

func TestEvaluateSubjectMappingsWithActions_ComplexCondition_MultipleConditionGroupsAreAND(t *testing.T) {
	// Create a subject mapping with complex conditions (AND + OR)
	complexSM := &policy.SubjectMapping{
		SubjectConditionSet: &policy.SubjectConditionSet{
			SubjectSets: []*policy.SubjectSet{
				{
					ConditionGroups: []*policy.ConditionGroup{
						{
							BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
							Conditions: []*policy.Condition{
								{
									SubjectExternalSelectorValue: ".department",
									SubjectExternalValues:        []string{"engineering"},
									Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								},
								{
									SubjectExternalSelectorValue: ".level",
									SubjectExternalValues:        []string{"senior", "principal"},
									Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								},
							},
						},
						{
							BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
							Conditions: []*policy.Condition{
								{
									SubjectExternalSelectorValue: ".roles[0]",
									SubjectExternalValues:        []string{"admin"},
									Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								},
							},
						},
					},
				},
			},
		},
		Actions: []*policy.Action{
			{
				Name: actionNameRead,
			},
			{
				Name: actionNameDelete,
			},
		},
	}

	// Setup test data - non-matching senior engineer
	seniorEngEntity := createEntityRepresentation("senior-engineer", map[string]interface{}{
		"department": "engineering",
		"level":      "senior",
	})

	// Setup test data - matching principal engineer with admin attribute
	principalEngWithAdmin := createEntityRepresentation("engineer-with-admin", map[string]interface{}{
		"roles":      []any{"admin"},
		"department": "engineering",
		"level":      "principal",
	})

	// Setup test data - matching senior engineer with admin attribute in index other than selected
	seniorEngWithAdminEntityInBadIndex := createEntityRepresentation("engineer-with-wrong-admin", map[string]interface{}{
		"roles":      []any{"user", "admin"}, // selector looks for admin in index 0
		"department": "engineering",
		"level":      "senior",
	})

	// Setup test data - non-matching admin user
	nonEngAdminEntity := createEntityRepresentation("admin-user", map[string]interface{}{
		"roles": []any{"admin"},
	})

	attributeMappings := map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue{
		classRestrictedFQN: createAttributeMapping(
			classRestrictedFQN,
			complexSM,
		),
	}

	// Test senior engineer
	seniorEntitlements, err := EvaluateSubjectMappingsWithActions(attributeMappings, seniorEngEntity)
	require.NoError(t, err)
	assert.Empty(t, seniorEntitlements)
	seniorActions, exists := seniorEntitlements[classRestrictedFQN]
	assert.False(t, exists)
	assert.Empty(t, seniorActions)

	// Test principal engineer with admin
	adminEntitlements, err := EvaluateSubjectMappingsWithActions(attributeMappings, principalEngWithAdmin)
	require.NoError(t, err)
	assert.Len(t, adminEntitlements, 1)
	seniorWithAdminActions, exists := adminEntitlements[classRestrictedFQN]
	assert.True(t, exists)
	assert.Len(t, seniorWithAdminActions, 2)
	actionNames := make([]string, 0, len(seniorWithAdminActions))
	for _, action := range seniorWithAdminActions {
		actionNames = append(actionNames, action.GetName())
	}
	assert.Contains(t, actionNames, actionNameRead)
	assert.Contains(t, actionNames, actionNameDelete)

	// Test senior engineer with admin in a different index
	adminEntitlementsBadIndex, err := EvaluateSubjectMappingsWithActions(attributeMappings, seniorEngWithAdminEntityInBadIndex)
	require.NoError(t, err)
	assert.Empty(t, adminEntitlementsBadIndex)
	adminActionsBadIndex, exists := adminEntitlementsBadIndex[classRestrictedFQN]
	assert.False(t, exists)
	assert.Empty(t, adminActionsBadIndex)

	// Test non-engineering admin
	nonEngAdminEntitlements, err := EvaluateSubjectMappingsWithActions(attributeMappings, nonEngAdminEntity)
	require.NoError(t, err)
	assert.Empty(t, nonEngAdminEntitlements)
	nonEngAdminActions, exists := nonEngAdminEntitlements[classRestrictedFQN]
	assert.False(t, exists)
	assert.Empty(t, nonEngAdminActions)
}
