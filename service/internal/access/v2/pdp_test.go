package access

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	authz "github.com/opentdf/platform/protocol/go/authorization/v2"
	ers "github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/policy/actions"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	// Base namespaces
	testBaseNamespace     = "https://test.example.com"
	testClassificationFQN = testBaseNamespace + "/attr/classification"
	testDepartmentFQN     = testBaseNamespace + "/attr/department"
	testCountryFQN        = testBaseNamespace + "/attr/country"

	// Classification values
	testClassTopSecretFQN    = testClassificationFQN + "/value/topsecret"
	testClassSecretFQN       = testClassificationFQN + "/value/secret"
	testClassConfidentialFQN = testClassificationFQN + "/value/confidential"
	testClassPublicFQN       = testClassificationFQN + "/value/public"

	// Department values
	testDeptRnDFQN         = testDepartmentFQN + "/value/rnd"
	testDeptEngineeringFQN = testDepartmentFQN + "/value/engineering"
	testDeptSalesFQN       = testDepartmentFQN + "/value/sales"
	testDeptFinanceFQN     = testDepartmentFQN + "/value/finance"

	// Country values
	testCountryUSAFQN = testCountryFQN + "/value/usa"
	testCountryUKFQN  = testCountryFQN + "/value/uk"
)

var (
	testActionRead   = &policy.Action{Name: actions.ActionNameRead}
	testActionCreate = &policy.Action{Name: actions.ActionNameCreate}
	testActionUpdate = &policy.Action{Name: actions.ActionNameUpdate}
	testActionDelete = &policy.Action{Name: actions.ActionNameDelete}
)

type PDPTestSuite struct {
	suite.Suite
	ctx    context.Context
	logger *logger.Logger

	// Test attributes
	classificationAttr *policy.Attribute
	departmentAttr     *policy.Attribute
	countryAttr        *policy.Attribute

	// Test subject mappings
	secretSubjectMapping       *policy.SubjectMapping
	confidentialSubjectMapping *policy.SubjectMapping
	rndSubjectMapping          *policy.SubjectMapping
	financeSubjectMapping      *policy.SubjectMapping
	usaSubjectMapping          *policy.SubjectMapping

	// Test entity representations
	adminEntity     *ers.EntityRepresentation
	developerEntity *ers.EntityRepresentation
	analystEntity   *ers.EntityRepresentation
}

func (s *PDPTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.logger = logger.CreateTestLogger()

	// Classification attribute (HIERARCHY)
	s.classificationAttr = &policy.Attribute{
		Fqn:  testClassificationFQN,
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		Values: []*policy.Value{
			{Fqn: testClassSecretFQN, Value: "secret"},
			{Fqn: testClassConfidentialFQN, Value: "confidential"},
			{Fqn: testClassPublicFQN, Value: "public"},
		},
	}

	// Department attribute (ANY_OF)
	s.departmentAttr = &policy.Attribute{
		Fqn:  testDepartmentFQN,
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values: []*policy.Value{
			{Fqn: testDeptRnDFQN, Value: "rnd"},
			{Fqn: testDeptSalesFQN, Value: "sales"},
			{Fqn: testDeptFinanceFQN, Value: "finance"},
		},
	}

	// Country attribute (ALL_OF)
	s.countryAttr = &policy.Attribute{
		Fqn:  testCountryFQN,
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values: []*policy.Value{
			{Fqn: testCountryUSAFQN, Value: "usa"},
			{Fqn: testCountryUKFQN, Value: "uk"},
		},
	}

	// Setup subject mappings
	s.secretSubjectMapping = &policy.SubjectMapping{
		AttributeValue: &policy.Value{
			Fqn:   testClassSecretFQN,
			Value: "secret",
		},
		SubjectConditionSet: &policy.SubjectConditionSet{
			SubjectSets: []*policy.SubjectSet{
				{
					ConditionGroups: []*policy.ConditionGroup{
						{
							BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
							Conditions: []*policy.Condition{
								{
									SubjectExternalSelectorValue: ".properties.role",
									SubjectExternalValues:        []string{"admin"},
									Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								},
							},
						},
					},
				},
			},
		},
		Actions: []*policy.Action{testActionRead, testActionUpdate, testActionDelete},
	}

	s.confidentialSubjectMapping = &policy.SubjectMapping{
		AttributeValue: &policy.Value{
			Fqn:   testClassConfidentialFQN,
			Value: "confidential",
		},
		SubjectConditionSet: &policy.SubjectConditionSet{
			SubjectSets: []*policy.SubjectSet{
				{
					ConditionGroups: []*policy.ConditionGroup{
						{
							BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
							Conditions: []*policy.Condition{
								{
									SubjectExternalSelectorValue: ".properties.role",
									SubjectExternalValues:        []string{"developer"},
									Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								},
							},
						},
					},
				},
			},
		},
		Actions: []*policy.Action{testActionRead, testActionUpdate},
	}

	s.rndSubjectMapping = &policy.SubjectMapping{
		AttributeValue: &policy.Value{
			Fqn:   testDeptRnDFQN,
			Value: "rnd",
		},
		SubjectConditionSet: &policy.SubjectConditionSet{
			SubjectSets: []*policy.SubjectSet{
				{
					ConditionGroups: []*policy.ConditionGroup{
						{
							BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
							Conditions: []*policy.Condition{
								{
									SubjectExternalSelectorValue: ".properties.department",
									SubjectExternalValues:        []string{"engineering"},
									Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								},
							},
						},
					},
				},
			},
		},
		Actions: []*policy.Action{testActionRead, testActionUpdate},
	}

	s.financeSubjectMapping = &policy.SubjectMapping{
		AttributeValue: &policy.Value{
			Fqn:   testDeptFinanceFQN,
			Value: "finance",
		},
		SubjectConditionSet: &policy.SubjectConditionSet{
			SubjectSets: []*policy.SubjectSet{
				{
					ConditionGroups: []*policy.ConditionGroup{
						{
							BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
							Conditions: []*policy.Condition{
								{
									SubjectExternalSelectorValue: ".properties.department",
									SubjectExternalValues:        []string{"finance"},
									Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								},
							},
						},
					},
				},
			},
		},
		Actions: []*policy.Action{testActionRead, testActionUpdate},
	}

	s.usaSubjectMapping = &policy.SubjectMapping{
		AttributeValue: &policy.Value{
			Fqn:   testCountryUSAFQN,
			Value: "usa",
		},
		SubjectConditionSet: &policy.SubjectConditionSet{
			SubjectSets: []*policy.SubjectSet{
				{
					ConditionGroups: []*policy.ConditionGroup{
						{
							BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
							Conditions: []*policy.Condition{
								{
									SubjectExternalSelectorValue: ".properties.country",
									SubjectExternalValues:        []string{"us"},
									Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								},
							},
						},
					},
				},
			},
		},
		Actions: []*policy.Action{testActionRead},
	}

	// Setup test entities
	s.adminEntity = &ers.EntityRepresentation{
		OriginalId: "admin-entity",
		AdditionalProps: []*structpb.Struct{
			{
				Fields: map[string]*structpb.Value{
					"properties": structpb.NewStructValue(&structpb.Struct{
						Fields: map[string]*structpb.Value{
							"role":       structpb.NewStringValue("admin"),
							"department": structpb.NewStringValue("engineering"),
							"country":    structpb.NewStringValue("us"),
						},
					}),
				},
			},
		},
	}

	s.developerEntity = &ers.EntityRepresentation{
		OriginalId: "developer-entity",
		AdditionalProps: []*structpb.Struct{
			{
				Fields: map[string]*structpb.Value{
					"properties": structpb.NewStructValue(&structpb.Struct{
						Fields: map[string]*structpb.Value{
							"role":       structpb.NewStringValue("developer"),
							"department": structpb.NewStringValue("engineering"),
							"country":    structpb.NewStringValue("us"),
						},
					}),
				},
			},
		},
	}

	s.analystEntity = &ers.EntityRepresentation{
		OriginalId: "analyst-entity",
		AdditionalProps: []*structpb.Struct{
			{
				Fields: map[string]*structpb.Value{
					"properties": structpb.NewStructValue(&structpb.Struct{
						Fields: map[string]*structpb.Value{
							"role":       structpb.NewStringValue("analyst"),
							"department": structpb.NewStringValue("finance"),
							"country":    structpb.NewStringValue("uk"),
						},
					}),
				},
			},
		},
	}
}

func TestPDPSuite(t *testing.T) {
	suite.Run(t, new(PDPTestSuite))
}

func (s *PDPTestSuite) TestNewPolicyDecisionPoint() {
	tests := []struct {
		name            string
		attributes      []*policy.Attribute
		subjectMappings []*policy.SubjectMapping
		expectError     bool
	}{
		{
			name:            "valid initialization",
			attributes:      []*policy.Attribute{s.classificationAttr, s.departmentAttr, s.countryAttr},
			subjectMappings: []*policy.SubjectMapping{s.secretSubjectMapping, s.confidentialSubjectMapping, s.rndSubjectMapping},
			expectError:     false,
		},
		{
			name:            "nil attributes and subject mappings",
			attributes:      nil,
			subjectMappings: nil,
			expectError:     true,
		},
		{
			name:            "nil attributes but non-nil subject mappings",
			attributes:      nil,
			subjectMappings: []*policy.SubjectMapping{s.secretSubjectMapping},
			expectError:     true,
		},
		{
			name:            "non-nil attributes but nil subject mappings",
			attributes:      []*policy.Attribute{s.classificationAttr},
			subjectMappings: nil,
			expectError:     true,
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			pdp, err := NewPolicyDecisionPoint(s.ctx, s.logger, tc.attributes, tc.subjectMappings)

			if tc.expectError {
				s.Error(err)
				s.Nil(pdp)
			} else {
				s.NoError(err)
				s.NotNil(pdp)
			}
		})
	}
}

func TestGetDecision(t *testing.T) {
	// Setup
	ctx := context.Background()
	logger := logger.CreateTestLogger()

	// Create test attributes
	classificationAttr := &policy.Attribute{
		Fqn:  testClassificationFQN,
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		Values: []*policy.Value{
			{Fqn: testClassTopSecretFQN, Value: "topsecret"},
			{Fqn: testClassSecretFQN, Value: "secret"},
			{Fqn: testClassConfidentialFQN, Value: "confidential"},
		},
	}

	departmentAttr := &policy.Attribute{
		Fqn:  testDepartmentFQN,
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values: []*policy.Value{
			{Fqn: testDeptEngineeringFQN, Value: "engineering"},
			{Fqn: testDeptFinanceFQN, Value: "finance"},
		},
	}

	// Create test subject mappings
	secretMapping := &policy.SubjectMapping{
		AttributeValue: &policy.Value{
			Fqn:   testClassSecretFQN,
			Value: "secret",
		},
		SubjectConditionSet: &policy.SubjectConditionSet{
			SubjectSets: []*policy.SubjectSet{
				{
					ConditionGroups: []*policy.ConditionGroup{
						{
							BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
							Conditions: []*policy.Condition{
								{
									SubjectExternalSelectorValue: ".clearance",
									SubjectExternalValues:        []string{"secret"},
									Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								},
							},
						},
					},
				},
			},
		},
		Actions: []*policy.Action{
			actionRead,
			actionCreate,
		},
	}

	engineeringMapping := &policy.SubjectMapping{
		AttributeValue: &policy.Value{
			Fqn:   testDeptEngineeringFQN,
			Value: "engineering",
		},
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
			actionRead,
		},
	}

	// Create a PDP
	pdp, err := NewPolicyDecisionPoint(
		ctx,
		logger,
		[]*policy.Attribute{classificationAttr, departmentAttr},
		[]*policy.SubjectMapping{secretMapping, engineeringMapping},
	)
	require.NoError(t, err)
	require.NotNil(t, pdp)

	t.Run("Access granted when entity has appropriate entitlements", func(t *testing.T) {
		// Create test entity with appropriate entitlements
		entity := &ers.EntityRepresentation{
			OriginalId: "test-user-1",
			AdditionalProps: []*structpb.Struct{
				{
					Fields: map[string]*structpb.Value{
						"clearance":  structpb.NewStringValue("secret"),
						"department": structpb.NewStringValue("engineering"),
					},
				},
			},
		}

		// Add direct properties at the root level as well
		entity.AdditionalProps[0].Fields["clearance"] = structpb.NewStringValue("secret")
		entity.AdditionalProps[0].Fields["department"] = structpb.NewStringValue("engineering")

		// Resource to evaluate (Secret classification)
		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{testClassSecretFQN},
					},
				},
			},
		}

		// Get decision
		decision, err := pdp.GetDecision(ctx, entity, actionRead, resources)

		// Assertions
		require.NoError(t, err)
		require.NotNil(t, decision)
		assert.True(t, decision.Access)
		assert.Len(t, decision.Results, 1)
		assert.True(t, decision.Results[0].Passed)
		assert.Empty(t, decision.Results[0].EntitlementFailures)
	})

	t.Run("Access denied when entity lacks entitlements", func(t *testing.T) {
		// Create test entity with insufficient entitlements
		entity := &ers.EntityRepresentation{
			OriginalId: "test-user-2",
			AdditionalProps: []*structpb.Struct{
				{
					Fields: map[string]*structpb.Value{
						"clearance":  structpb.NewStringValue("confidential"), // Not high enough for secret
						"department": structpb.NewStringValue("finance"),      // Not engineering
					},
				},
			},
		}

		// Add direct properties at the root level as well
		entity.AdditionalProps[0].Fields["clearance"] = structpb.NewStringValue("confidential")
		entity.AdditionalProps[0].Fields["department"] = structpb.NewStringValue("finance")

		// Resource to evaluate (Secret classification)
		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{testClassSecretFQN},
					},
				},
			},
		}

		// Get decision
		decision, err := pdp.GetDecision(ctx, entity, actionRead, resources)

		// Assertions
		require.NoError(t, err)
		require.NotNil(t, decision)
		assert.False(t, decision.Access)
		assert.Len(t, decision.Results, 1)
		assert.False(t, decision.Results[0].Passed)
		assert.NotEmpty(t, decision.Results[0].EntitlementFailures)
	})

	t.Run("Access denied for disallowed action", func(t *testing.T) {
		// Create test entity with appropriate entitlements
		entity := &ers.EntityRepresentation{
			OriginalId: "test-user-3",
			AdditionalProps: []*structpb.Struct{
				{
					Fields: map[string]*structpb.Value{
						"clearance":  structpb.NewStringValue("secret"),
						"department": structpb.NewStringValue("engineering"),
					},
				},
			},
		}

		// Add direct properties at the root level as well
		entity.AdditionalProps[0].Fields["clearance"] = structpb.NewStringValue("secret")
		entity.AdditionalProps[0].Fields["department"] = structpb.NewStringValue("engineering")

		// Resource to evaluate (Engineering department)
		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{testDeptEngineeringFQN},
					},
				},
			},
		}

		// Get decision
		decision, err := pdp.GetDecision(ctx, entity, actionCreate, resources)

		// Assertions
		require.NoError(t, err)
		require.NotNil(t, decision)
		assert.False(t, decision.Access)
		assert.Len(t, decision.Results, 1)
		assert.False(t, decision.Results[0].Passed)
	})

	t.Run("Multiple resources - partial access", func(t *testing.T) {
		// Create test entity with appropriate entitlements
		entity := &ers.EntityRepresentation{
			OriginalId: "test-user-4",
			AdditionalProps: []*structpb.Struct{
				{
					Fields: map[string]*structpb.Value{
						"clearance":  structpb.NewStringValue("secret"),
						"department": structpb.NewStringValue("engineering"),
					},
				},
			},
		}

		// Add direct properties at the root level as well
		entity.AdditionalProps[0].Fields["clearance"] = structpb.NewStringValue("secret")
		entity.AdditionalProps[0].Fields["department"] = structpb.NewStringValue("engineering")

		// Resources to evaluate (Secret classification and Finance department)
		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{testClassSecretFQN},
					},
				},
			},
			{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{testDeptFinanceFQN},
					},
				},
			},
		}

		// Get decision
		decision, err := pdp.GetDecision(ctx, entity, actionRead, resources)

		// Assertions
		require.NoError(t, err)
		require.NotNil(t, decision)
		assert.False(t, decision.Access) // False because one resource is denied
		assert.Len(t, decision.Results, 2)

		// First resource (Secret) should be allowed
		assert.True(t, decision.Results[0].Passed)

		// Second resource (Finance) should be denied
		assert.False(t, decision.Results[1].Passed)
	})

	t.Run("Invalid resource FQN", func(t *testing.T) {
		// Create test entity
		entity := &ers.EntityRepresentation{
			OriginalId: "test-user-5",
			AdditionalProps: []*structpb.Struct{
				{
					Fields: map[string]*structpb.Value{
						"clearance":  structpb.NewStringValue("secret"),
						"department": structpb.NewStringValue("engineering"),
					},
				},
			},
		}

		// Resource with invalid FQN
		resources := []*authz.Resource{
			{
				Resource: &authz.Resource_AttributeValues_{
					AttributeValues: &authz.Resource_AttributeValues{
						Fqns: []string{testBaseNamespace + "/attr/nonexistent/value/test"},
					},
				},
			},
		}

		// Get decision
		decision, err := pdp.GetDecision(ctx, entity, actionRead, resources)

		// Assertions
		require.Error(t, err)
		assert.Nil(t, decision)
		assert.Equal(t, ErrInvalidResource, err)
	})
}
