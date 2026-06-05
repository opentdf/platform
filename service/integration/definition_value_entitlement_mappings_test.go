package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/service/internal/fixtures"
	policydb "github.com/opentdf/platform/service/policy/db"
	"github.com/stretchr/testify/suite"
)

type DefinitionValueEntitlementMappingsSuite struct {
	suite.Suite
	f  fixtures.Fixtures
	db fixtures.DBInterface
	//nolint:containedctx // Only used for test suite
	ctx context.Context
}

func (s *DefinitionValueEntitlementMappingsSuite) SetupSuite() {
	slog.Info("setting up db.DefinitionValueEntitlementMappings test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_def_value_entitlement_mappings"
	s.db = fixtures.NewDBInterface(s.ctx, c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision(s.ctx)
}

func (s *DefinitionValueEntitlementMappingsSuite) TearDownSuite() {
	slog.Info("tearing down db.DefinitionValueEntitlementMappings test suite")
	s.f.TearDown(s.ctx)
}

func TestDefinitionValueEntitlementMappingsSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping definition_value_entitlement_mappings integration tests")
	}
	suite.Run(t, new(DefinitionValueEntitlementMappingsSuite))
}

func (s *DefinitionValueEntitlementMappingsSuite) TestCreateAndGet() {
	attr := s.createDefinition("dvem_create_ok", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)

	created, err := s.db.PolicyClient.CreateDefinitionValueEntitlementMapping(s.ctx, &subjectmapping.CreateDefinitionValueEntitlementMappingRequest{
		AttributeDefinitionId: attr.GetId(),
		ValueResolver:         s.resolver(".patientAssignments[]", policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN),
		Actions:               []*policy.Action{s.readAction()},
	})
	s.Require().NoError(err)
	s.Require().NotEmpty(created.GetId())

	got, err := s.db.PolicyClient.GetDefinitionValueEntitlementMapping(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.Equal(attr.GetId(), got.GetAttributeDefinition().GetId())
	s.Equal(".patientAssignments[]", got.GetValueResolver().GetSubjectExternalSelectorValue())
	s.Equal(policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN, got.GetValueResolver().GetOperator())
	s.Len(got.GetActions(), 1)
	s.Nil(got.GetSubjectConditionSet(), "optional static pre-gate omitted")
}

func (s *DefinitionValueEntitlementMappingsSuite) TestCreateWithStaticGate() {
	attr := s.createDefinition("dvem_create_gate", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)

	created, err := s.db.PolicyClient.CreateDefinitionValueEntitlementMapping(s.ctx, &subjectmapping.CreateDefinitionValueEntitlementMappingRequest{
		AttributeDefinitionId:  attr.GetId(),
		ValueResolver:          s.resolver(".patientAssignments[]", policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN),
		Actions:                []*policy.Action{s.readAction()},
		NewSubjectConditionSet: s.sampleSCSCreate(),
	})
	s.Require().NoError(err)

	got, err := s.db.PolicyClient.GetDefinitionValueEntitlementMapping(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.Require().NotNil(got.GetSubjectConditionSet(), "static pre-gate should be hydrated")
	s.NotEmpty(got.GetSubjectConditionSet().GetSubjectSets())
}

func (s *DefinitionValueEntitlementMappingsSuite) TestRejectsHierarchyDefinition() {
	attr := s.createDefinition("dvem_hierarchy", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY)

	_, err := s.db.PolicyClient.CreateDefinitionValueEntitlementMapping(s.ctx, &subjectmapping.CreateDefinitionValueEntitlementMappingRequest{
		AttributeDefinitionId: attr.GetId(),
		ValueResolver:         s.resolver(".x[]", policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN),
		Actions:               []*policy.Action{s.readAction()},
	})
	s.Require().Error(err, "HIERARCHY definitions must be rejected")
}

func (s *DefinitionValueEntitlementMappingsSuite) TestNoCoexistence_SubjectMappingThenDynamic() {
	attr := s.createDefinition("dvem_coexist_fwd", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
	val, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attr.GetId(), &attributes.CreateAttributeValueRequest{Value: "v1"})
	s.Require().NoError(err)

	_, err = s.db.PolicyClient.CreateSubjectMapping(s.ctx, &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:       val.GetId(),
		Actions:                []*policy.Action{s.readAction()},
		NewSubjectConditionSet: s.sampleSCSCreate(),
	})
	s.Require().NoError(err)

	// definition now has a value-level subject mapping; a dynamic mapping must be rejected
	_, err = s.db.PolicyClient.CreateDefinitionValueEntitlementMapping(s.ctx, &subjectmapping.CreateDefinitionValueEntitlementMappingRequest{
		AttributeDefinitionId: attr.GetId(),
		ValueResolver:         s.resolver(".x[]", policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN),
		Actions:               []*policy.Action{s.readAction()},
	})
	s.Require().Error(err, "dynamic mapping must not coexist with value-level subject mappings")
}

func (s *DefinitionValueEntitlementMappingsSuite) TestNoCoexistence_DynamicThenSubjectMapping() {
	attr := s.createDefinition("dvem_coexist_rev", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)

	_, err := s.db.PolicyClient.CreateDefinitionValueEntitlementMapping(s.ctx, &subjectmapping.CreateDefinitionValueEntitlementMappingRequest{
		AttributeDefinitionId: attr.GetId(),
		ValueResolver:         s.resolver(".x[]", policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN),
		Actions:               []*policy.Action{s.readAction()},
	})
	s.Require().NoError(err)

	val, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attr.GetId(), &attributes.CreateAttributeValueRequest{Value: "v1"})
	s.Require().NoError(err)

	// definition now has a dynamic mapping; a value-level subject mapping must be rejected
	_, err = s.db.PolicyClient.CreateSubjectMapping(s.ctx, &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:       val.GetId(),
		Actions:                []*policy.Action{s.readAction()},
		NewSubjectConditionSet: s.sampleSCSCreate(),
	})
	s.Require().Error(err, "value-level subject mapping must not coexist with a dynamic mapping")
}

func (s *DefinitionValueEntitlementMappingsSuite) TestRejectsRuleChangeToHierarchy() {
	attr := s.createDefinition("dvem_rule_guard", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)

	_, err := s.db.PolicyClient.CreateDefinitionValueEntitlementMapping(s.ctx, &subjectmapping.CreateDefinitionValueEntitlementMappingRequest{
		AttributeDefinitionId: attr.GetId(),
		ValueResolver:         s.resolver(".x[]", policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN),
		Actions:               []*policy.Action{s.readAction()},
	})
	s.Require().NoError(err)

	_, err = s.db.PolicyClient.UnsafeUpdateAttribute(s.ctx, &unsafe.UnsafeUpdateAttributeRequest{
		Id:   attr.GetId(),
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
	})
	s.Require().Error(err, "changing the rule to HIERARCHY must be rejected when a dynamic mapping exists")
}

func (s *DefinitionValueEntitlementMappingsSuite) TestUpdateAndDelete() {
	attr := s.createDefinition("dvem_update_delete", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF)

	created, err := s.db.PolicyClient.CreateDefinitionValueEntitlementMapping(s.ctx, &subjectmapping.CreateDefinitionValueEntitlementMappingRequest{
		AttributeDefinitionId: attr.GetId(),
		ValueResolver:         s.resolver(".patientAssignments[]", policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN),
		Actions:               []*policy.Action{s.readAction()},
	})
	s.Require().NoError(err)

	updated, err := s.db.PolicyClient.UpdateDefinitionValueEntitlementMapping(s.ctx, &subjectmapping.UpdateDefinitionValueEntitlementMappingRequest{
		Id:            created.GetId(),
		ValueResolver: s.resolver(".accounts[]", policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN_CONTAINS),
	})
	s.Require().NoError(err)
	s.Equal(".accounts[]", updated.GetValueResolver().GetSubjectExternalSelectorValue())
	s.Equal(policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN_CONTAINS, updated.GetValueResolver().GetOperator())

	_, err = s.db.PolicyClient.DeleteDefinitionValueEntitlementMapping(s.ctx, created.GetId())
	s.Require().NoError(err)

	_, err = s.db.PolicyClient.GetDefinitionValueEntitlementMapping(s.ctx, created.GetId())
	s.Require().Error(err, "mapping should be gone after delete")
}

func (s *DefinitionValueEntitlementMappingsSuite) TestListByDefinition() {
	attr := s.createDefinition("dvem_list", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
	_, err := s.db.PolicyClient.CreateDefinitionValueEntitlementMapping(s.ctx, &subjectmapping.CreateDefinitionValueEntitlementMappingRequest{
		AttributeDefinitionId: attr.GetId(),
		ValueResolver:         s.resolver(".patientAssignments[]", policy.DynamicValueOperatorEnum_DYNAMIC_VALUE_OPERATOR_ENUM_RESOURCE_VALUE_IN),
		Actions:               []*policy.Action{s.readAction()},
	})
	s.Require().NoError(err)

	resp, err := s.db.PolicyClient.ListDefinitionValueEntitlementMappings(s.ctx, &subjectmapping.ListDefinitionValueEntitlementMappingsRequest{
		AttributeDefinitionId: attr.GetId(),
	})
	s.Require().NoError(err)
	s.Require().Len(resp.GetDefinitionValueEntitlementMappings(), 1)
	s.Equal(attr.GetId(), resp.GetDefinitionValueEntitlementMappings()[0].GetAttributeDefinition().GetId())
}

// createDefinition makes a fresh attribute under the example.com namespace with no values
// or subject mappings, so each test controls its own coexistence state.
func (s *DefinitionValueEntitlementMappingsSuite) createDefinition(name string, rule policy.AttributeRuleTypeEnum) *policy.Attribute {
	nsID := s.f.GetNamespaceKey("example.com").ID
	attr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		Name:        name,
		NamespaceId: nsID,
		Rule:        rule,
	})
	s.Require().NoError(err)
	s.Require().NotNil(attr)
	return attr
}

func (s *DefinitionValueEntitlementMappingsSuite) readAction() *policy.Action {
	return s.f.GetStandardAction(policydb.ActionRead.String())
}

func (s *DefinitionValueEntitlementMappingsSuite) resolver(selector string, op policy.DynamicValueOperatorEnum) *policy.DefinitionValueResolver {
	return &policy.DefinitionValueResolver{
		SubjectExternalSelectorValue: selector,
		Operator:                     op,
	}
}

func (s *DefinitionValueEntitlementMappingsSuite) sampleSCSCreate() *subjectmapping.SubjectConditionSetCreate {
	return &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{{
			ConditionGroups: []*policy.ConditionGroup{{
				BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
				Conditions: []*policy.Condition{{
					SubjectExternalSelectorValue: ".department",
					Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
					SubjectExternalValues:        []string{"cardiology"},
				}},
			}},
		}},
	}
}
