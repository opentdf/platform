package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/dynamicvaluemapping"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	policydb "github.com/opentdf/platform/service/policy/db"
	"github.com/stretchr/testify/suite"
)

type DynamicValueMappingsSuite struct {
	suite.Suite
	f  fixtures.Fixtures
	db fixtures.DBInterface
	//nolint:containedctx // Only used for test suite
	ctx context.Context
}

func (s *DynamicValueMappingsSuite) SetupSuite() {
	slog.Info("setting up db.DynamicValueMappings test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_dynamic_value_mappings"
	s.db = fixtures.NewDBInterface(s.ctx, c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision(s.ctx)
}

func (s *DynamicValueMappingsSuite) TearDownSuite() {
	slog.Info("tearing down db.DynamicValueMappings test suite")
	s.f.TearDown(s.ctx)
}

func TestDynamicValueMappingsSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping dynamic_value_mappings integration tests")
	}
	suite.Run(t, new(DynamicValueMappingsSuite))
}

func (s *DynamicValueMappingsSuite) TestCreateAndGet() {
	attr := s.createDefinition("dvem_create_ok", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)

	created, err := s.db.PolicyClient.CreateDynamicValueMapping(s.ctx, &dynamicvaluemapping.CreateDynamicValueMappingRequest{
		AttributeDefinitionId: attr.GetId(),
		ValueResolver:         s.resolver(".patientAssignments[]", policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN),
		Actions:               []*policy.Action{s.readAction()},
	})
	s.Require().NoError(err)
	s.Require().NotEmpty(created.GetId())

	got, err := s.db.PolicyClient.GetDynamicValueMapping(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.Equal(attr.GetId(), got.GetAttributeDefinition().GetId())
	s.Equal(".patientAssignments[]", got.GetValueResolver().GetSubjectExternalSelectorValue())
	s.Equal(policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN, got.GetValueResolver().GetOperator())
	s.Len(got.GetActions(), 1)
	s.Nil(got.GetSubjectConditionSet(), "optional static pre-gate omitted")
}

func (s *DynamicValueMappingsSuite) TestCreateWithStaticGate() {
	attr := s.createDefinition("dvem_create_gate", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)

	created, err := s.db.PolicyClient.CreateDynamicValueMapping(s.ctx, &dynamicvaluemapping.CreateDynamicValueMappingRequest{
		AttributeDefinitionId:  attr.GetId(),
		ValueResolver:          s.resolver(".patientAssignments[]", policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN),
		Actions:                []*policy.Action{s.readAction()},
		NewSubjectConditionSet: s.sampleSCSCreate(),
	})
	s.Require().NoError(err)

	got, err := s.db.PolicyClient.GetDynamicValueMapping(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.Require().NotNil(got.GetSubjectConditionSet(), "static pre-gate should be hydrated")
	s.NotEmpty(got.GetSubjectConditionSet().GetSubjectSets())
}

func (s *DynamicValueMappingsSuite) TestRejectsHierarchyDefinition() {
	attr := s.createDefinition("dvem_hierarchy", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY)

	_, err := s.db.PolicyClient.CreateDynamicValueMapping(s.ctx, &dynamicvaluemapping.CreateDynamicValueMappingRequest{
		AttributeDefinitionId: attr.GetId(),
		ValueResolver:         s.resolver(".x[]", policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN),
		Actions:               []*policy.Action{s.readAction()},
	})
	s.Require().ErrorIs(err, db.ErrEnumValueInvalid, "HIERARCHY definitions must be rejected")
}

func (s *DynamicValueMappingsSuite) TestRejectsNotInOperator() {
	attr := s.createDefinition("dvem_not_in", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)

	_, err := s.db.PolicyClient.CreateDynamicValueMapping(s.ctx, &dynamicvaluemapping.CreateDynamicValueMappingRequest{
		AttributeDefinitionId: attr.GetId(),
		ValueResolver:         s.resolver(".x[]", policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN),
		Actions:               []*policy.Action{s.readAction()},
	})
	s.Require().ErrorIs(err, db.ErrEnumValueInvalid, "NOT_IN operator must be rejected for dynamic value resolution")
}

func (s *DynamicValueMappingsSuite) TestNoCoexistence_SubjectMappingThenDynamic() {
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
	_, err = s.db.PolicyClient.CreateDynamicValueMapping(s.ctx, &dynamicvaluemapping.CreateDynamicValueMappingRequest{
		AttributeDefinitionId: attr.GetId(),
		ValueResolver:         s.resolver(".x[]", policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN),
		Actions:               []*policy.Action{s.readAction()},
	})
	s.Require().ErrorIs(err, db.ErrRestrictViolation, "dynamic mapping must not coexist with value-level subject mappings")
}

func (s *DynamicValueMappingsSuite) TestNoCoexistence_DynamicThenSubjectMapping() {
	attr := s.createDefinition("dvem_coexist_rev", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)

	_, err := s.db.PolicyClient.CreateDynamicValueMapping(s.ctx, &dynamicvaluemapping.CreateDynamicValueMappingRequest{
		AttributeDefinitionId: attr.GetId(),
		ValueResolver:         s.resolver(".x[]", policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN),
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
	s.Require().ErrorIs(err, db.ErrRestrictViolation, "value-level subject mapping must not coexist with a dynamic mapping")
}

func (s *DynamicValueMappingsSuite) TestNoCoexistence_RegisteredResourceAAV() {
	attr := s.createDefinition("dvem_rr_coexist", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
	val, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attr.GetId(), &attributes.CreateAttributeValueRequest{Value: "rr_dvm_val"})
	s.Require().NoError(err)

	_, err = s.db.PolicyClient.CreateDynamicValueMapping(s.ctx, &dynamicvaluemapping.CreateDynamicValueMappingRequest{
		AttributeDefinitionId: attr.GetId(),
		ValueResolver:         s.resolver(".x[]", policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN),
		Actions:               []*policy.Action{s.readAction()},
	})
	s.Require().NoError(err)

	regRes, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		NamespaceId: s.f.GetNamespaceKey("example.com").ID,
		Name:        "dvem_rr_coexist_res",
	})
	s.Require().NoError(err)

	// A value under a definition with a dynamic mapping must not be added to a registered resource's
	// action attribute values.
	_, err = s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: regRes.GetId(),
		Value:      "rr_val_1",
		ActionAttributeValues: []*registeredresources.ActionAttributeValue{
			{
				ActionIdentifier: &registeredresources.ActionAttributeValue_ActionName{
					ActionName: policydb.ActionRead.String(),
				},
				AttributeValueIdentifier: &registeredresources.ActionAttributeValue_AttributeValueFqn{
					AttributeValueFqn: val.GetFqn(),
				},
			},
		},
	})
	s.Require().ErrorIs(err, db.ErrRestrictViolation, "value under a DVM definition must not be added to a registered resource's action attribute values")
}

func (s *DynamicValueMappingsSuite) TestNoCoexistence_RegisteredResourceAAVThenDynamic() {
	attr := s.createDefinition("dvem_rr_coexist_rev", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
	val, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attr.GetId(), &attributes.CreateAttributeValueRequest{Value: "rr_dvm_val_rev"})
	s.Require().NoError(err)

	regRes, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		NamespaceId: s.f.GetNamespaceKey("example.com").ID,
		Name:        "dvem_rr_coexist_rev_res",
	})
	s.Require().NoError(err)

	// The value is added to a registered resource's action attribute values before any dynamic
	// mapping exists, so this succeeds.
	_, err = s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: regRes.GetId(),
		Value:      "rr_val_rev_1",
		ActionAttributeValues: []*registeredresources.ActionAttributeValue{
			{
				ActionIdentifier: &registeredresources.ActionAttributeValue_ActionName{
					ActionName: policydb.ActionRead.String(),
				},
				AttributeValueIdentifier: &registeredresources.ActionAttributeValue_AttributeValueFqn{
					AttributeValueFqn: val.GetFqn(),
				},
			},
		},
	})
	s.Require().NoError(err)

	// The definition now has a value referenced by a registered resource's action attribute values;
	// a dynamic mapping must be rejected.
	_, err = s.db.PolicyClient.CreateDynamicValueMapping(s.ctx, &dynamicvaluemapping.CreateDynamicValueMappingRequest{
		AttributeDefinitionId: attr.GetId(),
		ValueResolver:         s.resolver(".x[]", policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN),
		Actions:               []*policy.Action{s.readAction()},
	})
	s.Require().ErrorIs(err, db.ErrRestrictViolation, "dynamic mapping must not coexist with values already on a registered resource's action attribute values")
}

func (s *DynamicValueMappingsSuite) TestRejectsRuleChangeToHierarchy() {
	attr := s.createDefinition("dvem_rule_guard", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)

	_, err := s.db.PolicyClient.CreateDynamicValueMapping(s.ctx, &dynamicvaluemapping.CreateDynamicValueMappingRequest{
		AttributeDefinitionId: attr.GetId(),
		ValueResolver:         s.resolver(".x[]", policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN),
		Actions:               []*policy.Action{s.readAction()},
	})
	s.Require().NoError(err)

	_, err = s.db.PolicyClient.UnsafeUpdateAttribute(s.ctx, &unsafe.UnsafeUpdateAttributeRequest{
		Id:   attr.GetId(),
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
	})
	s.Require().ErrorIs(err, db.ErrRestrictViolation, "changing the rule to HIERARCHY must be rejected when a dynamic mapping exists")
}

func (s *DynamicValueMappingsSuite) TestUpdateAndDelete() {
	attr := s.createDefinition("dvem_update_delete", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF)

	created, err := s.db.PolicyClient.CreateDynamicValueMapping(s.ctx, &dynamicvaluemapping.CreateDynamicValueMappingRequest{
		AttributeDefinitionId: attr.GetId(),
		ValueResolver:         s.resolver(".patientAssignments[]", policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN),
		Actions:               []*policy.Action{s.readAction()},
	})
	s.Require().NoError(err)

	updated, err := s.db.PolicyClient.UpdateDynamicValueMapping(s.ctx, &dynamicvaluemapping.UpdateDynamicValueMappingRequest{
		Id:            created.GetId(),
		ValueResolver: s.resolver(".accounts[]", policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS),
	})
	s.Require().NoError(err)
	s.Equal(".accounts[]", updated.GetValueResolver().GetSubjectExternalSelectorValue())
	s.Equal(policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS, updated.GetValueResolver().GetOperator())

	_, err = s.db.PolicyClient.DeleteDynamicValueMapping(s.ctx, created.GetId())
	s.Require().NoError(err)

	_, err = s.db.PolicyClient.GetDynamicValueMapping(s.ctx, created.GetId())
	s.Require().ErrorIs(err, db.ErrNotFound, "mapping should be gone after delete")
}

func (s *DynamicValueMappingsSuite) TestListByDefinition() {
	attr := s.createDefinition("dvem_list", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
	_, err := s.db.PolicyClient.CreateDynamicValueMapping(s.ctx, &dynamicvaluemapping.CreateDynamicValueMappingRequest{
		AttributeDefinitionId: attr.GetId(),
		ValueResolver:         s.resolver(".patientAssignments[]", policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN),
		Actions:               []*policy.Action{s.readAction()},
	})
	s.Require().NoError(err)

	resp, err := s.db.PolicyClient.ListDynamicValueMappings(s.ctx, &dynamicvaluemapping.ListDynamicValueMappingsRequest{
		AttributeDefinitionId: attr.GetId(),
	})
	s.Require().NoError(err)
	s.Require().Len(resp.GetDynamicValueMappings(), 1)
	s.Equal(attr.GetId(), resp.GetDynamicValueMappings()[0].GetAttributeDefinition().GetId())
}

func (s *DynamicValueMappingsSuite) TestListByDefinition_Pagination() {
	attr := s.createDefinition("dvem_list_page", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
	for _, selector := range []string{".a[]", ".b[]", ".c[]"} {
		_, err := s.db.PolicyClient.CreateDynamicValueMapping(s.ctx, &dynamicvaluemapping.CreateDynamicValueMappingRequest{
			AttributeDefinitionId: attr.GetId(),
			ValueResolver:         s.resolver(selector, policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN),
			Actions:               []*policy.Action{s.readAction()},
		})
		s.Require().NoError(err)
	}

	// first page: limit 2 of 3 -> next offset points past the page
	first, err := s.db.PolicyClient.ListDynamicValueMappings(s.ctx, &dynamicvaluemapping.ListDynamicValueMappingsRequest{
		AttributeDefinitionId: attr.GetId(),
		Pagination:            &policy.PageRequest{Limit: 2},
	})
	s.Require().NoError(err)
	s.Len(first.GetDynamicValueMappings(), 2)
	s.Equal(int32(3), first.GetPagination().GetTotal())
	s.Equal(int32(2), first.GetPagination().GetNextOffset())

	// track ids to assert the pages partition the corpus (no overlap, no gaps)
	seen := map[string]struct{}{}
	for _, m := range first.GetDynamicValueMappings() {
		seen[m.GetId()] = struct{}{}
	}
	s.Len(seen, 2, "first page should contain two distinct mappings")

	// second page: remaining item, no further pages
	second, err := s.db.PolicyClient.ListDynamicValueMappings(s.ctx, &dynamicvaluemapping.ListDynamicValueMappingsRequest{
		AttributeDefinitionId: attr.GetId(),
		Pagination:            &policy.PageRequest{Limit: 2, Offset: 2},
	})
	s.Require().NoError(err)
	s.Len(second.GetDynamicValueMappings(), 1)
	s.Equal(int32(3), second.GetPagination().GetTotal())
	s.Equal(int32(0), second.GetPagination().GetNextOffset())

	for _, m := range second.GetDynamicValueMappings() {
		_, overlap := seen[m.GetId()]
		s.False(overlap, "page 2 must not repeat an item from page 1")
		seen[m.GetId()] = struct{}{}
	}
	s.Len(seen, 3, "combined pages should cover all created mappings exactly once")
}

// createDefinition makes a fresh attribute under the example.com namespace with no values
// or subject mappings, so each test controls its own coexistence state.
func (s *DynamicValueMappingsSuite) createDefinition(name string, rule policy.AttributeRuleTypeEnum) *policy.Attribute {
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

func (s *DynamicValueMappingsSuite) readAction() *policy.Action {
	return s.f.GetStandardAction(policydb.ActionRead.String())
}

func (s *DynamicValueMappingsSuite) resolver(selector string, operator policy.SubjectMappingOperatorEnum) *policy.DynamicValueResolver {
	return &policy.DynamicValueResolver{
		SubjectExternalSelectorValue: selector,
		Operator:                     operator,
	}
}

func (s *DynamicValueMappingsSuite) sampleSCSCreate() *subjectmapping.SubjectConditionSetCreate {
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
