package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	policyservice "github.com/opentdf/platform/service/policy"
	"github.com/stretchr/testify/suite"
)

type PolicyObjectCountsSuite struct {
	suite.Suite
	db  fixtures.DBInterface
	ctx context.Context //nolint:containedctx // context is used in the test suite

	namespace                 *policy.Namespace
	emptyNamespace            *policy.Namespace
	attribute                 *policy.Attribute
	emptyAttribute            *policy.Attribute
	attributeValue            *policy.Value
	emptyAttributeValue       *policy.Value
	action                    *policy.Action
	initialActionCount        int64
	emptyNamespaceActionCount int64
	obligation                *policy.Obligation
	emptyObligation           *policy.Obligation
	excludedObligationValueID string
}

func (s *PolicyObjectCountsSuite) SetupSuite() {
	slog.Info("setting up db.PolicyObjectCounts test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_policy_object_counts"
	s.db = fixtures.NewDBInterface(s.ctx, c)
	_, err := s.db.Client.RunMigrations(s.ctx, policyservice.Migrations)
	s.Require().NoError(err)

	s.namespace, err = s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "policy-object-counts.example.com",
	})
	s.Require().NoError(err)
	s.emptyNamespace, err = s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "empty-policy-object-counts.example.com",
	})
	s.Require().NoError(err)
	s.initialActionCount, err = s.db.PolicyClient.GetCountActions(s.ctx, s.namespace.GetId(), "")
	s.Require().NoError(err)
	s.emptyNamespaceActionCount, err = s.db.PolicyClient.GetCountActions(s.ctx, s.emptyNamespace.GetId(), "")
	s.Require().NoError(err)

	s.attribute, err = s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		Name:        "count-attribute",
		NamespaceId: s.namespace.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	})
	s.Require().NoError(err)
	s.emptyAttribute, err = s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		Name:        "empty-count-attribute",
		NamespaceId: s.namespace.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	})
	s.Require().NoError(err)

	s.attributeValue, err = s.db.PolicyClient.CreateAttributeValue(s.ctx, s.attribute.GetId(), &attributes.CreateAttributeValueRequest{
		Value:       "count-value",
		AttributeId: s.attribute.GetId(),
	})
	s.Require().NoError(err)
	s.emptyAttributeValue, err = s.db.PolicyClient.CreateAttributeValue(s.ctx, s.attribute.GetId(), &attributes.CreateAttributeValueRequest{
		Value:       "empty-count-value",
		AttributeId: s.attribute.GetId(),
	})
	s.Require().NoError(err)

	group, err := s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, &resourcemapping.CreateResourceMappingGroupRequest{
		Name:        "count-group",
		NamespaceId: s.namespace.GetId(),
	})
	s.Require().NoError(err)
	for _, term := range []string{"count-term-one", "count-term-two", "count-term-three"} {
		_, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, &resourcemapping.CreateResourceMappingRequest{
			AttributeValueId: s.attributeValue.GetId(),
			Terms:            []string{term},
			GroupId:          group.GetId(),
		})
		s.Require().NoError(err)
	}

	s.action, err = s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:        "count-action-one",
		NamespaceId: s.namespace.GetId(),
	})
	s.Require().NoError(err)
	_, err = s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:        "count-action-two",
		NamespaceId: s.namespace.GetId(),
	})
	s.Require().NoError(err)

	var subjectConditionSetID string
	for range 2 {
		scs, err := s.db.PolicyClient.CreateSubjectConditionSet(
			s.ctx,
			newCountSubjectConditionSet(),
			s.namespace.GetId(),
			"",
		)
		s.Require().NoError(err)
		subjectConditionSetID = scs.GetId()
	}
	_, err = s.db.PolicyClient.CreateSubjectMapping(s.ctx, &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              s.attributeValue.GetId(),
		ExistingSubjectConditionSetId: subjectConditionSetID,
		Actions:                       []*policy.Action{{Id: s.action.GetId()}},
		NamespaceId:                   s.namespace.GetId(),
	})
	s.Require().NoError(err)

	s.obligation, err = s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		Name:        "count-obligation",
		NamespaceId: s.namespace.GetId(),
		Values:      []string{"count-obligation-value-one", "count-obligation-value-two", "count-obligation-value-three"},
	})
	s.Require().NoError(err)
	s.Require().Len(s.obligation.GetValues(), 3)
	s.emptyObligation, err = s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		Name:        "empty-count-obligation",
		NamespaceId: s.namespace.GetId(),
	})
	s.Require().NoError(err)

	for i, value := range s.obligation.GetValues() {
		if i == 0 {
			s.excludedObligationValueID = value.GetId()
		}
		_, err := s.db.PolicyClient.CreateObligationTrigger(s.ctx, &obligations.AddObligationTriggerRequest{
			ObligationValue: &common.IdFqnIdentifier{Id: value.GetId()},
			AttributeValue:  &common.IdFqnIdentifier{Id: s.attributeValue.GetId()},
			Action:          &common.IdNameIdentifier{Id: s.action.GetId()},
		})
		s.Require().NoError(err)
	}
}

func (s *PolicyObjectCountsSuite) TearDownSuite() {
	slog.Info("tearing down db.PolicyObjectCounts test suite")
	s.Require().NoError(s.db.DropSchema(s.ctx))
}

func (s *PolicyObjectCountsSuite) Test_ParentScopedCounts_ReturnExactCounts_Succeeds() {
	count, err := s.db.PolicyClient.GetCountAttributeDefinitions(s.ctx, s.namespace.GetId())
	s.Require().NoError(err)
	s.Equal(int64(2), count)
	count, err = s.db.PolicyClient.GetCountAttributeDefinitions(s.ctx, s.emptyNamespace.GetId())
	s.Require().NoError(err)
	s.Zero(count)

	count, err = s.db.PolicyClient.GetCountAttributeValues(s.ctx, s.attribute.GetId())
	s.Require().NoError(err)
	s.Equal(int64(2), count)

	count, err = s.db.PolicyClient.GetCountAttributeValues(s.ctx, s.emptyAttribute.GetId())
	s.Require().NoError(err)
	s.Zero(count)

	count, err = s.db.PolicyClient.GetCountResourceMappings(s.ctx, s.attributeValue.GetId())
	s.Require().NoError(err)
	s.Equal(int64(3), count)

	count, err = s.db.PolicyClient.GetCountResourceMappings(s.ctx, s.emptyAttributeValue.GetId())
	s.Require().NoError(err)
	s.Zero(count)

	count, err = s.db.PolicyClient.GetCountSubjectMappings(s.ctx, s.attributeValue.GetId())
	s.Require().NoError(err)
	s.Equal(int64(1), count)

	count, err = s.db.PolicyClient.GetCountSubjectMappings(s.ctx, s.emptyAttributeValue.GetId())
	s.Require().NoError(err)
	s.Zero(count)

	count, err = s.db.PolicyClient.GetCountObligationValues(s.ctx, s.obligation.GetId(), "")
	s.Require().NoError(err)
	s.Equal(int64(3), count)

	count, err = s.db.PolicyClient.GetCountObligationValues(s.ctx, "", s.obligation.GetFqn())
	s.Require().NoError(err)
	s.Equal(int64(3), count)

	count, err = s.db.PolicyClient.GetCountObligationValues(s.ctx, s.emptyObligation.GetId(), "")
	s.Require().NoError(err)
	s.Zero(count)
}

func (s *PolicyObjectCountsSuite) Test_NamespaceScopedCounts_ByIDAndFQN_Succeeds() {
	count, err := s.db.PolicyClient.GetCountSubjectConditionSets(s.ctx, s.namespace.GetId(), "")
	s.Require().NoError(err)
	s.Equal(int64(2), count)
	count, err = s.db.PolicyClient.GetCountSubjectConditionSets(s.ctx, "", s.namespace.GetFqn())
	s.Require().NoError(err)
	s.Equal(int64(2), count)

	count, err = s.db.PolicyClient.GetCountObligationDefinitions(s.ctx, s.namespace.GetId(), "")
	s.Require().NoError(err)
	s.Equal(int64(2), count)
	count, err = s.db.PolicyClient.GetCountObligationDefinitions(s.ctx, "", s.namespace.GetFqn())
	s.Require().NoError(err)
	s.Equal(int64(2), count)

	count, err = s.db.PolicyClient.GetCountActions(s.ctx, s.namespace.GetId(), "")
	s.Require().NoError(err)
	s.Equal(s.initialActionCount+2, count)
	count, err = s.db.PolicyClient.GetCountActions(s.ctx, "", s.namespace.GetFqn())
	s.Require().NoError(err)
	s.Equal(s.initialActionCount+2, count)

	resolvedNamespaceID, count, err := s.db.PolicyClient.GetCountResourceMappingGroups(s.ctx, s.namespace.GetId(), "")
	s.Require().NoError(err)
	s.Equal(s.namespace.GetId(), resolvedNamespaceID)
	s.Equal(int64(1), count)

	resolvedNamespaceID, count, err = s.db.PolicyClient.GetCountResourceMappingGroups(s.ctx, "", s.namespace.GetFqn())
	s.Require().NoError(err)
	s.Equal(s.namespace.GetId(), resolvedNamespaceID)
	s.Equal(int64(1), count)

	count, err = s.db.PolicyClient.GetCountSubjectConditionSets(s.ctx, s.emptyNamespace.GetId(), "")
	s.Require().NoError(err)
	s.Zero(count)

	count, err = s.db.PolicyClient.GetCountObligationDefinitions(s.ctx, s.emptyNamespace.GetId(), "")
	s.Require().NoError(err)
	s.Zero(count)

	count, err = s.db.PolicyClient.GetCountActions(s.ctx, s.emptyNamespace.GetId(), "")
	s.Require().NoError(err)
	s.Equal(s.emptyNamespaceActionCount, count)

	resolvedNamespaceID, count, err = s.db.PolicyClient.GetCountResourceMappingGroups(s.ctx, s.emptyNamespace.GetId(), "")
	s.Require().NoError(err)
	s.Equal(s.emptyNamespace.GetId(), resolvedNamespaceID)
	s.Zero(count)
}

func (s *PolicyObjectCountsSuite) Test_GetCountActionsWithNewAdditions_NormalizesNames_Succeeds() {
	currentCount, newAdditions, err := s.db.PolicyClient.GetCountActionsWithNewAdditions(
		s.ctx,
		s.namespace.GetId(),
		"",
		[]string{s.action.GetName(), "COUNT-ACTION-ONE", "new-action", "NEW-ACTION", ""},
	)
	s.Require().NoError(err)
	s.Equal(s.initialActionCount+2, currentCount)
	s.Equal(int64(1), newAdditions)

	countByFQN, additionsByFQN, err := s.db.PolicyClient.GetCountActionsWithNewAdditions(
		s.ctx,
		"",
		s.namespace.GetFqn(),
		[]string{s.action.GetName(), "new-action"},
	)
	s.Require().NoError(err)
	s.Equal(currentCount, countByFQN)
	s.Equal(newAdditions, additionsByFQN)
}

func (s *PolicyObjectCountsSuite) Test_GetCountObligationTriggersForAttributeValue_ByIdentifierAndExclusion_Succeeds() {
	resolvedAttributeValueID, count, err := s.db.PolicyClient.GetCountObligationTriggersForAttributeValue(
		s.ctx,
		&common.IdFqnIdentifier{Id: s.attributeValue.GetId()},
		"",
	)
	s.Require().NoError(err)
	s.Equal(s.attributeValue.GetId(), resolvedAttributeValueID)
	s.Equal(int64(3), count)

	resolvedAttributeValueID, count, err = s.db.PolicyClient.GetCountObligationTriggersForAttributeValue(
		s.ctx,
		&common.IdFqnIdentifier{Fqn: s.attributeValue.GetFqn()},
		"",
	)
	s.Require().NoError(err)
	s.Equal(s.attributeValue.GetId(), resolvedAttributeValueID)
	s.Equal(int64(3), count)

	resolvedAttributeValueID, count, err = s.db.PolicyClient.GetCountObligationTriggersForAttributeValue(
		s.ctx,
		&common.IdFqnIdentifier{Id: s.attributeValue.GetId()},
		s.excludedObligationValueID,
	)
	s.Require().NoError(err)
	s.Equal(s.attributeValue.GetId(), resolvedAttributeValueID)
	s.Equal(int64(2), count)

	resolvedAttributeValueID, count, err = s.db.PolicyClient.GetCountObligationTriggersForAttributeValue(
		s.ctx,
		&common.IdFqnIdentifier{Id: s.emptyAttributeValue.GetId()},
		"",
	)
	s.Require().NoError(err)
	s.Equal(s.emptyAttributeValue.GetId(), resolvedAttributeValueID)
	s.Zero(count)
}

func (s *PolicyObjectCountsSuite) Test_GlobalCounts_WithoutNamespaceIdentifier_Succeeds() {
	actionCount, err := s.db.PolicyClient.GetCountActions(s.ctx, "", "")
	s.Require().NoError(err)
	scsCount, err := s.db.PolicyClient.GetCountSubjectConditionSets(s.ctx, "", "")
	s.Require().NoError(err)

	globalAction, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{Name: "count-global-action"})
	s.Require().NoError(err)
	defer func() {
		_, err := s.db.PolicyClient.DeleteAction(s.ctx, &actions.DeleteActionRequest{Id: globalAction.GetId()})
		s.Require().NoError(err)
	}()

	globalSCS, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, newCountSubjectConditionSet(), "", "")
	s.Require().NoError(err)
	defer func() {
		_, err := s.db.PolicyClient.DeleteSubjectConditionSet(s.ctx, globalSCS.GetId())
		s.Require().NoError(err)
	}()

	count, err := s.db.PolicyClient.GetCountActions(s.ctx, "", "")
	s.Require().NoError(err)
	s.Equal(actionCount+1, count)

	count, err = s.db.PolicyClient.GetCountSubjectConditionSets(s.ctx, "", "")
	s.Require().NoError(err)
	s.Equal(scsCount+1, count)

	currentCount, newAdditions, err := s.db.PolicyClient.GetCountActionsWithNewAdditions(
		s.ctx,
		"",
		"",
		[]string{"COUNT-GLOBAL-ACTION", "new-global-action"},
	)
	s.Require().NoError(err)
	s.Equal(actionCount+1, currentCount)
	s.Equal(int64(1), newAdditions)
}

func (s *PolicyObjectCountsSuite) Test_ParentNamespaceLookups_ByIDAndFQN_Succeeds() {
	namespaceID, err := s.db.PolicyClient.GetAttributeDefinitionNamespaceID(s.ctx, s.attribute.GetId())
	s.Require().NoError(err)
	s.Equal(s.namespace.GetId(), namespaceID)

	namespaceID, err = s.db.PolicyClient.GetAttributeValueNamespaceID(
		s.ctx,
		&common.IdFqnIdentifier{Id: s.attributeValue.GetId()},
	)
	s.Require().NoError(err)
	s.Equal(s.namespace.GetId(), namespaceID)

	namespaceID, err = s.db.PolicyClient.GetAttributeValueNamespaceID(
		s.ctx,
		&common.IdFqnIdentifier{Fqn: s.attributeValue.GetFqn()},
	)
	s.Require().NoError(err)
	s.Equal(s.namespace.GetId(), namespaceID)
}

func (s *PolicyObjectCountsSuite) Test_NamespaceScopedCounts_UnknownNamespaceFqn_Fails() {
	const unknownNamespaceFQN = "https://unknown.example.com"

	_, _, err := s.db.PolicyClient.GetCountResourceMappingGroups(s.ctx, "", unknownNamespaceFQN)
	s.Require().ErrorIs(err, db.ErrNotFound)

	_, err = s.db.PolicyClient.GetCountSubjectConditionSets(s.ctx, "", unknownNamespaceFQN)
	s.Require().ErrorIs(err, db.ErrNotFound)

	_, err = s.db.PolicyClient.GetCountActions(s.ctx, "", unknownNamespaceFQN)
	s.Require().ErrorIs(err, db.ErrNotFound)

	_, _, err = s.db.PolicyClient.GetCountActionsWithNewAdditions(s.ctx, "", unknownNamespaceFQN, []string{"read"})
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *PolicyObjectCountsSuite) Test_ParentNamespaceLookups_UnknownIds_Fails() {
	unknownID := uuid.NewString()

	_, err := s.db.PolicyClient.GetAttributeDefinitionNamespaceID(s.ctx, unknownID)
	s.Require().ErrorIs(err, db.ErrNotFound)

	_, err = s.db.PolicyClient.GetAttributeValueNamespaceID(s.ctx, &common.IdFqnIdentifier{Id: unknownID})
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func TestPolicyObjectCountsSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping policy object counts integration tests")
	}
	suite.Run(t, new(PolicyObjectCountsSuite))
}

func newCountSubjectConditionSet() *subjectmapping.SubjectConditionSetCreate {
	return &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{{}},
	}
}
