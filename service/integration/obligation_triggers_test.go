package integration

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/suite"
)

const (
	namespaceName      = "test-namespace"
	attributeName      = "test-attribute"
	attributeValueName = "test-value"
	actionName         = "test-action"
	obligationName     = "test-obligation"
	obligationValue    = "test-obligation-value"
	clientID           = "test-client-id"
)

type ObligationTriggersSuite struct {
	suite.Suite
	ctx                       context.Context //nolint:containedctx // context is used in the test suite
	db                        fixtures.DBInterface
	f                         fixtures.Fixtures
	namespace                 *policy.Namespace
	attribute                 *policy.Attribute
	attributeValue            *policy.Value
	action                    *policy.Action
	obligation                *policy.Obligation
	obligationValue           *policy.ObligationValue
	triggerIDsToClean         []string
	obligationValueIDsToClean []string
}

type DifferentNamespaceEntities struct {
	Namespace        *policy.Namespace
	Obligation       *policy.Obligation
	ObligationValue  *policy.ObligationValue
	Attribute        *policy.Attribute
	AttributeValue   *policy.Value
	Trigger          *policy.ObligationTrigger
	CleanupNamespace func()
	CleanupTrigger   func()
}

func (s *ObligationTriggersSuite) SetupSuite() {
	slog.Info("setting up db.Obligations test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_obligation_triggers"
	s.db = fixtures.NewDBInterface(s.ctx, c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision(s.ctx)

	var err error

	// Create a namespace
	s.namespace, err = s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: namespaceName,
	})
	s.Require().NoError(err)

	// Create an attribute
	s.attribute, err = s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		Name:        attributeName,
		NamespaceId: s.namespace.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	})
	s.Require().NoError(err)

	// Create an attribute value
	s.attributeValue, err = s.db.PolicyClient.CreateAttributeValue(s.ctx, s.attribute.GetId(), &attributes.CreateAttributeValueRequest{
		Value:       attributeValueName,
		AttributeId: s.attribute.GetId(),
	})
	s.Require().NoError(err)

	// Create an action
	s.action, err = s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name: actionName,
	})
	s.Require().NoError(err)

	// Create an obligation
	s.obligation, err = s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		Name:        obligationName,
		NamespaceId: s.namespace.GetId(),
	})
	s.Require().NoError(err)

	// Create an obligation value
	s.obligationValue, err = s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationId: s.obligation.GetId(),
		Value:        obligationValue,
	})
	s.Require().NoError(err)
}

func (s *ObligationTriggersSuite) TearDownSuite() {
	var err error
	ctx := context.Background()

	_, err = s.db.PolicyClient.DeleteObligation(ctx, &obligations.DeleteObligationRequest{
		Id: s.obligation.GetId(),
	})
	s.Require().NoError(err)

	_, err = s.db.PolicyClient.DeleteAction(ctx, &actions.DeleteActionRequest{
		Id: s.action.GetId(),
	})
	s.Require().NoError(err)

	_, err = s.db.PolicyClient.UnsafeDeleteNamespace(ctx, s.namespace, s.namespace.GetFqn())
	s.Require().NoError(err)
}

func (s *ObligationTriggersSuite) TearDownTest() {
	for _, triggerID := range s.triggerIDsToClean {
		_, err := s.db.PolicyClient.DeleteObligationTrigger(s.ctx, &obligations.RemoveObligationTriggerRequest{
			Id: triggerID,
		})
		s.Require().NoError(err)
	}
	for _, obligationValueID := range s.obligationValueIDsToClean {
		_, err := s.db.PolicyClient.DeleteObligationValue(s.ctx, &obligations.DeleteObligationValueRequest{
			Id: obligationValueID,
		})
		s.Require().NoError(err)
	}
	s.triggerIDsToClean = nil
	s.obligationValueIDsToClean = nil
}

func TestObligationTriggersSuite(t *testing.T) {
	suite.Run(t, new(ObligationTriggersSuite))
}

func (s *ObligationTriggersSuite) Test_CreateObligationTrigger_NoMetadata_Success() {
	s.triggerIDsToClean = append(s.triggerIDsToClean, s.createGenericTrigger().GetId())
}

func (s *ObligationTriggersSuite) Test_CreateObligationTrigger_WithIDs_Success() {
	trigger, err := s.db.PolicyClient.CreateObligationTrigger(s.ctx, &obligations.AddObligationTriggerRequest{
		ObligationValue: &common.IdFqnIdentifier{Id: s.obligationValue.GetId()},
		AttributeValue:  &common.IdFqnIdentifier{Id: s.attributeValue.GetId()},
		Action:          &common.IdNameIdentifier{Id: s.action.GetId()},
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{"source": "test"},
		},
		Context: &policy.RequestContext{
			Pep: &policy.PolicyEnforcementPoint{
				ClientId: clientID,
			},
		},
	})
	s.triggerIDsToClean = append(s.triggerIDsToClean, trigger.GetId())
	s.Require().NoError(err)
	s.validateTriggerWithDefaults(trigger, true)
	s.Require().Equal("test", trigger.GetMetadata().GetLabels()["source"])
}

func (s *ObligationTriggersSuite) Test_CreateObligationTrigger_NoCtx_Success() {
	trigger, err := s.db.PolicyClient.CreateObligationTrigger(s.ctx, &obligations.AddObligationTriggerRequest{
		ObligationValue: &common.IdFqnIdentifier{Id: s.obligationValue.GetId()},
		AttributeValue:  &common.IdFqnIdentifier{Id: s.attributeValue.GetId()},
		Action:          &common.IdNameIdentifier{Id: s.action.GetId()},
	})
	s.triggerIDsToClean = append(s.triggerIDsToClean, trigger.GetId())
	s.Require().NoError(err)
	s.validateTriggerWithDefaults(trigger, false)
}

func (s *ObligationTriggersSuite) Test_CreateObligationTrigger_WithNameFQN_Success() {
	trigger, err := s.db.PolicyClient.CreateObligationTrigger(s.ctx, &obligations.AddObligationTriggerRequest{
		ObligationValue: &common.IdFqnIdentifier{Fqn: s.obligation.GetNamespace().GetFqn() + "/obl/" + s.obligationValue.GetObligation().GetName() + "/value/" + s.obligationValue.GetValue()},
		AttributeValue:  &common.IdFqnIdentifier{Fqn: s.attributeValue.GetFqn()},
		Action:          &common.IdNameIdentifier{Name: s.action.GetName()},
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{"source": "test"},
		},
		Context: &policy.RequestContext{
			Pep: &policy.PolicyEnforcementPoint{
				ClientId: clientID,
			},
		},
	})
	s.triggerIDsToClean = append(s.triggerIDsToClean, trigger.GetId())
	s.Require().NoError(err)
	s.validateTriggerWithDefaults(trigger, true)
	s.Require().Equal("test", trigger.GetMetadata().GetLabels()["source"])
}

func (s *ObligationTriggersSuite) Test_CreateObligationTrigger_ObligationValueNotFound_Fails() {
	randomID := uuid.NewString()
	trigger, err := s.db.PolicyClient.CreateObligationTrigger(s.ctx, &obligations.AddObligationTriggerRequest{
		ObligationValue: &common.IdFqnIdentifier{Id: randomID},
		AttributeValue:  &common.IdFqnIdentifier{Id: s.attributeValue.GetId()},
		Action:          &common.IdNameIdentifier{Id: s.action.GetId()},
		Context: &policy.RequestContext{
			Pep: &policy.PolicyEnforcementPoint{
				ClientId: clientID,
			},
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(trigger)
}

func (s *ObligationTriggersSuite) Test_CreateObligationTrigger_AttributeValueNotFound_Fails() {
	randomID := uuid.NewString()
	trigger, err := s.db.PolicyClient.CreateObligationTrigger(s.ctx, &obligations.AddObligationTriggerRequest{
		ObligationValue: &common.IdFqnIdentifier{Id: s.obligationValue.GetId()},
		AttributeValue:  &common.IdFqnIdentifier{Id: randomID},
		Action:          &common.IdNameIdentifier{Id: s.action.GetId()},
		Context: &policy.RequestContext{
			Pep: &policy.PolicyEnforcementPoint{
				ClientId: clientID,
			},
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotNullViolation)
	s.Nil(trigger)
}

func (s *ObligationTriggersSuite) Test_CreateObligationTrigger_ActionNotFound_Fails() {
	randomID := uuid.NewString()
	trigger, err := s.db.PolicyClient.CreateObligationTrigger(s.ctx, &obligations.AddObligationTriggerRequest{
		ObligationValue: &common.IdFqnIdentifier{Id: s.obligationValue.GetId()},
		AttributeValue:  &common.IdFqnIdentifier{Id: s.attributeValue.GetId()},
		Action:          &common.IdNameIdentifier{Id: randomID},
		Context: &policy.RequestContext{
			Pep: &policy.PolicyEnforcementPoint{
				ClientId: clientID,
			},
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrInvalidOblTriParam)
	s.Nil(trigger)
}

func (s *ObligationTriggersSuite) Test_CreateObligationTrigger_AttributeValueDifferentNamespace_Fails() {
	// Create a different namespace
	differentNamespace, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "different-namespace",
	})
	s.Require().NoError(err)
	defer func() {
		_, err := s.db.PolicyClient.UnsafeDeleteNamespace(s.ctx, differentNamespace, differentNamespace.GetFqn())
		s.Require().NoError(err)
	}()

	// Create an attribute in the different namespace
	differentAttribute, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		Name:        "different-attribute",
		NamespaceId: differentNamespace.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	})
	s.Require().NoError(err)

	// Create an attribute value in the different namespace
	differentAttributeValue, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, differentAttribute.GetId(), &attributes.CreateAttributeValueRequest{
		Value:       "different-value",
		AttributeId: differentAttribute.GetId(),
	})
	s.Require().NoError(err)

	// Try to create a trigger with obligation value from one namespace and attribute value from another
	trigger, err := s.db.PolicyClient.CreateObligationTrigger(s.ctx, &obligations.AddObligationTriggerRequest{
		ObligationValue: &common.IdFqnIdentifier{Id: s.obligationValue.GetId()},
		AttributeValue:  &common.IdFqnIdentifier{Id: differentAttributeValue.GetId()},
		Action:          &common.IdNameIdentifier{Id: s.action.GetId()},
		Context: &policy.RequestContext{
			Pep: &policy.PolicyEnforcementPoint{
				ClientId: clientID,
			},
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrInvalidOblTriParam)
	s.Nil(trigger)
}

func (s *ObligationTriggersSuite) Test_DeleteObligationTrigger_Success() {
	trigger := s.createGenericTrigger()
	deletedTrigger, err := s.db.PolicyClient.DeleteObligationTrigger(s.ctx, &obligations.RemoveObligationTriggerRequest{
		Id: trigger.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(deletedTrigger)
	s.Equal(trigger.GetId(), deletedTrigger.GetId())
}

func (s *ObligationTriggersSuite) Test_DeleteObligationTrigger_NotFound_Fails() {
	randomID := uuid.NewString()
	_, err := s.db.PolicyClient.DeleteObligationTrigger(s.ctx, &obligations.RemoveObligationTriggerRequest{
		Id: randomID,
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

// ListObligationTriggers tests
func (s *ObligationTriggersSuite) Test_ListObligationTriggers_NoTriggersNoFilter_Success() {
	triggers, pageResult, err := s.db.PolicyClient.ListObligationTriggers(s.ctx, &obligations.ListObligationTriggersRequest{})
	s.Require().NoError(err)
	s.Require().Empty(triggers)
	s.Require().NotNil(pageResult)
	s.validatePageResponses(pageResult, 0, 0, 0)
}

func (s *ObligationTriggersSuite) Test_ListObligationTriggers_OrdersByCreatedAt_Succeeds() {
	first := s.createUniqueTrigger("ordered-first")
	s.triggerIDsToClean = append(s.triggerIDsToClean, first.GetId())
	s.obligationValueIDsToClean = append(s.obligationValueIDsToClean, first.GetObligationValue().GetId())
	time.Sleep(5 * time.Millisecond)
	second := s.createUniqueTrigger("ordered-second")
	s.triggerIDsToClean = append(s.triggerIDsToClean, second.GetId())
	s.obligationValueIDsToClean = append(s.obligationValueIDsToClean, second.GetObligationValue().GetId())
	time.Sleep(5 * time.Millisecond)
	third := s.createUniqueTrigger("ordered-third")
	s.triggerIDsToClean = append(s.triggerIDsToClean, third.GetId())
	s.obligationValueIDsToClean = append(s.obligationValueIDsToClean, third.GetObligationValue().GetId())

	triggers, _, err := s.db.PolicyClient.ListObligationTriggers(s.ctx, &obligations.ListObligationTriggersRequest{
		NamespaceId: s.namespace.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(triggers)

	assertIDsInOrder(s.T(), triggers, func(t *policy.ObligationTrigger) string { return t.GetId() }, first.GetId(), second.GetId(), third.GetId())
}

func (s *ObligationTriggersSuite) Test_ListObligationTriggers_NoTriggersWithNamespaceId_Success() {
	triggers, pageResult, err := s.db.PolicyClient.ListObligationTriggers(s.ctx, &obligations.ListObligationTriggersRequest{
		NamespaceId: s.namespace.GetId(),
	})
	s.Require().NoError(err)
	s.Require().Empty(triggers)
	s.validatePageResponses(pageResult, 0, 0, 0)
}

func (s *ObligationTriggersSuite) Test_ListObligationTriggers_NoTriggersWithNamespaceFqn_Success() {
	triggers, pageResult, err := s.db.PolicyClient.ListObligationTriggers(s.ctx, &obligations.ListObligationTriggersRequest{
		NamespaceFqn: s.namespace.GetFqn(),
	})
	s.Require().NoError(err)
	s.Require().Empty(triggers)
	s.validatePageResponses(pageResult, 0, 0, 0)
}

func (s *ObligationTriggersSuite) Test_ListObligationTriggers_MultipleTriggersNoFilter_MultipleNamespaces_Success() {
	createdTriggersMap := s.createMultipleUniqueTriggers(2)
	s.appendObligationValuesToClean(createdTriggersMap)
	differentNS := s.createDifferentNamespaceWithTrigger("different-namespace-id-test")
	defer differentNS.CleanupNamespace()
	defer differentNS.CleanupTrigger()
	createdTriggersMap[differentNS.Trigger.GetId()] = differentNS.Trigger

	triggers, pageResult, err := s.db.PolicyClient.ListObligationTriggers(s.ctx, &obligations.ListObligationTriggersRequest{})
	s.Require().NoError(err)
	s.Require().Len(triggers, 3)
	s.validatePageResponses(pageResult, 3, 0, 0)

	// Verify all triggers are returned
	foundTriggers := make(map[string]bool)
	for _, t := range triggers {
		createdTrigger, ok := createdTriggersMap[t.GetId()]
		s.Require().True(ok)
		foundTriggers[t.GetId()] = true
		s.validateTrigger(t, createdTrigger.GetObligationValue(), createdTrigger.GetAttributeValue(), createdTrigger.GetAction(), true)
	}
	// Validate all triggers are found
	for id := range createdTriggersMap {
		s.Require().True(foundTriggers[id])
	}
}

func (s *ObligationTriggersSuite) Test_ListObligationTriggers_MultipleTriggersWithNamespaceId_MultipleNamespaces_Success() {
	createdTriggersMap := s.createMultipleUniqueTriggers(2)
	s.appendObligationValuesToClean(createdTriggersMap)
	differentNS := s.createDifferentNamespaceWithTrigger("different-namespace-id-test")
	defer differentNS.CleanupNamespace()
	defer differentNS.CleanupTrigger()

	triggers, pageResult, err := s.db.PolicyClient.ListObligationTriggers(s.ctx, &obligations.ListObligationTriggersRequest{
		NamespaceId: s.namespace.GetId(),
	})
	s.Require().NoError(err)
	s.Require().Len(triggers, 2)
	s.validatePageResponses(pageResult, 2, 0, 0)

	foundTriggers := make(map[string]bool)
	for _, t := range triggers {
		s.Require().Equal(s.namespace.GetId(), t.GetObligationValue().GetObligation().GetNamespace().GetId())
		createdTrigger, ok := createdTriggersMap[t.GetId()]
		s.Require().True(ok)
		s.validateTrigger(t, createdTrigger.GetObligationValue(), createdTrigger.GetAttributeValue(), createdTrigger.GetAction(), true)
		foundTriggers[t.GetId()] = true
	}
	for id := range createdTriggersMap {
		s.Require().True(foundTriggers[id])
	}
}

func (s *ObligationTriggersSuite) Test_ListObligationTriggers_MultipleTriggersWithNamespaceFqn_Success() {
	createdTriggersMap := s.createMultipleUniqueTriggers(2)
	s.appendObligationValuesToClean(createdTriggersMap)
	differentNS := s.createDifferentNamespaceWithTrigger("different-namespace-id-test")
	defer differentNS.CleanupNamespace()
	defer differentNS.CleanupTrigger()

	triggers, pageResult, err := s.db.PolicyClient.ListObligationTriggers(s.ctx, &obligations.ListObligationTriggersRequest{
		NamespaceFqn: s.namespace.GetFqn(),
	})
	s.Require().NoError(err)
	s.Require().Len(triggers, 2)
	s.validatePageResponses(pageResult, 2, 0, 0)

	foundTriggers := make(map[string]bool)
	for _, t := range triggers {
		s.Require().Equal(s.namespace.GetFqn(), t.GetObligationValue().GetObligation().GetNamespace().GetFqn())
		createdTrigger, ok := createdTriggersMap[t.GetId()]
		s.Require().True(ok)
		s.validateTrigger(t, createdTrigger.GetObligationValue(), createdTrigger.GetAttributeValue(), createdTrigger.GetAction(), true)
		foundTriggers[t.GetId()] = true
	}
	for id := range createdTriggersMap {
		s.Require().True(foundTriggers[id])
	}
}

func (s *ObligationTriggersSuite) Test_ListObligationTriggers_WithPagination_Success() {
	createdTriggersMap := s.createMultipleUniqueTriggers(5)
	s.appendObligationValuesToClean(createdTriggersMap)
	var currentOffset int32
	foundTriggers := make(map[string]bool)
	var total int32 = 5
	var limit int32 = 2
	for i := 0; i < 3; i++ {
		nextOffset := currentOffset + 2
		expectedTriggersCount := 2
		if i == 2 {
			nextOffset = 0
			expectedTriggersCount = 1
		}

		triggers, pageResult, err := s.db.PolicyClient.ListObligationTriggers(s.ctx, &obligations.ListObligationTriggersRequest{
			Pagination: &policy.PageRequest{
				Limit:  limit,
				Offset: currentOffset,
			},
		})
		s.Require().NoError(err)

		for _, t := range triggers {
			s.validateTrigger(t, createdTriggersMap[t.GetId()].GetObligationValue(), createdTriggersMap[t.GetId()].GetAttributeValue(), createdTriggersMap[t.GetId()].GetAction(), true)
			foundTriggers[t.GetId()] = true
		}
		s.Require().Len(triggers, expectedTriggersCount)
		s.validatePageResponses(pageResult, total, currentOffset, nextOffset)
		currentOffset = pageResult.GetNextOffset()
	}
	s.Require().Len(foundTriggers, 5)
}

func (s *ObligationTriggersSuite) Test_ListObligationTriggers_WithNamespaceAndPagination_Success() {
	trigger := s.createGenericTrigger()
	s.triggerIDsToClean = append(s.triggerIDsToClean, trigger.GetId())
	differentNS := s.createDifferentNamespaceWithTrigger("different-namespace-for-list-test")
	defer differentNS.CleanupNamespace()
	defer differentNS.CleanupTrigger()

	triggers, pageRes, err := s.db.PolicyClient.ListObligationTriggers(s.ctx, &obligations.ListObligationTriggersRequest{
		NamespaceId: s.namespace.GetId(),
		Pagination: &policy.PageRequest{
			Limit: 1,
		},
	})
	s.Require().NoError(err)
	s.Require().Len(triggers, 1)
	s.validatePageResponses(pageRes, 1, 0, 0)
	s.Require().Equal(s.namespace.GetId(), triggers[0].GetObligationValue().GetObligation().GetNamespace().GetId())
	s.validateTriggerWithDefaults(triggers[0], true)
}

func (s *ObligationTriggersSuite) Test_ListObligationTriggers_LimitToLarge() {
	triggers, pageRes, err := s.db.PolicyClient.ListObligationTriggers(s.ctx, &obligations.ListObligationTriggersRequest{
		NamespaceId: s.namespace.GetId(),
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax + 1,
		},
	})
	s.Require().ErrorIs(err, db.ErrListLimitTooLarge)
	s.Require().Nil(triggers)
	s.Require().Nil(pageRes)
}

func (s *ObligationTriggersSuite) Test_ListObligationTriggers_NoContext_Success() {
	// Create a trigger without context
	trigger, err := s.db.PolicyClient.CreateObligationTrigger(s.ctx, &obligations.AddObligationTriggerRequest{
		ObligationValue: &common.IdFqnIdentifier{Id: s.obligationValue.GetId()},
		AttributeValue:  &common.IdFqnIdentifier{Id: s.attributeValue.GetId()},
		Action:          &common.IdNameIdentifier{Id: s.action.GetId()},
	})
	s.Require().NoError(err)
	s.triggerIDsToClean = append(s.triggerIDsToClean, trigger.GetId())

	// List triggers
	triggers, pageResult, err := s.db.PolicyClient.ListObligationTriggers(s.ctx, &obligations.ListObligationTriggersRequest{})
	s.Require().NoError(err)
	s.Require().Len(triggers, 1)
	s.validatePageResponses(pageResult, 1, 0, 0)

	// Verify the listed trigger has no context
	listedTrigger := triggers[0]
	s.Require().Equal(trigger.GetId(), listedTrigger.GetId())
	s.validateTriggerWithDefaults(listedTrigger, false)
}

func (s *ObligationTriggersSuite) createGenericTrigger() *policy.ObligationTrigger {
	trigger, err := s.db.PolicyClient.CreateObligationTrigger(s.ctx, &obligations.AddObligationTriggerRequest{
		ObligationValue: &common.IdFqnIdentifier{Id: s.obligationValue.GetId()},
		AttributeValue:  &common.IdFqnIdentifier{Id: s.attributeValue.GetId()},
		Action:          &common.IdNameIdentifier{Id: s.action.GetId()},
		Metadata:        &common.MetadataMutable{},
		Context: &policy.RequestContext{
			Pep: &policy.PolicyEnforcementPoint{
				ClientId: clientID,
			},
		},
	})
	s.Require().NoError(err)
	s.validateTriggerWithDefaults(trigger, true)
	return trigger
}

func (s *ObligationTriggersSuite) createUniqueTrigger(uniqueSuffix string) *policy.ObligationTrigger {
	// Create a unique obligation value for this trigger
	uniqueObligationValue, err := s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationId: s.obligation.GetId(),
		Value:        obligationValue + "-" + uniqueSuffix,
	})
	s.Require().NoError(err)

	trigger, err := s.db.PolicyClient.CreateObligationTrigger(s.ctx, &obligations.AddObligationTriggerRequest{
		ObligationValue: &common.IdFqnIdentifier{Id: uniqueObligationValue.GetId()},
		AttributeValue:  &common.IdFqnIdentifier{Id: s.attributeValue.GetId()},
		Action:          &common.IdNameIdentifier{Id: s.action.GetId()},
		Metadata:        &common.MetadataMutable{},
		Context: &policy.RequestContext{
			Pep: &policy.PolicyEnforcementPoint{
				ClientId: clientID,
			},
		},
	})
	s.Require().NoError(err)

	// Validate the trigger with the unique obligation value using the refactored method
	s.validateTrigger(trigger, uniqueObligationValue, s.attributeValue, s.action, true)

	return trigger
}

func (s *ObligationTriggersSuite) createMultipleUniqueTriggers(count int) map[string]*policy.ObligationTrigger {
	triggersMap := make(map[string]*policy.ObligationTrigger)
	for i := range count {
		trigger := s.createUniqueTrigger(fmt.Sprintf("trigger-%d", i))
		triggersMap[trigger.GetId()] = trigger
		s.triggerIDsToClean = append(s.triggerIDsToClean, trigger.GetId())
	}
	return triggersMap
}

// validateTrigger validates that the actual trigger matches the expected values
func (s *ObligationTriggersSuite) validateTrigger(actual *policy.ObligationTrigger, expectedObligationValue *policy.ObligationValue, expectedAttributeValue *policy.Value, expectedAction *policy.Action, shouldHaveCtx bool) {
	s.Require().NotNil(actual)
	s.Require().NotEmpty(actual.GetId())

	// Validate attribute value
	s.Require().Equal(expectedAttributeValue.GetId(), actual.GetAttributeValue().GetId())
	s.Require().Equal(expectedAttributeValue.GetFqn(), actual.GetAttributeValue().GetFqn())
	s.Require().Equal(expectedAttributeValue.GetValue(), actual.GetAttributeValue().GetValue())

	// Validate obligation value
	s.Require().Equal(expectedObligationValue.GetId(), actual.GetObligationValue().GetId())
	s.Require().Equal(expectedObligationValue.GetValue(), actual.GetObligationValue().GetValue())
	s.Require().Equal(expectedObligationValue.GetObligation().GetId(), actual.GetObligationValue().GetObligation().GetId())
	s.Require().Equal(expectedObligationValue.GetObligation().GetName(), actual.GetObligationValue().GetObligation().GetName())
	s.Require().Equal(expectedObligationValue.GetObligation().GetNamespace().GetFqn(), actual.GetObligationValue().GetObligation().GetNamespace().GetFqn())
	s.Require().NotEmpty(expectedObligationValue.GetFqn())
	s.Require().Equal(expectedObligationValue.GetFqn(), actual.GetObligationValue().GetFqn())
	s.Require().Empty(actual.GetObligationValue().GetTriggers())

	// Validate action
	s.Require().Equal(expectedAction.GetId(), actual.GetAction().GetId())
	s.Require().Equal(expectedAction.GetName(), actual.GetAction().GetName())

	// Validate context
	if shouldHaveCtx {
		s.Require().NotNil(actual.GetContext())
		s.Require().Len(actual.GetContext(), 1)
		s.Require().NotNil(actual.GetContext()[0].GetPep())
		s.Require().Equal(clientID, actual.GetContext()[0].GetPep().GetClientId())
	} else {
		s.Require().Empty(actual.GetContext())
	}
}

func (s *ObligationTriggersSuite) validatePageResponses(pageResult *policy.PageResponse, expectedTotal, expectedCurrentOffset, expectedNextOffset int32) {
	s.Require().NotNil(pageResult)
	s.Require().Equal(expectedTotal, pageResult.GetTotal())
	s.Require().Equal(expectedCurrentOffset, pageResult.GetCurrentOffset())
	s.Require().Equal(expectedNextOffset, pageResult.GetNextOffset())
}

// validateTriggerWithDefaults validates a trigger against the suite's default values for backward compatibility
func (s *ObligationTriggersSuite) validateTriggerWithDefaults(trigger *policy.ObligationTrigger, shouldHaveCtx bool) {
	s.validateTrigger(trigger, s.obligationValue, s.attributeValue, s.action, shouldHaveCtx)
}

func (s *ObligationTriggersSuite) appendObligationValuesToClean(createdTriggers map[string]*policy.ObligationTrigger) {
	for _, trigger := range createdTriggers {
		s.obligationValueIDsToClean = append(s.obligationValueIDsToClean, trigger.GetObligationValue().GetId())
	}
}

func (s *ObligationTriggersSuite) createDifferentNamespaceWithTrigger(namespaceName string) *DifferentNamespaceEntities {
	// Create a different namespace
	differentNamespace, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: namespaceName,
	})
	s.Require().NoError(err)

	// Create obligation in different namespace
	differentObligation, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		Name:        "different-obligation-" + namespaceName,
		NamespaceId: differentNamespace.GetId(),
	})
	s.Require().NoError(err)

	// Create obligation value in different namespace
	differentObligationValue, err := s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationId: differentObligation.GetId(),
		Value:        "different-obligation-value-" + namespaceName,
	})
	s.Require().NoError(err)

	// Create attribute in different namespace
	differentAttribute, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		Name:        "different-attribute-" + namespaceName,
		NamespaceId: differentNamespace.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	})
	s.Require().NoError(err)

	// Create attribute value in different namespace
	differentAttributeValue, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, differentAttribute.GetId(), &attributes.CreateAttributeValueRequest{
		Value:       "different-value-" + namespaceName,
		AttributeId: differentAttribute.GetId(),
	})
	s.Require().NoError(err)

	// Create trigger in different namespace
	differentTrigger, err := s.db.PolicyClient.CreateObligationTrigger(s.ctx, &obligations.AddObligationTriggerRequest{
		ObligationValue: &common.IdFqnIdentifier{Id: differentObligationValue.GetId()},
		AttributeValue:  &common.IdFqnIdentifier{Id: differentAttributeValue.GetId()},
		Action:          &common.IdNameIdentifier{Id: s.action.GetId()},
		Context: &policy.RequestContext{
			Pep: &policy.PolicyEnforcementPoint{
				ClientId: clientID,
			},
		},
	})
	s.Require().NoError(err)

	return &DifferentNamespaceEntities{
		Namespace:       differentNamespace,
		Obligation:      differentObligation,
		ObligationValue: differentObligationValue,
		Attribute:       differentAttribute,
		AttributeValue:  differentAttributeValue,
		Trigger:         differentTrigger,
		CleanupNamespace: func() {
			_, err := s.db.PolicyClient.UnsafeDeleteNamespace(s.ctx, differentNamespace, differentNamespace.GetFqn())
			s.Require().NoError(err)
		},
		CleanupTrigger: func() {
			_, err := s.db.PolicyClient.DeleteObligationTrigger(s.ctx, &obligations.RemoveObligationTriggerRequest{
				Id: differentTrigger.GetId(),
			})
			s.Require().NoError(err)
		},
	}
}
