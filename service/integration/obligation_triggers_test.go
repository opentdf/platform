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
)

type ObligationTriggersSuite struct {
	suite.Suite
	ctx               context.Context //nolint:containedctx // context is used in the test suite
	db                fixtures.DBInterface
	f                 fixtures.Fixtures
	namespace         *policy.Namespace
	attribute         *policy.Attribute
	attributeValue    *policy.Value
	action            *policy.Action
	obligation        *policy.Obligation
	obligationValue   *policy.ObligationValue
	triggerIDsToClean []string
}

func (s *ObligationTriggersSuite) SetupSuite() {
	slog.Info("setting up db.Obligations test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_obligation_triggers"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()

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
		Name: obligationName,
		NamespaceIdentifier: &obligations.CreateObligationRequest_Id{
			Id: s.namespace.GetId(),
		},
	})
	s.Require().NoError(err)

	// Create an obligation value
	s.obligationValue, err = s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationIdentifier: &obligations.CreateObligationValueRequest_Id{
			Id: s.obligation.GetId(),
		},
		Value: obligationValue,
	})
	s.Require().NoError(err)
}

func (s *ObligationTriggersSuite) TearDownSuite() {
	var err error
	ctx := context.Background()

	_, err = s.db.PolicyClient.DeleteObligation(ctx, &obligations.DeleteObligationRequest{
		Identifier: &obligations.DeleteObligationRequest_Id{
			Id: s.obligation.GetId(),
		},
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
	s.triggerIDsToClean = nil
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
	})
	s.triggerIDsToClean = append(s.triggerIDsToClean, trigger.GetId())
	s.Require().NoError(err)
	s.validateTrigger(trigger)
	s.Require().Equal("test", trigger.GetMetadata().GetLabels()["source"])
}

func (s *ObligationTriggersSuite) Test_CreateObligationTrigger_WithNameFQN_Success() {
	trigger, err := s.db.PolicyClient.CreateObligationTrigger(s.ctx, &obligations.AddObligationTriggerRequest{
		ObligationValue: &common.IdFqnIdentifier{Fqn: s.obligation.GetNamespace().GetFqn() + "/obl/" + s.obligationValue.GetObligation().GetName() + "/value/" + s.obligationValue.GetValue()},
		AttributeValue:  &common.IdFqnIdentifier{Fqn: s.attributeValue.GetFqn()},
		Action:          &common.IdNameIdentifier{Name: s.action.GetName()},
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{"source": "test"},
		},
	})
	s.triggerIDsToClean = append(s.triggerIDsToClean, trigger.GetId())
	s.Require().NoError(err)
	s.validateTrigger(trigger)
	s.Require().Equal("test", trigger.GetMetadata().GetLabels()["source"])
}

func (s *ObligationTriggersSuite) Test_CreateObligationTrigger_ObligationValueNotFound_Fails() {
	randomID := uuid.NewString()
	trigger, err := s.db.PolicyClient.CreateObligationTrigger(s.ctx, &obligations.AddObligationTriggerRequest{
		ObligationValue: &common.IdFqnIdentifier{Id: randomID},
		AttributeValue:  &common.IdFqnIdentifier{Id: s.attributeValue.GetId()},
		Action:          &common.IdNameIdentifier{Id: s.action.GetId()},
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
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotNullViolation)
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
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotNullViolation)
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

func (s *ObligationTriggersSuite) createGenericTrigger() *policy.ObligationTrigger {
	trigger, err := s.db.PolicyClient.CreateObligationTrigger(s.ctx, &obligations.AddObligationTriggerRequest{
		ObligationValue: &common.IdFqnIdentifier{Id: s.obligationValue.GetId()},
		AttributeValue:  &common.IdFqnIdentifier{Id: s.attributeValue.GetId()},
		Action:          &common.IdNameIdentifier{Id: s.action.GetId()},
		Metadata:        &common.MetadataMutable{},
	})
	s.Require().NoError(err)
	s.validateTrigger(trigger)
	return trigger
}

func (s *ObligationTriggersSuite) validateTrigger(trigger *policy.ObligationTrigger) {
	s.Require().NotNil(trigger)
	s.Require().NotEmpty(trigger.GetId())
	s.Require().Equal(s.attributeValue.GetId(), trigger.GetAttributeValue().GetId())
	s.Require().Equal(s.attributeValue.GetFqn(), trigger.GetAttributeValue().GetFqn())
	s.Require().Equal(s.attributeValue.GetValue(), trigger.GetAttributeValue().GetValue())
	s.Require().Equal(s.obligationValue.GetId(), trigger.GetObligationValue().GetId())
	s.Require().Equal(s.obligationValue.GetValue(), trigger.GetObligationValue().GetValue())
	s.Require().Equal(s.obligationValue.GetObligation().GetId(), trigger.GetObligationValue().GetObligation().GetId())
	s.Require().Equal(s.obligationValue.GetObligation().GetName(), trigger.GetObligationValue().GetObligation().GetName())
	s.Require().Equal(s.obligationValue.GetObligation().GetNamespace().GetFqn(), trigger.GetObligationValue().GetObligation().GetNamespace().GetFqn())
	s.Require().Empty(trigger.GetObligationValue().GetTriggers())
	s.Require().Equal(s.action.GetId(), trigger.GetAction().GetId())
	s.Require().Equal(s.action.GetName(), trigger.GetAction().GetName())
}
