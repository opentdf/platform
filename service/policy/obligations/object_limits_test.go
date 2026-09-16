package obligations

import (
	"context"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	"github.com/stretchr/testify/require"
)

type objectLimitCounterStub struct {
	obligationDefinitions int64
	obligationTriggers    int64
	actionsCurrent        int64
	actionAdditions       int64
}

func (s objectLimitCounterStub) GetCountObligationDefinitions(context.Context, string, string) (int64, error) {
	return s.obligationDefinitions, nil
}

func (objectLimitCounterStub) GetCountObligationValues(context.Context, string, string) (int64, error) {
	return 0, nil
}

func (s objectLimitCounterStub) GetCountObligationTriggersForAttributeValue(context.Context, *common.IdFqnIdentifier, string) (int64, error) {
	return s.obligationTriggers, nil
}

func (s objectLimitCounterStub) GetCountActionsWithNewAdditions(context.Context, string, string, []string) (int64, int64, error) {
	return s.actionsCurrent, s.actionAdditions, nil
}

func (objectLimitCounterStub) GetAttributeValueNamespaceID(context.Context, *common.IdFqnIdentifier) (string, error) {
	return "namespace-id", nil
}

func Test_EnforceCreateObligationLimits_ObligationDefinitionAtLimit_Fails(t *testing.T) {
	t.Parallel()

	service := &Service{config: &policyconfig.Config{MaxObjectCounts: policyconfig.MaxObjectCounts{ObligationDefinitionsPerNamespace: 10}}}
	err := service.enforceCreateObligationLimits(t.Context(), objectLimitCounterStub{obligationDefinitions: 10}, &obligations.CreateObligationRequest{})
	require.ErrorIs(t, err, policyconfig.ErrObjectLimitExceeded)
}

func Test_EnforceCreateObligationValueLimits_ImplicitActionsAcrossValuesExceedLimit_Fails(t *testing.T) {
	t.Parallel()

	service := &Service{config: &policyconfig.Config{MaxObjectCounts: policyconfig.MaxObjectCounts{ActionsPerNamespace: 5}}}
	err := service.enforceCreateObligationValueLimits(t.Context(), objectLimitCounterStub{actionsCurrent: 4, actionAdditions: 2}, &obligations.CreateObligationValueRequest{
		Triggers: []*obligations.ValueTriggerRequest{
			{Action: &common.IdNameIdentifier{Name: "one"}, AttributeValue: &common.IdFqnIdentifier{Id: "value-one"}},
			{Action: &common.IdNameIdentifier{Name: "two"}, AttributeValue: &common.IdFqnIdentifier{Id: "value-two"}},
		},
	})
	require.ErrorIs(t, err, policyconfig.ErrObjectLimitExceeded)
}

func Test_EnforceCreateObligationValueLimits_TriggersPerAttributeValueExceedLimit_Fails(t *testing.T) {
	t.Parallel()

	service := &Service{config: &policyconfig.Config{MaxObjectCounts: policyconfig.MaxObjectCounts{ObligationTriggersPerAttributeValue: 10}}}
	attributeValue := &common.IdFqnIdentifier{Id: "attribute-value-id"}
	err := service.enforceCreateObligationValueLimits(t.Context(), objectLimitCounterStub{obligationTriggers: 9}, &obligations.CreateObligationValueRequest{
		Triggers: []*obligations.ValueTriggerRequest{
			{AttributeValue: attributeValue},
			{AttributeValue: attributeValue},
		},
	})
	require.ErrorIs(t, err, policyconfig.ErrObjectLimitExceeded)
}
