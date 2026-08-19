package obligations

import (
	"context"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
	"github.com/stretchr/testify/require"
)

type objectLimitCounterStub struct {
	obligationDefinitions int64
}

func (s objectLimitCounterStub) CountObligationDefinitions(context.Context, string, string) (int64, error) {
	return s.obligationDefinitions, nil
}

func (objectLimitCounterStub) CountObligationValues(context.Context, string, string) (int64, error) {
	return 0, nil
}

func (objectLimitCounterStub) CountObligationTriggersForAttributeValues(context.Context, []*common.IdFqnIdentifier) ([]policydb.PolicyObjectCount, error) {
	return nil, nil
}

func Test_EnforceCreateObligationLimits_ObligationDefinitionAtLimit_Fails(t *testing.T) {
	t.Parallel()

	service := &Service{config: &policyconfig.Config{ObjectLimits: policyconfig.ObjectLimits{ObligationDefinitions: 10}}}
	err := service.enforceCreateObligationLimits(t.Context(), objectLimitCounterStub{obligationDefinitions: 10}, &obligations.CreateObligationRequest{})
	require.ErrorIs(t, err, policyconfig.ErrObjectLimitExceeded)
}
