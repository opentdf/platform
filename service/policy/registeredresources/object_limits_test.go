package registeredresources

import (
	"context"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	"github.com/stretchr/testify/require"
)

type actionAdditionCounterStub struct {
	current   int64
	additions int64
}

func (s actionAdditionCounterStub) GetCountActionsWithNewAdditions(context.Context, string, string, []string) (int64, int64, error) {
	return s.current, s.additions, nil
}

func Test_EnforceActionAdditionLimit_NewActionsExceedLimit_Fails(t *testing.T) {
	t.Parallel()

	err := enforceActionAdditionLimit(
		t.Context(),
		actionAdditionCounterStub{current: 4, additions: 2},
		5,
		"namespace-id",
		"",
		[]string{"one", "two"},
	)
	require.ErrorIs(t, err, policyconfig.ErrObjectLimitExceeded)
}

func Test_EnforceActionAdditionLimit_ExistingActionsAtLimit_Succeeds(t *testing.T) {
	t.Parallel()

	err := enforceActionAdditionLimit(
		t.Context(),
		actionAdditionCounterStub{current: 5},
		5,
		"namespace-id",
		"",
		[]string{"existing"},
	)
	require.NoError(t, err)
}

func Test_RegisteredResourceActionNames_ActionIDsIgnored_Succeeds(t *testing.T) {
	t.Parallel()

	names := registeredResourceActionNames([]*registeredresources.ActionAttributeValue{
		{ActionIdentifier: &registeredresources.ActionAttributeValue_ActionId{ActionId: "action-id"}},
		{ActionIdentifier: &registeredresources.ActionAttributeValue_ActionName{ActionName: "new-action"}},
	})
	require.Equal(t, []string{"new-action"}, names)
}
