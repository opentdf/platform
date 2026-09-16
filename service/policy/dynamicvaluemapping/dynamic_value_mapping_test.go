package dynamicvaluemapping

import (
	"context"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
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

func Test_EnforceDynamicActionLimit_NewActionsExceedLimit_Fails(t *testing.T) {
	t.Parallel()

	err := enforceDynamicActionLimit(
		t.Context(),
		actionAdditionCounterStub{current: 4, additions: 2},
		5,
		"namespace-id",
		"",
		[]*policy.Action{{Name: "one"}, {Name: "two"}},
	)
	require.ErrorIs(t, err, policyconfig.ErrObjectLimitExceeded)
}
