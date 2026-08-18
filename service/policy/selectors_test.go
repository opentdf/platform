package policy_test

import (
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/require"
)

func TestSearchTermValidation(t *testing.T) {
	v, err := protovalidate.New()
	require.NoError(t, err)

	require.NoError(t, v.Validate(&policy.Search{
		Term: strings.Repeat("a", 253),
	}))

	err = v.Validate(&policy.Search{
		Term: strings.Repeat("a", 254),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "string.max_len")
}
