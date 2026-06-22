package policy

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair_Unsupported(t *testing.T) {
	_, err := generateKeyPair(policy.Algorithm_ALGORITHM_UNSPECIFIED)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported algorithm")
}
