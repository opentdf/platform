package identifier

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBreakOblFQN(t *testing.T) {
	validFQN := "https://namespace.com/obl/drm"
	nsFQN, oblName := BreakOblFQN(validFQN)
	require.Equal(t, "https://namespace.com", nsFQN)
	require.Equal(t, "drm", oblName)

	invalidFQN := ""
	nsFQN, oblName = BreakOblFQN(invalidFQN)
	require.Equal(t, "", nsFQN)
	require.Equal(t, "", oblName)
}

func TestBreakOblValFQN(t *testing.T) {
	validFQN := "https://namespace.com/obl/drm/value/watermark"
	nsFQN, oblName, valName := BreakOblValFQN(validFQN)
	require.Equal(t, "https://namespace.com", nsFQN)
	require.Equal(t, "drm", oblName)
	require.Equal(t, "watermark", valName)

	invalidFQN := ""
	nsFQN, oblName, valName = BreakOblValFQN(invalidFQN)
	require.Equal(t, "", nsFQN)
	require.Equal(t, "", oblName)
	require.Equal(t, "", valName)
}
