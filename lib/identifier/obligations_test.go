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

func TestBuildOblFQN(t *testing.T) {
	nsFQN := "https://namespace.com"
	oblName := "drm"
	expectedFQN := nsFQN + "/obl/" + oblName
	fqn := BuildOblFQN(nsFQN, oblName)
	require.Equal(t, expectedFQN, fqn)
}

func TestBuildOblValFQN(t *testing.T) {
	nsFQN := "https://namespace.com"
	oblName := "drm"
	valName := "watermark"
	expectedFQN := nsFQN + "/obl/" + oblName + "/value/" + valName
	fqn := BuildOblValFQN(nsFQN, oblName, valName)
	require.Equal(t, expectedFQN, fqn)
}
