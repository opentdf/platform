package kas

import (
	"testing"

	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/kas/access"
	"github.com/stretchr/testify/assert"
)

func TestInferLegacyKeys_empty(t *testing.T) {
	assert.Empty(t, inferLegacyKeys(nil))
}

func TestInferLegacyKeys_singles(t *testing.T) {
	one := []access.CurrentKeyFor{
		{
			Algorithm: security.AlgorithmRSA2048,
			KID:       "rsa",
		},
	}

	oneLegacy := []access.CurrentKeyFor{
		{
			Algorithm: security.AlgorithmRSA2048,
			KID:       "rsa",
			Legacy:    true,
		},
	}

	assert.Equal(t, oneLegacy, inferLegacyKeys(one))
	assert.False(t, one[0].Legacy)
	assert.True(t, oneLegacy[0].Legacy)
}

func TestInferLegacyKeys_Mixed(t *testing.T) {
	in := []access.CurrentKeyFor{
		{
			Algorithm: security.AlgorithmRSA2048,
			KID:       "a",
		},
		{
			Algorithm: security.AlgorithmECP256R1,
			KID:       "b",
		},
		{
			Algorithm: security.AlgorithmECP256R1,
			KID:       "c",
			Legacy:    true,
		},
		{
			Algorithm: security.AlgorithmECP256R1,
			KID:       "d",
		},
	}

	assert.Empty(t, inferLegacyKeys(in))
}
