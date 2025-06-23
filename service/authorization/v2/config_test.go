package authorization

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ValidateConfig_ValidConfig(t *testing.T) {
	config := &Config{
		Cache: EntitlementPolicyCacheConfig{
			Enabled:         true,
			RefreshInterval: "30s",
		},
	}

	err := config.Validate()
	assert.NoError(t, err)
}

func Test_ValidateConfig_InvalidRefreshInterval(t *testing.T) {
	config := &Config{
		Cache: EntitlementPolicyCacheConfig{
			Enabled:         true,
			RefreshInterval: "5ms", // Too short
		},
	}

	err := config.Validate()
	assert.Error(t, err)

	config = &Config{
		Cache: EntitlementPolicyCacheConfig{
			Enabled:         true,
			RefreshInterval: "2h", // Too long
		},
	}

	err = config.Validate()
	assert.Error(t, err)
}

func Test_ValidateConfig_DisabledCache(t *testing.T) {
	config := &Config{
		Cache: EntitlementPolicyCacheConfig{
			Enabled:         false,
			RefreshInterval: "30s",
		},
	}

	err := config.Validate()
	assert.NoError(t, err)
}
