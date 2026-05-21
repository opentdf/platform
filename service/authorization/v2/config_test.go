package authorization

import (
	"testing"

	"github.com/creasty/defaults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ValidateConfig_ValidConfig(t *testing.T) {
	config := newConfigWithDefaults(t)
	config.Cache.Enabled = true

	err := config.Validate()
	assert.NoError(t, err)
}

func Test_ValidateConfig_InvalidRefreshInterval(t *testing.T) {
	config := newConfigWithDefaults(t)
	config.Cache.Enabled = true
	config.Cache.RefreshInterval = "5ms" // Too short

	err := config.Validate()
	require.Error(t, err)

	config = newConfigWithDefaults(t)
	config.Cache.Enabled = true
	config.Cache.RefreshInterval = "2h" // Too long

	err = config.Validate()
	require.Error(t, err)
}

func Test_ValidateConfig_DisabledCache(t *testing.T) {
	config := newConfigWithDefaults(t)
	config.Cache.Enabled = false

	err := config.Validate()
	assert.NoError(t, err)
}

func Test_ValidateConfig_DefaultRequestLimits(t *testing.T) {
	config := newConfigWithDefaults(t)

	assert.Equal(t, 20, config.RequestLimits.ResourceAttributeValuesMax)
	assert.Equal(t, 10, config.RequestLimits.EntityChainEntitiesMax)
	assert.Equal(t, 50, config.RequestLimits.FulfillableObligationFqnsMax)
	assert.Equal(t, 1000, config.RequestLimits.MultiResourceRequestMax)
	assert.Equal(t, 200, config.RequestLimits.BulkDecisionRequestMax)
}

func Test_ValidateConfig_InvalidRequestLimits(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(*Config)
		expectedErr string
	}{
		{
			name: "resource attribute values max must be positive",
			mutate: func(config *Config) {
				config.RequestLimits.ResourceAttributeValuesMax = 0
			},
			expectedErr: "resource_attribute_values_max [0] must be greater than 0",
		},
		{
			name: "entity chain entities max must be positive",
			mutate: func(config *Config) {
				config.RequestLimits.EntityChainEntitiesMax = 0
			},
			expectedErr: "entity_chain_entities_max [0] must be greater than 0",
		},
		{
			name: "fulfillable obligation fqns max can be zero but not negative",
			mutate: func(config *Config) {
				config.RequestLimits.FulfillableObligationFqnsMax = -1
			},
			expectedErr: "fulfillable_obligation_fqns_max [-1] must be greater than or equal to 0",
		},
		{
			name: "multi resource request max must be positive",
			mutate: func(config *Config) {
				config.RequestLimits.MultiResourceRequestMax = 0
			},
			expectedErr: "multi_resource_request_max [0] must be greater than 0",
		},
		{
			name: "bulk decision request max must be positive",
			mutate: func(config *Config) {
				config.RequestLimits.BulkDecisionRequestMax = 0
			},
			expectedErr: "bulk_decision_request_max [0] must be greater than 0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := newConfigWithDefaults(t)
			tc.mutate(config)

			err := config.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

func newConfigWithDefaults(t *testing.T) *Config {
	t.Helper()

	config := &Config{}
	require.NoError(t, defaults.Set(config))
	return config
}
