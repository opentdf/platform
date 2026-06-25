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

	assert.Equal(t, 20, config.RequestLimits.ResourceAttributeValuesFqnsMax)
	assert.Equal(t, 10, config.RequestLimits.EntityIdentifierEntityChainEntitiesMax)
	assert.Equal(t, 50, config.RequestLimits.DecisionRequestFulfillableObligationFqnsMax)
	assert.Equal(t, 1000, config.RequestLimits.GetDecisionMultiResourceResourcesMax)
	assert.Equal(t, 200, config.RequestLimits.GetDecisionBulkDecisionRequestsMax)
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
				config.RequestLimits.ResourceAttributeValuesFqnsMax = 0
			},
			expectedErr: "resource_attribute_values_fqns_max [0] must be greater than 0",
		},
		{
			name: "entity chain entities max must be positive",
			mutate: func(config *Config) {
				config.RequestLimits.EntityIdentifierEntityChainEntitiesMax = 0
			},
			expectedErr: "entity_identifier_entity_chain_entities_max [0] must be greater than 0",
		},
		{
			name: "fulfillable obligation fqns max must be positive",
			mutate: func(config *Config) {
				config.RequestLimits.DecisionRequestFulfillableObligationFqnsMax = 0
			},
			expectedErr: "decision_request_fulfillable_obligation_fqns_max [0] must be greater than 0",
		},
		{
			name: "multi resource request max must be positive",
			mutate: func(config *Config) {
				config.RequestLimits.GetDecisionMultiResourceResourcesMax = 0
			},
			expectedErr: "get_decision_multi_resource_resources_max [0] must be greater than 0",
		},
		{
			name: "bulk decision request max must be positive",
			mutate: func(config *Config) {
				config.RequestLimits.GetDecisionBulkDecisionRequestsMax = 0
			},
			expectedErr: "get_decision_bulk_decision_requests_max [0] must be greater than 0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := newConfigWithDefaults(t)
			tc.mutate(config)

			err := config.Validate()
			require.ErrorIs(t, err, ErrInvalidRequestLimitConfig)
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
