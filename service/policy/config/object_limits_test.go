package config

import (
	"testing"

	"connectrpc.com/connect"
	serviceconfig "github.com/opentdf/platform/service/pkg/config"
	"github.com/stretchr/testify/require"
)

func Test_GetSharedPolicyConfig_ObjectLimitsDecode(t *testing.T) {
	t.Parallel()

	cfg, err := GetSharedPolicyConfig(serviceconfig.ServiceConfig{
		"object_limits": map[string]any{
			"attribute_definitions": 10,
			"resource_mappings":     25,
		},
	})
	require.NoError(t, err)
	require.EqualValues(t, 10, cfg.ObjectLimits.AttributeDefinitions)
	require.EqualValues(t, 25, cfg.ObjectLimits.ResourceMappings)
	require.Zero(t, cfg.ObjectLimits.ObligationTriggers)
}

func Test_ObjectLimits_ValidateNegativeLimit_Fails(t *testing.T) {
	t.Parallel()

	err := (ObjectLimits{AttributeDefinitions: -1}).Validate()
	require.EqualError(t, err, "policy object limit [attribute_definitions] must be zero or positive")
}

func Test_EnforceObjectLimit_AtLimit_Fails(t *testing.T) {
	t.Parallel()

	err := EnforceObjectLimit(ObjectTypeAttributeDefinitions, 10, 10, 1)
	require.ErrorIs(t, err, ErrObjectLimitExceeded)

	connectErr := ObjectLimitConnectError(err)
	require.Error(t, connectErr)
	require.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(connectErr))
	require.Contains(t, connectErr.Error(), "maximum 10")
}

func Test_EnforceObjectLimit_ZeroLimit_Succeeds(t *testing.T) {
	t.Parallel()

	require.NoError(t, EnforceObjectLimit(ObjectTypeAttributeDefinitions, 0, 100, 1))
}
