package wellknownconfiguration

import (
	"testing"

	"connectrpc.com/connect"
	wellknown "github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Simulate the keymanagement registeredManagers struct
type registeredManagers struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func TestWellKnownWithKeyManagementData(t *testing.T) {
	// Clear configuration
	wellKnownConfiguration = make(map[string]any)
	logger := logger.CreateTestLogger()
	service := WellKnownService{logger: logger}

	t.Run("Empty key managers list", func(t *testing.T) {
		// This simulates what keymanagement service registers when no factories are provided
		emptyManagers := []registeredManagers{}
		wellKnownConfiguration["key_managers"] = emptyManagers

		req := connect.NewRequest(&wellknown.GetWellKnownConfigurationRequest{})
		resp, err := service.GetWellKnownConfiguration(t.Context(), req)

		require.NoError(t, err)
		assert.NotNil(t, resp.Msg.GetConfiguration())
		assert.Contains(t, resp.Msg.GetConfiguration().GetFields(), "key_managers")

		// Should be an empty array, not cause serialization errors
		keyManagersField := resp.Msg.GetConfiguration().GetFields()["key_managers"]
		assert.NotNil(t, keyManagersField)
	})

	t.Run("With basic key manager", func(t *testing.T) {
		// This simulates what would happen if basic manager was registered
		managersWithBasic := []registeredManagers{
			{
				Name:        "opentdf.io/basic",
				Description: "Key manager: opentdf.io/basic",
			},
		}
		wellKnownConfiguration["key_managers"] = managersWithBasic

		req := connect.NewRequest(&wellknown.GetWellKnownConfigurationRequest{})
		resp, err := service.GetWellKnownConfiguration(t.Context(), req)

		require.NoError(t, err)
		assert.NotNil(t, resp.Msg.GetConfiguration())
		assert.Contains(t, resp.Msg.GetConfiguration().GetFields(), "key_managers")

		// Should serialize the struct properly to a list with one item
		keyManagersField := resp.Msg.GetConfiguration().GetFields()["key_managers"]
		assert.NotNil(t, keyManagersField)
	})

	t.Run("With multiple key managers", func(t *testing.T) {
		// This simulates what would happen with multiple registered managers
		multipleManagers := []registeredManagers{
			{
				Name:        "opentdf.io/basic",
				Description: "Key manager: opentdf.io/basic",
			},
			{
				Name:        "aws-hsm",
				Description: "Key manager: aws-hsm",
			},
			{
				Name:        "azure-vault",
				Description: "Key manager: azure-vault",
			},
		}
		wellKnownConfiguration["key_managers"] = multipleManagers

		req := connect.NewRequest(&wellknown.GetWellKnownConfigurationRequest{})
		resp, err := service.GetWellKnownConfiguration(t.Context(), req)

		require.NoError(t, err)
		assert.NotNil(t, resp.Msg.GetConfiguration())
		assert.Contains(t, resp.Msg.GetConfiguration().GetFields(), "key_managers")

		// Should serialize the struct array properly
		keyManagersField := resp.Msg.GetConfiguration().GetFields()["key_managers"]
		assert.NotNil(t, keyManagersField)
	})

	t.Run("Mixed configuration with key managers", func(t *testing.T) {
		// This simulates a full wellknown config with various services
		wellKnownConfiguration = map[string]any{
			"base_key": map[string]string{},
			"health": map[string]string{
				"endpoint": "/healthz",
			},
			"key_managers": []registeredManagers{
				{
					Name:        "opentdf.io/basic",
					Description: "Key manager: opentdf.io/basic",
				},
			},
			"platform_issuer": "http://localhost:8888/auth/realms/opentdf",
		}

		req := connect.NewRequest(&wellknown.GetWellKnownConfigurationRequest{})
		resp, err := service.GetWellKnownConfiguration(t.Context(), req)

		require.NoError(t, err)
		assert.NotNil(t, resp.Msg.GetConfiguration())

		// All sections should be present
		assert.Contains(t, resp.Msg.GetConfiguration().GetFields(), "base_key")
		assert.Contains(t, resp.Msg.GetConfiguration().GetFields(), "health")
		assert.Contains(t, resp.Msg.GetConfiguration().GetFields(), "key_managers")
		assert.Contains(t, resp.Msg.GetConfiguration().GetFields(), "platform_issuer")

		// The struct should have been converted properly without causing serialization errors
		keyManagersField := resp.Msg.GetConfiguration().GetFields()["key_managers"]
		assert.NotNil(t, keyManagersField)
	})
}

func TestRegressionPreviousError(t *testing.T) {
	// This test ensures the previous "proto: invalid type: []keymanagement.registeredManagers" error doesn't happen
	wellKnownConfiguration = make(map[string]any)
	logger := logger.CreateTestLogger()
	service := WellKnownService{logger: logger}

	// Simulate exact scenario that was failing before
	problemData := []registeredManagers{
		{Name: "opentdf.io/basic", Description: "Key manager: opentdf.io/basic"},
	}
	wellKnownConfiguration["key_managers"] = problemData

	req := connect.NewRequest(&wellknown.GetWellKnownConfigurationRequest{})

	// This should NOT panic or error - it was failing before with structpb serialization
	resp, err := service.GetWellKnownConfiguration(t.Context(), req)

	require.NoError(t, err, "Should not get serialization error anymore")
	assert.NotNil(t, resp.Msg.GetConfiguration())
	assert.Contains(t, resp.Msg.GetConfiguration().GetFields(), "key_managers")
}
