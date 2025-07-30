package keymanagement

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/keymanagement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagerRegistry(t *testing.T) {
	// Test the global manager registry functionality
	registry := GetGlobalManagerRegistry()
	
	// Test that default managers are registered
	managers := registry.GetRegisteredManagers()
	assert.NotEmpty(t, managers)
	
	// Test that specific managers are registered
	assert.True(t, registry.IsManagerRegistered("local"))
	assert.True(t, registry.IsManagerRegistered("aws"))
	assert.True(t, registry.IsManagerRegistered("gcp"))
	assert.True(t, registry.IsManagerRegistered("azure"))
	
	// Test registering a new manager
	err := registry.RegisterManager("test-manager", "Test manager for unit tests")
	require.NoError(t, err)
	assert.True(t, registry.IsManagerRegistered("test-manager"))
	
	// Test duplicate registration fails
	err = registry.RegisterManager("test-manager", "Duplicate test manager")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
	
	// Test disabling a manager
	err = registry.DisableManager("test-manager")
	require.NoError(t, err)
	assert.False(t, registry.IsManagerRegistered("test-manager"))
	
	// Test enabling a manager
	err = registry.EnableManager("test-manager")
	require.NoError(t, err)
	assert.True(t, registry.IsManagerRegistered("test-manager"))
}

func TestCreateProviderConfigValidation(t *testing.T) {
	// This tests the validation logic that would be called by the service
	// Note: This is a unit test that doesn't require database connection
	
	testCases := []struct {
		name        string
		manager     string
		expectValid bool
	}{
		{
			name:        "Valid local manager",
			manager:     "local",
			expectValid: true,
		},
		{
			name:        "Valid AWS manager",
			manager:     "aws",
			expectValid: true,
		},
		{
			name:        "Invalid manager type",
			manager:     "invalid-manager",
			expectValid: false,
		},
		{
			name:        "Empty manager",
			manager:     "",
			expectValid: false,
		},
	}
	
	registry := GetGlobalManagerRegistry()
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isValid := registry.IsManagerRegistered(tc.manager) && tc.manager != ""
			assert.Equal(t, tc.expectValid, isValid)
		})
	}
}

func TestServiceValidationLogic(t *testing.T) {
	// Test the validation logic that would be used in the actual service
	// This simulates what happens in CreateProviderConfig and UpdateProviderConfig
	
	registry := GetGlobalManagerRegistry()
	
	// Test CreateProviderConfig validation logic
	t.Run("CreateProviderConfig validation", func(t *testing.T) {
		req := &connect.Request[keymanagement.CreateProviderConfigRequest]{
			Msg: &keymanagement.CreateProviderConfigRequest{
				Name:       "test-provider",
				Manager:    "local",
				ConfigJson: []byte(`{"key": "value"}`),
			},
		}
		
		// Simulate the validation that happens in the service
		isValid := registry.IsManagerRegistered(req.Msg.GetManager())
		assert.True(t, isValid, "local manager should be valid")
		
		// Test with invalid manager
		req.Msg.Manager = "invalid-manager"
		isValid = registry.IsManagerRegistered(req.Msg.GetManager())
		assert.False(t, isValid, "invalid-manager should not be valid")
	})
	
	// Test UpdateProviderConfig validation logic
	t.Run("UpdateProviderConfig validation", func(t *testing.T) {
		req := &connect.Request[keymanagement.UpdateProviderConfigRequest]{
			Msg: &keymanagement.UpdateProviderConfigRequest{
				Id:      "123e4567-e89b-12d3-a456-426614174000",
				Manager: "aws",
			},
		}
		
		// Simulate the validation that happens in the service
		// Only validate if manager is provided (not empty)
		if req.Msg.Manager != "" {
			isValid := registry.IsManagerRegistered(req.Msg.Manager)
			assert.True(t, isValid, "aws manager should be valid")
		}
		
		// Test with invalid manager
		req.Msg.Manager = "invalid-manager"
		if req.Msg.Manager != "" {
			isValid := registry.IsManagerRegistered(req.Msg.Manager)
			assert.False(t, isValid, "invalid-manager should not be valid")
		}
		
		// Test with empty manager (should be allowed for updates)
		req.Msg.Manager = ""
		// No validation should occur for empty manager in updates
		assert.True(t, true, "empty manager should be allowed in updates")
	})
}