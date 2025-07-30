package keymanagement

import (
	"testing"

	"github.com/opentdf/platform/service/trust"
	"github.com/stretchr/testify/assert"
)

func TestServiceManagerValidation(t *testing.T) {
	// Create a service with some mock trust key manager factories
	service := &Service{
		keyManagerFactories: []trust.NamedKeyManagerFactory{
			{Name: "local", Factory: nil},
			{Name: "premium-hsm", Factory: nil},
			{Name: "premium-vault", Factory: nil},
		},
	}

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
			name:        "Valid premium-hsm manager",
			manager:     "premium-hsm",
			expectValid: true,
		},
		{
			name:        "Valid premium-vault manager",
			manager:     "premium-vault",
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

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isValid := service.isManagerRegistered(tc.manager)
			assert.Equal(t, tc.expectValid, isValid)
		})
	}
}

func TestServiceWithNoKeyManagers(t *testing.T) {
	// Create a service with no key manager factories
	service := &Service{
		keyManagerFactories: []trust.NamedKeyManagerFactory{},
	}

	// All manager names should be invalid
	assert.False(t, service.isManagerRegistered("local"))
	assert.False(t, service.isManagerRegistered("any-manager"))
}

func TestServiceManagerValidationCaseSensitive(t *testing.T) {
	service := &Service{
		keyManagerFactories: []trust.NamedKeyManagerFactory{
			{Name: "local", Factory: nil},
			{Name: "Premium-HSM", Factory: nil},
		},
	}

	// Manager names should be case sensitive
	assert.True(t, service.isManagerRegistered("local"))
	assert.False(t, service.isManagerRegistered("Local"))
	assert.False(t, service.isManagerRegistered("LOCAL"))

	assert.True(t, service.isManagerRegistered("Premium-HSM"))
	assert.False(t, service.isManagerRegistered("premium-hsm"))
	assert.False(t, service.isManagerRegistered("PREMIUM-HSM"))
}
