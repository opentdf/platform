package integration

import (
	"context"

	keycloakv2 "github.com/opentdf/platform/service/entityresolution/keycloak/v2"
	"github.com/opentdf/platform/service/entityresolution/integration/internal"
	"github.com/opentdf/platform/service/logger"
	"go.opentelemetry.io/otel/trace/noop"
)

// CreateKeycloakV2Service creates a configured Keycloak v2 ERS service for testing
func CreateKeycloakV2Service() (*keycloakv2.EntityResolutionServiceV2, error) {
	keycloakConfig := map[string]interface{}{
		"url":           "http://localhost:8080", // Mock Keycloak URL for testing
		"realm":         "opentdf",
		"client_id":     "test-client",
		"client_secret": "test-secret",
		"inferid": map[string]interface{}{
			"from": map[string]interface{}{
				"clientid": true,
				"email":    true,
				"username": true,
			},
		},
	}

	testLogger := logger.CreateTestLogger()
	service, _ := keycloakv2.RegisterKeycloakERS(keycloakConfig, testLogger)
	
	// Set a no-op tracer for testing to prevent nil pointer dereference
	service.Tracer = noop.NewTracerProvider().Tracer("test-keycloak-v2")
	
	return service, nil
}

// KeycloakTestAdapter implements ERSTestAdapter for Keycloak ERS testing
type KeycloakTestAdapter struct {
	service *keycloakv2.EntityResolutionServiceV2
}

// NewKeycloakTestAdapter creates a new Keycloak test adapter
func NewKeycloakTestAdapter() *KeycloakTestAdapter {
	return &KeycloakTestAdapter{}
}

// GetScopeName returns the scope name for Keycloak ERS
func (a *KeycloakTestAdapter) GetScopeName() string {
	return "Keycloak"
}

// SetupTestData for Keycloak would inject test data into Keycloak instance
func (a *KeycloakTestAdapter) SetupTestData(ctx context.Context, testDataSet *internal.ContractTestDataSet) error {
	// Note: In a real implementation, you would inject contract test data into Keycloak
	// This would require using Keycloak's admin API to create users and clients
	// For now, this is just a placeholder showing the structure
	return nil
}

// CreateERSService creates and returns a configured Keycloak ERS service
func (a *KeycloakTestAdapter) CreateERSService(ctx context.Context) (internal.ERSImplementation, error) {
	service, err := CreateKeycloakV2Service()
	if err != nil {
		return nil, err
	}
	a.service = service
	return service, nil
}

// TeardownTestData cleans up Keycloak test data and resources
func (a *KeycloakTestAdapter) TeardownTestData(ctx context.Context) error {
	// Note: In a real implementation, you would clean up test data from Keycloak
	// For now, this is a no-op
	return nil
}