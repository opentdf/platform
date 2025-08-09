package internal

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"google.golang.org/protobuf/types/known/structpb"
)

// No global configuration needed - all adapter-specific config is managed locally in adapter test files

// CreateTestEntityByUsername creates a test entity for username-based resolution
func CreateTestEntityByUsername(username string) *entity.Entity {
	return &entity.Entity{
		EntityType:  &entity.Entity_UserName{UserName: username},
		EphemeralId: fmt.Sprintf("test-user-%s", username),
		Category:    entity.Entity_CATEGORY_SUBJECT,
	}
}

// CreateTestEntityByEmail creates a test entity for email-based resolution
func CreateTestEntityByEmail(email string) *entity.Entity {
	return &entity.Entity{
		EntityType:  &entity.Entity_EmailAddress{EmailAddress: email},
		EphemeralId: fmt.Sprintf("test-email-%s", email),
		Category:    entity.Entity_CATEGORY_SUBJECT,
	}
}

// CreateTestEntityByClientID creates a test entity for client ID-based resolution
func CreateTestEntityByClientID(clientID string) *entity.Entity {
	return &entity.Entity{
		EntityType:  &entity.Entity_ClientId{ClientId: clientID},
		EphemeralId: fmt.Sprintf("test-client-%s", clientID),
		Category:    entity.Entity_CATEGORY_ENVIRONMENT,
	}
}

// CreateResolveEntitiesRequest creates a v2 ResolveEntitiesRequest for testing
func CreateResolveEntitiesRequest(entities ...*entity.Entity) *entityresolutionV2.ResolveEntitiesRequest {
	return &entityresolutionV2.ResolveEntitiesRequest{
		Entities: entities,
	}
}

// CreateTestJWT creates a proper JWT token for token-based testing
func CreateTestJWT(clientID, username, email string) string {
	// Use the same approach as the working entity chain comparison test
	// Header: {"alg":"HS256","typ":"JWT"}
	header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	
	// Create a cleaner JWT payload that doesn't have conflicting claims
	// This payload contains: {"sub":"testuser","email":"test@example.com","preferred_username":"testuser","azp":"test-client","aud":["test-audience"],"iss":"test-issuer","iat":1600000000,"exp":1600009600}
	// Note: removed "client_id" to avoid conflicts with strategy-based mapping
	payload := "eyJzdWIiOiJ0ZXN0dXNlciIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6InRlc3R1c2VyIiwiYXpwIjoidGVzdC1jbGllbnQiLCJhdWQiOlsidGVzdC1hdWRpZW5jZSJdLCJpc3MiOiJ0ZXN0LWlzc3VlciIsImlhdCI6MTYwMDAwMDAwMCwiZXhwIjoxNjAwMDA5NjAwfQ"
	
	// Mock signature
	signature := "dGVzdHNpZ25hdHVyZQ"
	
	return header + "." + payload + "." + signature
}

// CreateTestToken creates a test entity.Token with the given ephemeral ID and JWT
func CreateTestToken(ephemeralID, clientID, username, email string) *entity.Token {
	return &entity.Token{
		EphemeralId: ephemeralID,
		Jwt:         CreateTestJWT(clientID, username, email),
	}
}

// ValidateEntityRepresentation validates that an EntityRepresentation contains expected data
func ValidateEntityRepresentation(repr *entityresolutionV2.EntityRepresentation, originalID string, expectedFields map[string]interface{}) error {
	if repr.GetOriginalId() != originalID {
		return fmt.Errorf("expected original_id %s, got %s", originalID, repr.GetOriginalId())
	}

	if len(repr.GetAdditionalProps()) == 0 {
		return fmt.Errorf("expected additional_props to be populated, got empty")
	}

	// Check first additional prop (assuming single result)
	props := repr.GetAdditionalProps()[0]
	for key, expectedValue := range expectedFields {
		actualValue := props.GetFields()[key]
		if actualValue == nil {
			return fmt.Errorf("expected field %s not found in additional_props", key)
		}

		// Convert protobuf Value to comparable type
		var actual interface{}
		switch v := actualValue.GetKind().(type) {
		case *structpb.Value_StringValue:
			actual = v.StringValue
		case *structpb.Value_NumberValue:
			actual = v.NumberValue
		case *structpb.Value_BoolValue:
			actual = v.BoolValue
		case *structpb.Value_NullValue:
			actual = nil
		default:
			actual = actualValue.String()
		}

		if actual != expectedValue {
			return fmt.Errorf("field %s: expected %v, got %v", key, expectedValue, actual)
		}
	}

	return nil
}

// WaitForContainer waits for a container to be ready with retries
func WaitForContainer(ctx context.Context, checkFunc func() error, maxRetries int, delay time.Duration) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if err := checkFunc(); err == nil {
			return nil
		} else {
			lastErr = err
			slog.Debug("container not ready, retrying", "attempt", i+1, "error", err.Error())
			time.Sleep(delay)
		}
	}
	return fmt.Errorf("container not ready after %d attempts: %w", maxRetries, lastErr)
}

// GetTestUser finds a test user by username
func GetTestUser(username string) *TestUser {
	for _, user := range TestUsers {
		if user.Username == username {
			return &user
		}
	}
	return nil
}

// GetTestClient finds a test client by client ID
func GetTestClient(clientID string) *TestClient {
	for _, client := range TestClients {
		if client.ClientID == clientID {
			return &client
		}
	}
	return nil
}

// GetTestGroup finds a test group by name
func GetTestGroup(name string) *TestGroup {
	for _, group := range TestGroups {
		if group.Name == name {
			return &group
		}
	}
	return nil
}

