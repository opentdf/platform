package internal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	// AnonymousUser represents an anonymous or unknown user
	AnonymousUser = "anonymous"

	// Token expiration time constants
	tokenExpirationSeconds = 3600 // 1 hour in seconds
)

// No global configuration needed - all adapter-specific config is managed locally in adapter test files

// CreateTestEntityByUsername creates a test entity for username-based resolution
func CreateTestEntityByUsername(username string) *entity.Entity {
	return &entity.Entity{
		EntityType:  &entity.Entity_UserName{UserName: username},
		EphemeralId: ("test-user-" + username),
		Category:    entity.Entity_CATEGORY_SUBJECT,
	}
}

// CreateTestEntityByEmail creates a test entity for email-based resolution
func CreateTestEntityByEmail(email string) *entity.Entity {
	return &entity.Entity{
		EntityType:  &entity.Entity_EmailAddress{EmailAddress: email},
		EphemeralId: ("test-email-" + email),
		Category:    entity.Entity_CATEGORY_SUBJECT,
	}
}

// CreateTestEntityByClientID creates a test entity for client ID-based resolution
func CreateTestEntityByClientID(clientID string) *entity.Entity {
	return &entity.Entity{
		EntityType:  &entity.Entity_ClientId{ClientId: clientID},
		EphemeralId: ("test-client-" + clientID),
		Category:    entity.Entity_CATEGORY_ENVIRONMENT,
	}
}

// CreateResolveEntitiesRequest creates a v2 ResolveEntitiesRequest for testing
func CreateResolveEntitiesRequest(entities ...*entity.Entity) *entityresolutionV2.ResolveEntitiesRequest {
	return &entityresolutionV2.ResolveEntitiesRequest{
		Entities: entities,
	}
}

// CreateTestJWT creates a proper JWT token for token-based testing using actual parameters
func CreateTestJWT(clientID, username, email string) string {
	return CreateTestJWTWithClaims(clientID, username, email, nil)
}

// CreateTestJWTWithClaims creates a JWT token with additional custom claims for multi-strategy testing
func CreateTestJWTWithClaims(clientID, username, email string, additionalClaims map[string]interface{}) string {
	// Create JWT header: {"alg":"HS256","typ":"JWT"}
	header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

	// Create dynamic payload using actual input parameters
	now := time.Now().Unix()
	payloadData := map[string]interface{}{
		"sub":                username,
		"email":              email,
		"preferred_username": username,
		"azp":                clientID,
		"aud":                []string{"test-audience"}, // Default audience
		"iss":                "test-issuer",             // Default issuer
		"iat":                now,
		"exp":                now + tokenExpirationSeconds, // 1 hour validity
		"_test_marker":       true,                         // Clear indicator this is a test JWT
	}

	// Handle empty parameters gracefully
	if clientID != "" {
		payloadData["client_id"] = clientID // Include client_id when provided
	}
	if username == "" {
		payloadData["sub"] = AnonymousUser
		payloadData["preferred_username"] = AnonymousUser
	}
	if email == "" {
		delete(payloadData, "email") // Remove email claim if not provided
	}

	// Merge additional claims (allows overriding defaults)
	for key, value := range additionalClaims {
		payloadData[key] = value
	}

	// Encode payload to JSON then base64
	payloadJSON, err := json.Marshal(payloadData)
	if err != nil {
		// Fallback to basic payload if marshaling fails
		payloadJSON = []byte(fmt.Sprintf(`{"sub":"%s","email":"%s","azp":"%s","iat":%d,"exp":%d}`,
			username, email, clientID, now, now+tokenExpirationSeconds))
	}

	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Mock signature for testing (not cryptographically valid)
	signature := "dGVzdHNpZ25hdHVyZQ"

	return header + "." + encodedPayload + "." + signature
}

// Multi-Strategy Routing Test Helpers

// CreateInternalJWT creates a JWT for internal audience routing (uses JWT claims provider)
func CreateInternalJWT(clientID, username, email string) string {
	return CreateTestJWTWithClaims(clientID, username, email, map[string]interface{}{
		"aud": []string{"internal", "opentdf-internal"},
		"iss": "internal-issuer",
	})
}

// CreateExternalJWT creates a JWT for external audience routing (uses database lookup)
func CreateExternalJWT(clientID, username, email string, userID string) string {
	claims := map[string]interface{}{
		"aud": []string{"external", "partner"},
		"iss": "partner-issuer",
	}
	if userID != "" {
		claims["user_id"] = userID
	}
	return CreateTestJWTWithClaims(clientID, username, email, claims)
}

// CreateCustomerJWT creates a JWT for customer audience routing
func CreateCustomerJWT(clientID, username, email string) string {
	return CreateTestJWTWithClaims(clientID, username, email, map[string]interface{}{
		"aud": []string{"customer"},
		"iss": "customer-portal",
	})
}

// CreateEnvironmentJWT creates a JWT with environment context for environment entity routing
func CreateEnvironmentJWT(clientID, clientIP, deviceID string) string {
	return CreateTestJWTWithClaims(clientID, "", "", map[string]interface{}{
		"aud":       []string{"device-context"},
		"iss":       "device-registry",
		"client_ip": clientIP,
		"device_id": deviceID,
	})
}

// CreateMultiStrategyTestSet creates a set of JWTs for testing different routing scenarios
func CreateMultiStrategyTestSet() map[string]string {
	return map[string]string{
		"internal-user":    CreateInternalJWT("web-client", "alice", "alice@company.com"),
		"external-partner": CreateExternalJWT("partner-app", "bob", "bob@partner.org", "ext_user_456"),
		"customer-portal":  CreateCustomerJWT("customer-client", "charlie", "charlie@customer.com"),
		"device-context":   CreateEnvironmentJWT("mobile-app", "192.168.1.100", "device-12345"),
		"fallback-email":   CreateTestJWT("unknown-client", "dave", "dave@unknown.com"), // No specific audience
	}
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
		return errors.New("expected additional_props to be populated, got empty")
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
func WaitForContainer(_ context.Context, checkFunc func() error, maxRetries int, delay time.Duration) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		err := checkFunc()
		if err == nil {
			return nil
		}
		lastErr = err
		slog.Debug("container not ready, retrying",
			slog.Int("attempt", i+1),
			slog.String("error", err.Error()))
		time.Sleep(delay)
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
