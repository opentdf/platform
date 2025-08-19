package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	claimsv2 "github.com/opentdf/platform/service/entityresolution/claims/v2"
	"github.com/opentdf/platform/service/entityresolution/integration/internal"
	"github.com/opentdf/platform/service/logger"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

// TestClaimsEntityResolutionV2 runs Claims-specific tests focused on JWT and claims processing
// Note: Claims implementation doesn't perform typical entity resolution - it processes claims directly
func TestClaimsEntityResolutionV2(t *testing.T) {
	ctx := t.Context()
	adapter := NewClaimsTestAdapter()

	// Setup test data
	testDataSet := internal.NewContractTestDataSet()
	err := adapter.SetupTestData(ctx, testDataSet)
	if err != nil {
		t.Fatalf("Failed to setup test data: %v", err)
	}

	t.Cleanup(func() {
		if err := adapter.TeardownTestData(ctx); err != nil {
			t.Logf("Warning: Failed to cleanup test data: %v", err)
		}
	})

	// Create ERS service
	implementation, err := adapter.CreateERSService(ctx)
	if err != nil {
		t.Fatalf("Failed to create ERS service: %v", err)
	}

	t.Run("ResolveClaimsEntity", func(t *testing.T) {
		// Create a claims entity with structured data
		claimsData := map[string]interface{}{
			"sub":                "user123",
			"preferred_username": "testuser",
			"email":              "test@example.com",
			"groups":             "users,testers", // Use string instead of slice for structpb compatibility
		}

		structClaims, err := structpb.NewStruct(claimsData)
		if err != nil {
			t.Fatalf("Failed to create struct: %v", err)
		}

		anyClaims, err := anypb.New(structClaims)
		if err != nil {
			t.Fatalf("Failed to create any: %v", err)
		}

		claimsEntity := &entity.Entity{
			EntityType:  &entity.Entity_Claims{Claims: anyClaims},
			EphemeralId: "test-claims-entity",
			Category:    entity.Entity_CATEGORY_SUBJECT,
		}

		// Test ResolveEntities with claims entity
		resp, err := adapter.testResolveEntities(ctx, implementation, []*entity.Entity{claimsEntity})
		if err != nil {
			t.Fatalf("Failed to resolve claims entity: %v", err)
		}

		if len(resp.GetEntityRepresentations()) != 1 {
			t.Errorf("Expected 1 entity representation, got %d", len(resp.GetEntityRepresentations()))
		}

		repr := resp.GetEntityRepresentations()[0]
		if repr.GetOriginalId() != "test-claims-entity" {
			t.Errorf("Expected original ID 'test-claims-entity', got %s", repr.GetOriginalId())
		}

		if len(repr.GetAdditionalProps()) == 0 {
			t.Error("Expected additional properties, got none")
		} else {
			props := repr.GetAdditionalProps()[0].AsMap()
			if props["sub"] != "user123" {
				t.Errorf("Expected sub claim 'user123', got %v", props["sub"])
			}
			if props["preferred_username"] != "testuser" {
				t.Errorf("Expected preferred_username 'testuser', got %v", props["preferred_username"])
			}
		}
	})

	t.Run("ResolveNonClaimsEntities", func(t *testing.T) {
		// Claims implementation handles non-claims entities by converting them to JSON
		usernameEntity := internal.CreateTestEntityByUsername("alice")
		emailEntity := internal.CreateTestEntityByEmail("alice@opentdf.test")

		resp, err := adapter.testResolveEntities(ctx, implementation, []*entity.Entity{usernameEntity, emailEntity})
		if err != nil {
			t.Fatalf("Failed to resolve entities: %v", err)
		}

		if len(resp.GetEntityRepresentations()) != 2 {
			t.Errorf("Expected 2 entity representations, got %d", len(resp.GetEntityRepresentations()))
		}

		// Verify that entities were processed (converted to protojson format)
		for i, repr := range resp.GetEntityRepresentations() {
			if len(repr.GetAdditionalProps()) == 0 {
				t.Errorf("Entity %d: Expected additional properties, got none", i)
			} else {
				props := repr.GetAdditionalProps()[0].AsMap()
				// Should contain protojson representation of the entity
				if props["ephemeralId"] == nil {
					t.Errorf("Entity %d: Expected ephemeralId in protojson output", i)
				}
			}
		}
	})
}

// TestClaimsJWTProcessing tests Claims-specific JWT token processing functionality
func TestClaimsJWTProcessing(t *testing.T) {
	ctx := t.Context()
	adapter := NewClaimsTestAdapter()

	// Setup test data (which includes JWT keys)
	testDataSet := internal.NewContractTestDataSet()
	err := adapter.SetupTestData(ctx, testDataSet)
	if err != nil {
		t.Fatalf("Failed to setup test data: %v", err)
	}

	t.Cleanup(func() {
		if err := adapter.TeardownTestData(ctx); err != nil {
			t.Logf("Warning: Failed to cleanup test data: %v", err)
		}
	})

	// Create ERS service
	implementation, err := adapter.CreateERSService(ctx)
	if err != nil {
		t.Fatalf("Failed to create ERS service: %v", err)
	}

	t.Run("CreateEntityChainsFromValidTokens", func(t *testing.T) {
		// Create test JWT tokens
		tokens := []*entity.Token{
			{
				EphemeralId: "test-token-1",
				Jwt:         adapter.createTestJWT("test-client-1", "alice", "alice@opentdf.test", nil),
			},
			{
				EphemeralId: "test-token-2",
				Jwt: adapter.createTestJWT("test-client-2", "bob", "bob@opentdf.test", map[string]interface{}{
					"groups":     "users,admins", // Use string instead of slice for compatibility
					"department": "engineering",
				}),
			},
		}

		// Test CreateEntityChainsFromTokens
		resp, err := adapter.testCreateEntityChainsFromTokens(ctx, implementation, tokens)
		if err != nil {
			t.Fatalf("Failed to create entity chains: %v", err)
		}

		// Validate response
		if len(resp.GetEntityChains()) != 2 {
			t.Errorf("Expected 2 entity chains, got %d", len(resp.GetEntityChains()))
		}

		for i, chain := range resp.GetEntityChains() {
			expectedID := fmt.Sprintf("test-token-%d", i+1)
			if chain.GetEphemeralId() != expectedID {
				t.Errorf("Expected ephemeral ID %s, got %s", expectedID, chain.GetEphemeralId())
			}

			if len(chain.GetEntities()) == 0 {
				t.Errorf("Expected entities in chain, got none")
			}

			// Verify that we have a claims entity
			hasClaimsEntity := false
			for _, ent := range chain.GetEntities() {
				if _, ok := ent.GetEntityType().(*entity.Entity_Claims); ok {
					hasClaimsEntity = true
					break
				}
			}
			if !hasClaimsEntity {
				t.Errorf("Expected at least one claims entity in chain")
			}
		}
	})

	t.Run("HandleMalformedJWTTokens", func(t *testing.T) {
		malformedTokens := []*entity.Token{
			{
				EphemeralId: "malformed-token-1",
				Jwt:         "invalid.jwt.token",
			},
			{
				EphemeralId: "malformed-token-2",
				Jwt:         "",
			},
		}

		// This should handle malformed tokens gracefully
		_, err := adapter.testCreateEntityChainsFromTokens(ctx, implementation, malformedTokens)
		if err == nil {
			t.Error("Expected error for malformed JWT tokens, got none")
		}
	})

	t.Run("HandleExpiredJWTTokens", func(t *testing.T) {
		// Create expired JWT token
		expiredToken := adapter.createExpiredTestJWT("test-client-1", "alice", "alice@opentdf.test")

		tokens := []*entity.Token{
			{
				EphemeralId: "expired-token",
				Jwt:         expiredToken,
			},
		}

		// Claims implementation parses without validation, so this should still work
		resp, err := adapter.testCreateEntityChainsFromTokens(ctx, implementation, tokens)
		if err != nil {
			t.Fatalf("Unexpected error with expired token: %v", err)
		}

		if len(resp.GetEntityChains()) != 1 {
			t.Errorf("Expected 1 entity chain, got %d", len(resp.GetEntityChains()))
		}
	})

	t.Run("ResolveClaimsEntities", func(t *testing.T) {
		// Create a claims entity directly
		claimsData := map[string]interface{}{
			"sub":                "user123",
			"preferred_username": "testuser",
			"email":              "test@example.com",
			"groups":             "users,testers", // Use string instead of slice for structpb compatibility
		}

		structClaims, err := structpb.NewStruct(claimsData)
		if err != nil {
			t.Fatalf("Failed to create struct: %v", err)
		}

		anyClaims, err := anypb.New(structClaims)
		if err != nil {
			t.Fatalf("Failed to create any: %v", err)
		}

		claimsEntity := &entity.Entity{
			EntityType:  &entity.Entity_Claims{Claims: anyClaims},
			EphemeralId: "test-claims-entity",
			Category:    entity.Entity_CATEGORY_SUBJECT,
		}

		// Test ResolveEntities with claims entity
		resp, err := adapter.testResolveEntities(ctx, implementation, []*entity.Entity{claimsEntity})
		if err != nil {
			t.Fatalf("Failed to resolve claims entity: %v", err)
		}

		if len(resp.GetEntityRepresentations()) != 1 {
			t.Errorf("Expected 1 entity representation, got %d", len(resp.GetEntityRepresentations()))
		}

		repr := resp.GetEntityRepresentations()[0]
		if repr.GetOriginalId() != "test-claims-entity" {
			t.Errorf("Expected original ID 'test-claims-entity', got %s", repr.GetOriginalId())
		}

		if len(repr.GetAdditionalProps()) == 0 {
			t.Error("Expected additional properties, got none")
		} else {
			props := repr.GetAdditionalProps()[0].AsMap()
			if props["sub"] != "user123" {
				t.Errorf("Expected sub claim 'user123', got %v", props["sub"])
			}
		}
	})
}

// ClaimsTestAdapter implements ERSTestAdapter for Claims ERS testing
type ClaimsTestAdapter struct {
	service    *claimsv2.EntityResolutionServiceV2
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
}

// NewClaimsTestAdapter creates a new Claims test adapter
func NewClaimsTestAdapter() *ClaimsTestAdapter {
	return &ClaimsTestAdapter{
		keyID: "test-key-1",
	}
}

// GetScopeName returns the scope name for Claims ERS
func (a *ClaimsTestAdapter) GetScopeName() string {
	return "Claims"
}

// SetupTestData for Claims generates JWT signing keys and prepares test infrastructure
func (a *ClaimsTestAdapter) SetupTestData(_ context.Context, _ *internal.ContractTestDataSet) error {
	// Generate RSA key pair for JWT signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	a.privateKey = privateKey
	a.publicKey = &privateKey.PublicKey

	return nil
}

// CreateERSService creates and returns a configured Claims ERS service
func (a *ClaimsTestAdapter) CreateERSService(_ context.Context) (internal.ERSImplementation, error) {
	testLogger := logger.CreateTestLogger()
	service, _ := claimsv2.RegisterClaimsERS(nil, testLogger)

	// Set a no-op tracer for testing to prevent nil pointer dereference
	service.Tracer = noop.NewTracerProvider().Tracer("test-claims-v2")

	a.service = &service
	return &service, nil
}

// TeardownTestData cleans up Claims test data and resources
func (a *ClaimsTestAdapter) TeardownTestData(_ context.Context) error {
	// Clear keys
	a.privateKey = nil
	a.publicKey = nil
	return nil
}

// createTestJWT creates a signed JWT token for testing
func (a *ClaimsTestAdapter) createTestJWT(clientID, username, email string, additionalClaims map[string]interface{}) string {
	if a.privateKey == nil {
		// Fallback to unsigned token for basic testing
		return a.createUnsignedTestJWT(clientID, username, email, additionalClaims)
	}

	now := time.Now()

	// Create JWT token
	token := jwt.New()

	// Standard claims
	_ = token.Set(jwt.SubjectKey, username)
	_ = token.Set(jwt.AudienceKey, clientID)
	_ = token.Set(jwt.IssuedAtKey, now)
	_ = token.Set(jwt.ExpirationKey, now.Add(time.Hour))
	_ = token.Set(jwt.IssuerKey, "test-issuer")

	// Custom claims
	_ = token.Set("azp", clientID)
	_ = token.Set("preferred_username", username)
	_ = token.Set("email", email)

	// Additional custom claims
	if additionalClaims != nil {
		for key, value := range additionalClaims {
			_ = token.Set(key, value)
		}
	}

	// Create JWK key
	key, err := jwk.FromRaw(a.privateKey)
	if err != nil {
		return a.createUnsignedTestJWT(clientID, username, email, additionalClaims)
	}

	_ = key.Set(jwk.KeyIDKey, a.keyID)
	_ = key.Set(jwk.AlgorithmKey, jwa.RS256)

	// Sign the token
	tokenBytes, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		return a.createUnsignedTestJWT(clientID, username, email, additionalClaims)
	}

	return string(tokenBytes)
}

// createUnsignedTestJWT creates an unsigned JWT token for testing (fallback)
func (a *ClaimsTestAdapter) createUnsignedTestJWT(clientID, username, email string, additionalClaims map[string]interface{}) string {
	now := time.Now()

	claims := map[string]interface{}{
		"sub":                username,
		"aud":                clientID,
		"iat":                now.Unix(),
		"exp":                now.Add(time.Hour).Unix(),
		"iss":                "test-issuer",
		"azp":                clientID,
		"preferred_username": username,
		"email":              email,
	}

	// Add additional claims
	if additionalClaims != nil {
		for key, value := range additionalClaims {
			claims[key] = value
		}
	}

	// Create header and payload
	header := map[string]interface{}{
		"alg": "none",
		"typ": "JWT",
	}

	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(claims)

	// Base64 encode (without padding for JWT)
	headerB64 := encodeBase64URL(headerBytes)
	payloadB64 := encodeBase64URL(payloadBytes)

	return fmt.Sprintf("%s.%s.", headerB64, payloadB64)
}

// createExpiredTestJWT creates an expired JWT token for testing
func (a *ClaimsTestAdapter) createExpiredTestJWT(clientID, username, email string) string {
	pastTime := time.Now().Add(-2 * time.Hour)

	claims := map[string]interface{}{
		"sub":                username,
		"aud":                clientID,
		"iat":                pastTime.Unix(),
		"exp":                pastTime.Add(time.Hour).Unix(), // Expired 1 hour ago
		"iss":                "test-issuer",
		"azp":                clientID,
		"preferred_username": username,
		"email":              email,
	}

	header := map[string]interface{}{
		"alg": "none",
		"typ": "JWT",
	}

	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(claims)

	headerB64 := encodeBase64URL(headerBytes)
	payloadB64 := encodeBase64URL(payloadBytes)

	return fmt.Sprintf("%s.%s.", headerB64, payloadB64)
}

// testCreateEntityChainsFromTokens is a helper for testing token processing
func (a *ClaimsTestAdapter) testCreateEntityChainsFromTokens(ctx context.Context, implementation internal.ERSImplementation, tokens []*entity.Token) (*entityresolutionV2.CreateEntityChainsFromTokensResponse, error) {
	req := &entityresolutionV2.CreateEntityChainsFromTokensRequest{
		Tokens: tokens,
	}

	resp, err := implementation.CreateEntityChainsFromTokens(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}

	return resp.Msg, nil
}

// testResolveEntities is a helper for testing entity resolution
func (a *ClaimsTestAdapter) testResolveEntities(ctx context.Context, implementation internal.ERSImplementation, entities []*entity.Entity) (*entityresolutionV2.ResolveEntitiesResponse, error) {
	req := &entityresolutionV2.ResolveEntitiesRequest{
		Entities: entities,
	}

	resp, err := implementation.ResolveEntities(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}

	return resp.Msg, nil
}

// encodeBase64URL encodes bytes to base64 URL encoding without padding
func encodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
