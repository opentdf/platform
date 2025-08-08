package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCreateTestJWT(t *testing.T) {
	// Test with all parameters provided
	clientID := "test-client-123"
	username := "alice"
	email := "alice@company.com"
	
	jwt := CreateTestJWT(clientID, username, email)
	
	// JWT should have 3 parts separated by dots
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Errorf("JWT should have 3 parts, got %d", len(parts))
	}
	
	// Decode and validate payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Errorf("Failed to decode JWT payload: %v", err)
	}
	
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Errorf("Failed to unmarshal JWT payload: %v", err)
	}
	
	// Verify that actual parameters are used
	if payload["sub"] != username {
		t.Errorf("Expected sub=%s, got %v", username, payload["sub"])
	}
	
	if payload["email"] != email {
		t.Errorf("Expected email=%s, got %v", email, payload["email"])
	}
	
	if payload["azp"] != clientID {
		t.Errorf("Expected azp=%s, got %v", clientID, payload["azp"])
	}
	
	if payload["client_id"] != clientID {
		t.Errorf("Expected client_id=%s, got %v", clientID, payload["client_id"])
	}
	
	// Verify timestamps are recent (within last minute)
	iatFloat, ok := payload["iat"].(float64)
	if !ok {
		t.Errorf("iat should be a number, got %T", payload["iat"])
	} else {
		iat := int64(iatFloat)
		now := time.Now().Unix()
		if abs(now-iat) > 60 {
			t.Errorf("iat timestamp seems incorrect: iat=%d, now=%d, diff=%d", iat, now, abs(now-iat))
		}
	}
	
	// Verify test marker
	if testMarker, exists := payload["_test_marker"]; !exists || testMarker != true {
		t.Errorf("Expected _test_marker=true, got %v", testMarker)
	}
	
	t.Logf("Generated JWT payload: %s", string(payloadJSON))
}

func TestCreateTestJWTWithEmptyParams(t *testing.T) {
	// Test with empty parameters
	jwt := CreateTestJWT("", "", "")
	
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Errorf("JWT should have 3 parts, got %d", len(parts))
	}
	
	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Errorf("Failed to decode JWT payload: %v", err)
	}
	
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Errorf("Failed to unmarshal JWT payload: %v", err)
	}
	
	// Should handle empty username gracefully
	if payload["sub"] != "anonymous" {
		t.Errorf("Expected sub=anonymous for empty username, got %v", payload["sub"])
	}
	
	// Email should not be present if empty
	if _, exists := payload["email"]; exists {
		t.Errorf("Email should not be present when empty, got %v", payload["email"])
	}
	
	t.Logf("Generated JWT payload with empty params: %s", string(payloadJSON))
}

func TestCreateTestJWTDynamic(t *testing.T) {
	// Test that different parameters produce different JWTs
	jwt1 := CreateTestJWT("client1", "user1", "user1@test.com")
	jwt2 := CreateTestJWT("client2", "user2", "user2@test.com")
	
	if jwt1 == jwt2 {
		t.Error("Different parameters should produce different JWTs")
	}
	
	// Decode both payloads using helper function
	payload1, err := decodeJWTClaims(jwt1)
	if err != nil {
		t.Fatalf("Failed to decode JWT1: %v", err)
	}
	payload2, err := decodeJWTClaims(jwt2)
	if err != nil {
		t.Fatalf("Failed to decode JWT2: %v", err)
	}
	
	if payload1["sub"] == payload2["sub"] {
		t.Error("Different usernames should produce different sub claims")
	}
	
	if payload1["email"] == payload2["email"] {
		t.Error("Different emails should produce different email claims")
	}
	
	if payload1["client_id"] == payload2["client_id"] {
		t.Error("Different client IDs should produce different client_id claims")
	}
	
	// Verify both tokens have recent timestamps (not the old hardcoded 1600000000)
	now := time.Now().Unix()
	if iat1, ok := payload1["iat"].(float64); ok {
		if int64(iat1) < now-60 || int64(iat1) > now+60 {
			t.Errorf("JWT1 timestamp should be recent, got %v", iat1)
		}
	}
	if iat2, ok := payload2["iat"].(float64); ok {
		if int64(iat2) < now-60 || int64(iat2) > now+60 {
			t.Errorf("JWT2 timestamp should be recent, got %v", iat2)
		}
	}
	
	t.Logf("JWT 1 sub: %v, JWT 2 sub: %v", payload1["sub"], payload2["sub"])
	t.Logf("JWT 1 email: %v, JWT 2 email: %v", payload1["email"], payload2["email"])
}

func TestCreateTestJWTWithCustomClaims(t *testing.T) {
	// Test with custom audience and issuer
	customClaims := map[string]interface{}{
		"aud": []string{"custom-audience", "test-app"},
		"iss": "custom-issuer",
		"custom_field": "test-value",
	}
	
	token := CreateTestJWTWithClaims("test-client", "testuser", "test@example.com", customClaims)
	claims, err := decodeJWTClaims(token)
	if err != nil {
		t.Fatalf("Failed to decode JWT claims: %v", err)
	}
	
	// Verify custom claims override defaults
	aud := claims["aud"].([]interface{})
	foundCustom := false
	foundTestApp := false
	for _, a := range aud {
		if a == "custom-audience" {
			foundCustom = true
		}
		if a == "test-app" {
			foundTestApp = true
		}
	}
	if !foundCustom || !foundTestApp {
		t.Errorf("Expected audience to contain custom-audience and test-app, got %v", aud)
	}
	
	if claims["iss"] != "custom-issuer" {
		t.Errorf("Expected iss=custom-issuer, got %v", claims["iss"])
	}
	if claims["custom_field"] != "test-value" {
		t.Errorf("Expected custom_field=test-value, got %v", claims["custom_field"])
	}
	
	// Verify base claims are still present
	if claims["sub"] != "testuser" {
		t.Errorf("Expected sub=testuser, got %v", claims["sub"])
	}
	if claims["email"] != "test@example.com" {
		t.Errorf("Expected email=test@example.com, got %v", claims["email"])
	}
	if claims["azp"] != "test-client" {
		t.Errorf("Expected azp=test-client, got %v", claims["azp"])
	}
}

func TestMultiStrategyJWTHelpers(t *testing.T) {
	t.Run("InternalJWT", func(t *testing.T) {
		token := CreateInternalJWT("web-client", "alice", "alice@company.com")
		claims, err := decodeJWTClaims(token)
		if err != nil {
			t.Fatalf("Failed to decode internal JWT: %v", err)
		}
		
		aud := claims["aud"].([]interface{})
		hasInternal := false
		hasOpenTDFInternal := false
		for _, a := range aud {
			if a == "internal" {
				hasInternal = true
			}
			if a == "opentdf-internal" {
				hasOpenTDFInternal = true
			}
		}
		if !hasInternal || !hasOpenTDFInternal {
			t.Errorf("Expected audience to contain internal and opentdf-internal, got %v", aud)
		}
		if claims["iss"] != "internal-issuer" {
			t.Errorf("Expected iss=internal-issuer, got %v", claims["iss"])
		}
	})
	
	t.Run("ExternalJWT", func(t *testing.T) {
		token := CreateExternalJWT("partner-app", "bob", "bob@partner.org", "ext_user_456")
		claims, err := decodeJWTClaims(token)
		if err != nil {
			t.Fatalf("Failed to decode external JWT: %v", err)
		}
		
		aud := claims["aud"].([]interface{})
		hasExternal := false
		hasPartner := false
		for _, a := range aud {
			if a == "external" {
				hasExternal = true
			}
			if a == "partner" {
				hasPartner = true
			}
		}
		if !hasExternal || !hasPartner {
			t.Errorf("Expected audience to contain external and partner, got %v", aud)
		}
		if claims["iss"] != "partner-issuer" {
			t.Errorf("Expected iss=partner-issuer, got %v", claims["iss"])
		}
		if claims["user_id"] != "ext_user_456" {
			t.Errorf("Expected user_id=ext_user_456, got %v", claims["user_id"])
		}
	})
	
	t.Run("EnvironmentJWT", func(t *testing.T) {
		token := CreateEnvironmentJWT("mobile-app", "192.168.1.100", "device-12345")
		claims, err := decodeJWTClaims(token)
		if err != nil {
			t.Fatalf("Failed to decode environment JWT: %v", err)
		}
		
		aud := claims["aud"].([]interface{})
		hasDeviceContext := false
		for _, a := range aud {
			if a == "device-context" {
				hasDeviceContext = true
			}
		}
		if !hasDeviceContext {
			t.Errorf("Expected audience to contain device-context, got %v", aud)
		}
		if claims["iss"] != "device-registry" {
			t.Errorf("Expected iss=device-registry, got %v", claims["iss"])
		}
		if claims["client_ip"] != "192.168.1.100" {
			t.Errorf("Expected client_ip=192.168.1.100, got %v", claims["client_ip"])
		}
		if claims["device_id"] != "device-12345" {
			t.Errorf("Expected device_id=device-12345, got %v", claims["device_id"])
		}
	})
}

func TestMultiStrategyTestSet(t *testing.T) {
	testSet := CreateMultiStrategyTestSet()
	
	// Verify we have all expected scenarios
	expectedScenarios := []string{"internal-user", "external-partner", "customer-portal", "device-context", "fallback-email"}
	for _, scenario := range expectedScenarios {
		token, exists := testSet[scenario]
		if !exists {
			t.Errorf("Test set should include %s scenario", scenario)
			continue
		}
		if token == "" {
			t.Errorf("Token for %s should not be empty", scenario)
			continue
		}
		
		// Verify token is valid JWT format
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Errorf("JWT for %s should have 3 parts, got %d", scenario, len(parts))
		}
	}
	
	// Verify each token has different claims
	internalClaims, err := decodeJWTClaims(testSet["internal-user"])
	if err != nil {
		t.Fatalf("Failed to decode internal-user JWT: %v", err)
	}
	externalClaims, err := decodeJWTClaims(testSet["external-partner"])
	if err != nil {
		t.Fatalf("Failed to decode external-partner JWT: %v", err)
	}
	
	internalAud := internalClaims["aud"].([]interface{})
	externalAud := externalClaims["aud"].([]interface{})
	
	// Convert to strings for comparison
	internalAudStr := make([]string, len(internalAud))
	for i, v := range internalAud {
		internalAudStr[i] = v.(string)
	}
	externalAudStr := make([]string, len(externalAud))
	for i, v := range externalAud {
		externalAudStr[i] = v.(string)
	}
	
	if len(internalAudStr) == len(externalAudStr) {
		same := true
		for i, v := range internalAudStr {
			if i >= len(externalAudStr) || v != externalAudStr[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("Internal and external tokens should have different audiences")
		}
	}
}

// decodeJWTClaims is a helper function to decode JWT claims for testing
func decodeJWTClaims(jwt string) (map[string]interface{}, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}
	
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %v", err)
	}
	
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT payload: %v", err)
	}
	
	return claims, nil
}

// Helper function for absolute value
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}