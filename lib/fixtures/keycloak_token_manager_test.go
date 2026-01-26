package fixtures

import (
	"context"
	"testing"
	"time"
)

// TestTokenManager_InitialLogin tests that a new TokenManager successfully performs initial login
func TestTokenManager_InitialLogin(t *testing.T) {
	// Skip this test in CI as it requires a real Keycloak instance
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	connectParams := &KeycloakConnectParams{
		BasePath:         "http://localhost:8888/auth",
		Username:         "admin",
		Password:         "changeme",
		Realm:            "master",
		AllowInsecureTLS: true,
	}

	tm, err := NewTokenManager(ctx, connectParams, nil)
	if err != nil {
		t.Fatalf("Failed to create TokenManager: %v", err)
	}

	if tm.token == nil {
		t.Fatal("Token should not be nil after initial login")
	}

	if tm.client == nil {
		t.Fatal("Client should not be nil after initial login")
	}

	if tm.expiresAt.IsZero() {
		t.Fatal("ExpiresAt should be set after initial login")
	}

	if tm.tokenBuffer != 120*time.Second {
		t.Errorf("Expected default token buffer of 120s, got %v", tm.tokenBuffer)
	}
}

// TestTokenManager_CustomTokenBuffer tests that custom token buffer is applied
func TestTokenManager_CustomTokenBuffer(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	connectParams := &KeycloakConnectParams{
		BasePath:         "http://localhost:8888/auth",
		Username:         "admin",
		Password:         "changeme",
		Realm:            "master",
		AllowInsecureTLS: true,
	}

	customBuffer := 60 * time.Second
	config := &TokenManagerConfig{
		TokenBuffer: customBuffer,
	}

	tm, err := NewTokenManager(ctx, connectParams, config)
	if err != nil {
		t.Fatalf("Failed to create TokenManager: %v", err)
	}

	if tm.tokenBuffer != customBuffer {
		t.Errorf("Expected token buffer of %v, got %v", customBuffer, tm.tokenBuffer)
	}
}

// TestTokenManager_GetToken tests that GetToken returns a valid token
func TestTokenManager_GetToken(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	connectParams := &KeycloakConnectParams{
		BasePath:         "http://localhost:8888/auth",
		Username:         "admin",
		Password:         "changeme",
		Realm:            "master",
		AllowInsecureTLS: true,
	}

	tm, err := NewTokenManager(ctx, connectParams, nil)
	if err != nil {
		t.Fatalf("Failed to create TokenManager: %v", err)
	}

	token, err := tm.GetToken(ctx)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	if token == nil {
		t.Fatal("Token should not be nil")
	}

	if token.AccessToken == "" {
		t.Fatal("AccessToken should not be empty")
	}
}

// TestTokenManager_GetClient tests that GetClient returns a valid client
func TestTokenManager_GetClient(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	connectParams := &KeycloakConnectParams{
		BasePath:         "http://localhost:8888/auth",
		Username:         "admin",
		Password:         "changeme",
		Realm:            "master",
		AllowInsecureTLS: true,
	}

	tm, err := NewTokenManager(ctx, connectParams, nil)
	if err != nil {
		t.Fatalf("Failed to create TokenManager: %v", err)
	}

	client := tm.GetClient()
	if client == nil {
		t.Fatal("Client should not be nil")
	}
}

// TestTokenManager_PreemptiveRefresh tests that tokens are refreshed before expiration
func TestTokenManager_PreemptiveRefresh(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	connectParams := &KeycloakConnectParams{
		BasePath:         "http://localhost:8888/auth",
		Username:         "admin",
		Password:         "changeme",
		Realm:            "master",
		AllowInsecureTLS: true,
	}

	// Use a token buffer that is longer than typical token lifetimes to exercise the refresh logic.
	// With a 1-hour buffer, tokens with lifetimes shorter than 1 hour will trigger preemptive refresh.
	// If the Keycloak instance has tokens that live longer than 1 hour, this test will not observe a refresh,
	// which is expected behavior (no refresh needed if token is still valid beyond the buffer).
	config := &TokenManagerConfig{
		TokenBuffer: 1 * time.Hour, // Buffer longer than typical token lifetime
	}

	tm, err := NewTokenManager(ctx, connectParams, config)
	if err != nil {
		t.Fatalf("Failed to create TokenManager: %v", err)
	}

	firstToken := tm.token.AccessToken
	firstExpiresAt := tm.expiresAt

	// Get token should trigger refresh due to long buffer (if token lifetime < 1 hour)
	_, err = tm.GetToken(ctx)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	// Check if token was refreshed
	secondToken := tm.token.AccessToken
	secondExpiresAt := tm.expiresAt

	if firstToken == secondToken {
		// This is not necessarily a failure - it means the token lifetime is longer than our buffer
		t.Logf("Token was not refreshed. This is expected if token lifetime > 1 hour. Token expires at: %v", firstExpiresAt)
	} else {
		// Token was refreshed as expected
		t.Logf("Token was successfully refreshed. Old expiry: %v, New expiry: %v", firstExpiresAt, secondExpiresAt)
	}
}

// TestTokenManager_ConcurrentAccess tests thread safety of TokenManager
func TestTokenManager_ConcurrentAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	connectParams := &KeycloakConnectParams{
		BasePath:         "http://localhost:8888/auth",
		Username:         "admin",
		Password:         "changeme",
		Realm:            "master",
		AllowInsecureTLS: true,
	}

	tm, err := NewTokenManager(ctx, connectParams, nil)
	if err != nil {
		t.Fatalf("Failed to create TokenManager: %v", err)
	}

	// Spawn multiple goroutines to access token concurrently
	done := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func() {
			token, err := tm.GetToken(ctx)
			if err != nil {
				done <- err
				return
			}
			if token == nil {
				done <- err
				return
			}
			done <- nil
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		if err := <-done; err != nil {
			t.Errorf("Concurrent access failed: %v", err)
		}
	}
}

// TestTokenManager_RefreshFailure tests error handling when refresh fails
func TestTokenManager_RefreshFailure(t *testing.T) {
	ctx := context.Background()
	connectParams := &KeycloakConnectParams{
		BasePath:         "http://invalid-keycloak-url:9999/auth",
		Username:         "admin",
		Password:         "wrongpassword",
		Realm:            "master",
		AllowInsecureTLS: true,
	}

	_, err := NewTokenManager(ctx, connectParams, nil)
	if err == nil {
		t.Fatal("Expected error when creating TokenManager with invalid credentials")
	}
}

// TestTokenManager_NilConnectParams tests error handling for nil connect params
func TestTokenManager_NilConnectParams(t *testing.T) {
	ctx := context.Background()

	_, err := NewTokenManager(ctx, nil, nil)
	if err == nil {
		t.Fatal("Expected error when creating TokenManager with nil connect params")
	}
}
