package auth

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
)

func TestContextWithAuthNInfo(t *testing.T) {
	// Create mock JWK, JWT, and raw token
	mockJWK, _ := jwk.FromRaw([]byte("mockKey"))
	mockJWT, _ := jwt.NewBuilder().Build()
	rawToken := "mockRawToken"

	// Initialize context
	ctx := t.Context()
	newCtx := ContextWithAuthNInfo(ctx, mockJWK, mockJWT, rawToken)

	// Assert that the context contains the correct values
	value := newCtx.Value(authnContextKey)
	testAuthContext, ok := value.(*authContext)
	assert.True(t, ok)
	assert.NotNil(t, testAuthContext)
	assert.Equal(t, mockJWK, testAuthContext.key, "JWK should match")
	assert.Equal(t, mockJWT, testAuthContext.accessToken, "JWT should match")
	assert.Equal(t, rawToken, testAuthContext.rawToken, "Raw token should match")
}

func TestGetJWKFromContext(t *testing.T) {
	// Create mock context with JWK
	mockJWK, _ := jwk.FromRaw([]byte("mockKey"))
	ctx := ContextWithAuthNInfo(t.Context(), mockJWK, nil, "")

	// Retrieve the JWK and assert
	retrievedJWK := GetJWKFromContext(ctx, logger.CreateTestLogger())
	assert.NotNil(t, retrievedJWK, "JWK should not be nil")
	assert.Equal(t, mockJWK, retrievedJWK, "Retrieved JWK should match the mock JWK")
}

func TestGetAccessTokenFromContext(t *testing.T) {
	// Create mock context with JWT
	mockJWT, _ := jwt.NewBuilder().Build()
	ctx := ContextWithAuthNInfo(t.Context(), nil, mockJWT, "")

	// Retrieve the JWT and assert
	retrievedJWT := GetAccessTokenFromContext(ctx, logger.CreateTestLogger())
	assert.NotNil(t, retrievedJWT, "Access token should not be nil")
	assert.Equal(t, mockJWT, retrievedJWT, "Retrieved JWT should match the mock JWT")
}

func TestGetRawAccessTokenFromContext(t *testing.T) {
	// Create mock context with raw token
	rawToken := "mockRawToken"
	ctx := ContextWithAuthNInfo(t.Context(), nil, nil, rawToken)

	// Retrieve the raw token and assert
	retrievedRawToken := GetRawAccessTokenFromContext(ctx, logger.CreateTestLogger())
	assert.Equal(t, rawToken, retrievedRawToken, "Retrieved raw token should match the mock raw token")
}

func TestGetContextDetailsInvalidType(t *testing.T) {
	// Create a context with an invalid type
	ctx := context.WithValue(t.Context(), authnContextKey, "invalidType")

	// Assert that GetJWKFromContext handles the invalid type correctly
	retrievedJWK := GetJWKFromContext(ctx, logger.CreateTestLogger())
	assert.Nil(t, retrievedJWK, "JWK should be nil when context value is invalid")
}
