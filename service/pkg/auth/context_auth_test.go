package auth

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
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

func TestContextWithAuthnMetadata(t *testing.T) {
	mockClientID := "test-client-id"
	l := logger.CreateTestLogger()

	t.Run("should add access token and client id to metadata", func(t *testing.T) {
		ctx := ContextWithAuthNInfo(t.Context(), nil, nil, "raw-token-string")
		enrichedCtx := ContextWithAuthnMetadata(ctx, l, mockClientID)

		md, ok := metadata.FromIncomingContext(enrichedCtx)
		require.True(t, ok)

		accessToken := md.Get("access_token")
		require.Len(t, accessToken, 1)
		assert.Equal(t, "raw-token-string", accessToken[0])

		clientIDs := md.Get(clientIDKey)
		require.Len(t, clientIDs, 1)
		assert.Equal(t, mockClientID, clientIDs[0])
	})

	t.Run("should not set client id if empty", func(t *testing.T) {
		ctx := ContextWithAuthNInfo(t.Context(), nil, nil, "raw-token-string")
		enrichedCtx := ContextWithAuthnMetadata(ctx, l, "")

		md, ok := metadata.FromIncomingContext(enrichedCtx)
		require.True(t, ok)

		clientIDs := md.Get(clientIDKey)
		assert.Empty(t, clientIDs)
	})

	t.Run("should preserve existing metadata", func(t *testing.T) {
		originalMD := metadata.New(map[string]string{"original-key": "original-value"})
		ctx := metadata.NewIncomingContext(t.Context(), originalMD)
		ctx = ContextWithAuthNInfo(ctx, nil, nil, "raw-token-string")

		enrichedCtx := ContextWithAuthnMetadata(ctx, l, mockClientID)

		md, ok := metadata.FromIncomingContext(enrichedCtx)
		require.True(t, ok)

		originalValue := md.Get("original-key")
		require.Len(t, originalValue, 1)
		assert.Equal(t, "original-value", originalValue[0])

		clientIDs := md.Get(clientIDKey)
		require.Len(t, clientIDs, 1)
		assert.Equal(t, mockClientID, clientIDs[0])
	})
}

func TestGetClientIDFromContext(t *testing.T) {
	mockClientID := "test-client-id"

	t.Run("good - should retrieve client id from context", func(t *testing.T) {
		md := metadata.New(map[string]string{clientIDKey: mockClientID})
		ctx := metadata.NewIncomingContext(t.Context(), md)

		clientID, err := GetClientIDFromContext(ctx)
		require.NoError(t, err)
		assert.Equal(t, mockClientID, clientID)
	})

	t.Run("bad - should return error if client_id key is not present", func(t *testing.T) {
		md := metadata.New(map[string]string{"other-key": "other-value"})
		ctx := metadata.NewIncomingContext(t.Context(), md)

		_, err := GetClientIDFromContext(ctx)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMissingClientID)
	})

	t.Run("bad - should return error if no metadata in context", func(t *testing.T) {
		_, err := GetClientIDFromContext(t.Context())
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoMetadataFound)
	})

	t.Run("bad - should return error if more than one metadata client_id key in context", func(t *testing.T) {
		md := metadata.Pairs(clientIDKey, "id-1", clientIDKey, "id-2")
		ctx := metadata.NewIncomingContext(t.Context(), md)

		_, err := GetClientIDFromContext(ctx)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConflictClientID)
	})
}
