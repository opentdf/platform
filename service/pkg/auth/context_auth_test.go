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

func TestEnrichIncomingContextMetadataWithAuthn(t *testing.T) {
	mockClientID := "test-client-id"
	l := logger.CreateTestLogger()

	t.Run("should add access token and client id to metadata", func(t *testing.T) {
		ctx := ContextWithAuthNInfo(t.Context(), nil, nil, "raw-token-string")
		enrichedCtx := EnrichIncomingContextMetadataWithAuthn(ctx, l, mockClientID)

		md, ok := metadata.FromIncomingContext(enrichedCtx)
		require.True(t, ok)

		accessToken := md.Get(AccessTokenKey)
		require.Len(t, accessToken, 1)
		assert.Equal(t, "raw-token-string", accessToken[0])

		clientIDs := md.Get(ClientIDKey)
		require.Len(t, clientIDs, 1)
		assert.Equal(t, mockClientID, clientIDs[0])
	})

	t.Run("should not set client id if empty", func(t *testing.T) {
		ctx := ContextWithAuthNInfo(t.Context(), nil, nil, "raw-token-string")
		enrichedCtx := EnrichIncomingContextMetadataWithAuthn(ctx, l, "")

		md, ok := metadata.FromIncomingContext(enrichedCtx)
		require.True(t, ok)

		clientIDs := md.Get(ClientIDKey)
		assert.Empty(t, clientIDs)
	})

	t.Run("should preserve existing metadata", func(t *testing.T) {
		originalMD := metadata.New(map[string]string{"original-key": "original-value"})
		ctx := metadata.NewIncomingContext(t.Context(), originalMD)
		ctx = ContextWithAuthNInfo(ctx, nil, nil, "raw-token-string")
		enrichedCtx := EnrichIncomingContextMetadataWithAuthn(ctx, l, mockClientID)

		md, ok := metadata.FromIncomingContext(enrichedCtx)
		require.True(t, ok)

		originalValue := md.Get("original-key")
		require.Len(t, originalValue, 1)
		assert.Equal(t, "original-value", originalValue[0])

		clientIDs := md.Get(ClientIDKey)
		require.Len(t, clientIDs, 1)
		assert.Equal(t, mockClientID, clientIDs[0])
	})
}

func TestGetClientIDFromContext(t *testing.T) {
	mockClientID := "test-client-id"

	t.Run("good - should retrieve client id from incoming context", func(t *testing.T) {
		md := metadata.New(map[string]string{ClientIDKey: mockClientID})
		ctx := metadata.NewIncomingContext(t.Context(), md)

		incoming := true
		clientID, err := GetClientIDFromContext(ctx, incoming)
		require.NoError(t, err)
		assert.Equal(t, mockClientID, clientID)
	})

	t.Run("bad - should return error if clientID key is not present in incoming context", func(t *testing.T) {
		md := metadata.New(map[string]string{"other-key": "other-value"})
		ctx := metadata.NewIncomingContext(t.Context(), md)

		incoming := true
		_, err := GetClientIDFromContext(ctx, incoming)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMissingClientID)
	})

	t.Run("bad - should return error if no metadata in incoming context", func(t *testing.T) {
		incoming := true
		_, err := GetClientIDFromContext(t.Context(), incoming)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoMetadataFound)
	})

	t.Run("bad - should return error if more than one metadata clientID key in incoming context", func(t *testing.T) {
		md := metadata.Pairs(ClientIDKey, "id-1", ClientIDKey, "id-2")
		ctx := metadata.NewIncomingContext(t.Context(), md)
		incoming := true

		_, err := GetClientIDFromContext(ctx, incoming)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConflictClientID)
	})
	t.Run("good - should retrieve client id from outgoing context", func(t *testing.T) {
		md := metadata.New(map[string]string{ClientIDKey: mockClientID})
		ctx := metadata.NewOutgoingContext(t.Context(), md)

		incoming := false
		clientID, err := GetClientIDFromContext(ctx, incoming)
		require.NoError(t, err)
		assert.Equal(t, mockClientID, clientID)
	})

	t.Run("bad - should return error if clientID key is not present in outgoing context", func(t *testing.T) {
		md := metadata.New(map[string]string{"other-key": "other-value"})
		ctx := metadata.NewOutgoingContext(t.Context(), md)

		incoming := false
		_, err := GetClientIDFromContext(ctx, incoming)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMissingClientID)
	})

	t.Run("bad - should return error if no metadata in outgoing context", func(t *testing.T) {
		incoming := false
		_, err := GetClientIDFromContext(t.Context(), incoming)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoMetadataFound)
	})

	t.Run("bad - should return error if more than one metadata client_id key in outgoing context", func(t *testing.T) {
		md := metadata.Pairs(ClientIDKey, "id-1", ClientIDKey, "id-2")
		ctx := metadata.NewOutgoingContext(t.Context(), md)
		incoming := false

		_, err := GetClientIDFromContext(ctx, incoming)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConflictClientID)
	})
}
