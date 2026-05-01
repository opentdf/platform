package auth

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
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
	retrievedJWK := GetJWKFromContext(ctx, nil)
	assert.NotNil(t, retrievedJWK, "JWK should not be nil")
	assert.Equal(t, mockJWK, retrievedJWK, "Retrieved JWK should match the mock JWK")
}

func TestGetAccessTokenFromContext(t *testing.T) {
	// Create mock context with JWT
	mockJWT, _ := jwt.NewBuilder().Build()
	ctx := ContextWithAuthNInfo(t.Context(), nil, mockJWT, "")

	// Retrieve the JWT and assert
	retrievedJWT := GetAccessTokenFromContext(ctx, nil)
	assert.NotNil(t, retrievedJWT, "Access token should not be nil")
	assert.Equal(t, mockJWT, retrievedJWT, "Retrieved JWT should match the mock JWT")
}

func TestGetRawAccessTokenFromContext(t *testing.T) {
	// Create mock context with raw token
	rawToken := "mockRawToken"
	ctx := ContextWithAuthNInfo(t.Context(), nil, nil, rawToken)

	// Retrieve the raw token and assert
	retrievedRawToken := GetRawAccessTokenFromContext(ctx, nil)
	assert.Equal(t, rawToken, retrievedRawToken, "Retrieved raw token should match the mock raw token")
}

func TestGetRawAccessTokenFromContextDoesNotFallbackToMetadata(t *testing.T) {
	t.Run("incoming access token metadata", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs(AccessTokenKey, "incoming-token"))
		retrievedRawToken := GetRawAccessTokenFromContext(ctx, nil)
		assert.Empty(t, retrievedRawToken)
	})

	t.Run("outgoing authorization metadata", func(t *testing.T) {
		ctx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("Authorization", "Bearer outgoing-token"))
		retrievedRawToken := GetRawAccessTokenFromContext(ctx, nil)
		assert.Empty(t, retrievedRawToken)
	})
}

func TestGetAccessTokenFromContextDoesNotFallbackToMetadata(t *testing.T) {
	mockJWT, err := jwt.NewBuilder().
		Subject("metadata-user").
		Claim("roles", []string{"admin"}).
		Build()
	require.NoError(t, err)

	rawToken, err := jwt.Sign(mockJWT, jwt.WithInsecureNoSignature())
	require.NoError(t, err)

	ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs(AccessTokenKey, string(rawToken)))
	retrievedJWT := GetAccessTokenFromContext(ctx, nil)
	assert.Nil(t, retrievedJWT)
}

func TestRehydrateAccessTokenFromIncomingMetadata(t *testing.T) {
	t.Run("rehydrates from access token metadata", func(t *testing.T) {
		mockJWT, err := jwt.NewBuilder().
			Subject("metadata-user").
			Claim("roles", []string{"admin"}).
			Build()
		require.NoError(t, err)

		rawToken, err := jwt.Sign(mockJWT, jwt.WithInsecureNoSignature())
		require.NoError(t, err)

		ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs(AccessTokenKey, string(rawToken)))
		rehydratedCtx, err := RehydrateAccessTokenFromIncomingMetadata(ctx, nil)
		require.NoError(t, err)

		retrievedJWT := GetAccessTokenFromContext(rehydratedCtx, nil)
		require.NotNil(t, retrievedJWT)
		assert.Equal(t, "metadata-user", retrievedJWT.Subject())
		assert.Equal(t, string(rawToken), GetRawAccessTokenFromContext(rehydratedCtx, nil))
	})

	t.Run("uses authorization metadata", func(t *testing.T) {
		mockJWT, err := jwt.NewBuilder().Subject("authorization-user").Build()
		require.NoError(t, err)

		rawToken, err := jwt.Sign(mockJWT, jwt.WithInsecureNoSignature())
		require.NoError(t, err)

		ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("Authorization", "Bearer "+string(rawToken)))
		rehydratedCtx, err := RehydrateAccessTokenFromIncomingMetadata(ctx, nil)
		require.NoError(t, err)

		retrievedJWT := GetAccessTokenFromContext(rehydratedCtx, nil)
		require.NotNil(t, retrievedJWT)
		assert.Equal(t, "authorization-user", retrievedJWT.Subject())
	})

	t.Run("returns unchanged context when auth context already exists", func(t *testing.T) {
		existingJWT, err := jwt.NewBuilder().Subject("existing-user").Build()
		require.NoError(t, err)

		ctx := ContextWithAuthNInfo(t.Context(), nil, existingJWT, "existing-raw-token")
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(AccessTokenKey, "different-token"))
		rehydratedCtx, err := RehydrateAccessTokenFromIncomingMetadata(ctx, nil)
		require.NoError(t, err)

		retrievedJWT := GetAccessTokenFromContext(rehydratedCtx, nil)
		require.NotNil(t, retrievedJWT)
		assert.Equal(t, "existing-user", retrievedJWT.Subject())
		assert.Equal(t, "existing-raw-token", GetRawAccessTokenFromContext(rehydratedCtx, nil))
	})

	t.Run("returns error on invalid token metadata", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs(AccessTokenKey, "not-a-jwt"))
		_, err := RehydrateAccessTokenFromIncomingMetadata(ctx, nil)
		require.Error(t, err)
	})
}

func TestGetContextDetailsInvalidType(t *testing.T) {
	// Create a context with an invalid type
	ctx := context.WithValue(t.Context(), authnContextKey, "invalidType")

	// Assert that GetJWKFromContext handles the invalid type correctly
	retrievedJWK := GetJWKFromContext(ctx, nil)
	assert.Nil(t, retrievedJWK, "JWK should be nil when context value is invalid")
}

func TestEnrichIncomingContextMetadataWithAuthn(t *testing.T) {
	mockClientID := "test-client-id"
	t.Run("should add access token and client id to metadata", func(t *testing.T) {
		ctx := ContextWithAuthNInfo(t.Context(), nil, nil, "raw-token-string")
		enrichedCtx := EnrichIncomingContextMetadataWithAuthn(ctx, nil, mockClientID)

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
		enrichedCtx := EnrichIncomingContextMetadataWithAuthn(ctx, nil, "")

		md, ok := metadata.FromIncomingContext(enrichedCtx)
		require.True(t, ok)

		clientIDs := md.Get(ClientIDKey)
		assert.Empty(t, clientIDs)
	})

	t.Run("should preserve existing metadata", func(t *testing.T) {
		originalMD := metadata.New(map[string]string{"original-key": "original-value"})
		ctx := metadata.NewIncomingContext(t.Context(), originalMD)
		ctx = ContextWithAuthNInfo(ctx, nil, nil, "raw-token-string")
		enrichedCtx := EnrichIncomingContextMetadataWithAuthn(ctx, nil, mockClientID)

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
