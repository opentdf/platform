package auth

import (
	"context"
	"errors"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	"google.golang.org/grpc/metadata"
)

var (
	authnContextKey     = authContextKey{}
	ErrNoMetadataFound  = errors.New("no metadata found within context")
	ErrMissingClientID  = errors.New("missing authn idP clientID")
	ErrConflictClientID = errors.New("context metadata mistakenly has more than one authn idP clientID")
)

const (
	accessTokenKey = "access_token"
	clientIDKey    = "client_id"
)

type authContextKey struct{}

type authContext struct {
	key         jwk.Key
	accessToken jwt.Token
	rawToken    string
}

func ContextWithAuthNInfo(ctx context.Context, key jwk.Key, accessToken jwt.Token, raw string) context.Context {
	return context.WithValue(ctx, authnContextKey, &authContext{
		key,
		accessToken,
		raw,
	})
}

func getContextDetails(ctx context.Context, l *logger.Logger) *authContext {
	key := ctx.Value(authnContextKey)
	if key == nil {
		return nil
	}
	if c, ok := key.(*authContext); ok {
		return c
	}

	// We should probably return an error here?
	l.ErrorContext(ctx, "invalid authContext")
	return nil
}

func GetJWKFromContext(ctx context.Context, l *logger.Logger) jwk.Key {
	if c := getContextDetails(ctx, l); c != nil {
		return c.key
	}
	return nil
}

func GetAccessTokenFromContext(ctx context.Context, l *logger.Logger) jwt.Token {
	if c := getContextDetails(ctx, l); c != nil {
		return c.accessToken
	}
	return nil
}

func GetRawAccessTokenFromContext(ctx context.Context, l *logger.Logger) string {
	if c := getContextDetails(ctx, l); c != nil {
		return c.rawToken
	}
	return ""
}

// ContextWithAuthnMetadata adds the access token and client ID to context metadata
//
// Adding the authn into to gRPC metadata propagates it across services rather than strictly
// in-process within Go alone
func ContextWithAuthnMetadata(ctx context.Context, clientID string) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = metadata.New(nil)
	} else {
		// Do not modify original metadata from parent context
		md = md.Copy()
	}

	if rawToken := GetRawAccessTokenFromContext(ctx, nil); rawToken != "" {
		md.Set(accessTokenKey, rawToken)
	}

	// Add client ID to metadata for downstream services
	if clientID != "" {
		md.Set(clientIDKey, clientID)
	}

	return metadata.NewIncomingContext(ctx, md)
}

// GetClientIDFromContext retrieves the client ID from the metadata in the context
func GetClientIDFromContext(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrNoMetadataFound
	}

	clientIDs := md.Get(clientIDKey)
	if len(clientIDs) == 0 {
		return "", ErrMissingClientID
	}
	if len(clientIDs) > 1 {
		return "", ErrConflictClientID
	}

	return clientIDs[0], nil
}
