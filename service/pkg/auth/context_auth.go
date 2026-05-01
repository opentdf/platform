package auth

import (
	"context"
	"errors"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"google.golang.org/grpc/metadata"
)

var (
	authnContextKey     = authContextKey{}
	ErrNoMetadataFound  = errors.New("no metadata found within context")
	ErrMissingClientID  = errors.New("missing authn idP clientID")
	ErrConflictClientID = errors.New("context metadata mistakenly has more than one authn idP clientID")
)

const (
	AccessTokenKey = "access_token"
	ClientIDKey    = "client_id"
)

type authContextKey struct{}

type authContext struct {
	key         jwk.Key
	accessToken jwt.Token
	rawToken    string
}

type contextErrorLogger interface {
	ErrorContext(context.Context, string, ...any)
}

func ContextWithAuthNInfo(ctx context.Context, key jwk.Key, accessToken jwt.Token, raw string) context.Context {
	return context.WithValue(ctx, authnContextKey, &authContext{
		key,
		accessToken,
		raw,
	})
}

func getContextDetails(ctx context.Context, l contextErrorLogger) *authContext {
	key := ctx.Value(authnContextKey)
	if key == nil {
		return nil
	}
	if c, ok := key.(*authContext); ok {
		return c
	}

	if l != nil {
		l.ErrorContext(ctx, "invalid authContext")
	}
	return nil
}

func GetJWKFromContext(ctx context.Context, l contextErrorLogger) jwk.Key {
	if c := getContextDetails(ctx, l); c != nil {
		return c.key
	}
	return nil
}

func GetAccessTokenFromContext(ctx context.Context, l contextErrorLogger) jwt.Token {
	if c := getContextDetails(ctx, l); c != nil {
		if c.accessToken != nil {
			return c.accessToken
		}
	}

	rawToken := GetRawAccessTokenFromContext(ctx, l)
	if rawToken == "" {
		return nil
	}

	parsed, err := jwt.Parse([]byte(rawToken), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		if l != nil {
			l.ErrorContext(ctx, "failed to parse access token from context", "error", err)
		}
		return nil
	}

	return parsed
}

func GetRawAccessTokenFromContext(ctx context.Context, l contextErrorLogger) string {
	if c := getContextDetails(ctx, l); c != nil {
		if c.rawToken != "" {
			return c.rawToken
		}
	}

	if rawToken := getRawAccessTokenFromMetadata(ctx, true); rawToken != "" {
		return rawToken
	}
	if rawToken := getRawAccessTokenFromMetadata(ctx, false); rawToken != "" {
		return rawToken
	}

	return ""
}

// EnrichIncomingContextMetadataWithAuthn adds the access token and client ID to incoming context metadata
//
// Adding the authn info to gRPC metadata propagates it across services rather than strictly
// in-process within Go alone
func EnrichIncomingContextMetadataWithAuthn(ctx context.Context, l contextErrorLogger, clientID string) context.Context {
	rawToken := GetRawAccessTokenFromContext(ctx, l)

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = metadata.New(nil)
	} else {
		md = md.Copy()
	}
	if rawToken != "" {
		md.Set(AccessTokenKey, rawToken)
	}

	if clientID != "" {
		md.Set(ClientIDKey, clientID)
	}

	return metadata.NewIncomingContext(ctx, md)
}

func getRawAccessTokenFromMetadata(ctx context.Context, incoming bool) string {
	var (
		md metadata.MD
		ok bool
	)
	if incoming {
		md, ok = metadata.FromIncomingContext(ctx)
	} else {
		md, ok = metadata.FromOutgoingContext(ctx)
	}
	if !ok {
		return ""
	}

	if accessTokens := md.Get(AccessTokenKey); len(accessTokens) > 0 && accessTokens[0] != "" {
		return accessTokens[0]
	}

	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		authHeaders = md.Get("Authorization")
	}
	if len(authHeaders) > 0 {
		return trimAuthorizationHeader(authHeaders[0])
	}
	return ""
}

func trimAuthorizationHeader(header string) string {
	switch {
	case strings.HasPrefix(header, "Bearer "):
		return strings.TrimPrefix(header, "Bearer ")
	case strings.HasPrefix(header, "DPoP "):
		return strings.TrimPrefix(header, "DPoP ")
	default:
		return header
	}
}

// GetClientIDFromContext retrieves the client ID from the metadata in the context
func GetClientIDFromContext(ctx context.Context, incoming bool) (string, error) {
	var (
		md metadata.MD
		ok bool
	)
	if incoming {
		md, ok = metadata.FromIncomingContext(ctx)
	} else {
		md, ok = metadata.FromOutgoingContext(ctx)
	}
	if !ok {
		return "", ErrNoMetadataFound
	}

	clientIDs := md.Get(ClientIDKey)
	if len(clientIDs) == 0 {
		return "", ErrMissingClientID
	}
	if len(clientIDs) > 1 {
		return "", ErrConflictClientID
	}

	return clientIDs[0], nil
}
