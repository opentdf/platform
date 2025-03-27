package auth

import (
	"context"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	"google.golang.org/grpc/metadata"
)

var (
	authnContextKey = authContextKey{}
)

type authContextKey struct{}

type authContext struct {
	key         jwk.Key
	accessToken jwt.Token
	rawToken    string
}

const (
	AuthorizationBearer                  = "Bearer "
	HeaderAuthorization                  = "Authorization"
	HeaderWithIPCAuthorizationValidation = "With-Ipc-Authorization-Validation"
)

// WithAuthorizationContext adds the authorization context to the outgoing context
// This is used to pass the access token when needing to ensure the current user should have access
// to the resource
// Go can't pass the token in the context because it's a struct and not a string and Go doesn't know
// how to serialize it
func WithAuthorizationContext(ctx context.Context, req connect.AnyRequest) context.Context {
	raw := GetRawAccessTokenFromContext(ctx, nil)

	// If token is missing from context, try to get it from the request
	// This is useful when the request is not a connect request
	if raw == "" && req != nil {
		raw = req.Header().Get(HeaderAuthorization)
	}

	// If we don't have a token, we don't need to do anything
	if raw == "" {
		return ctx
	}

	// Add the token for extraction in auth
	ctx = metadata.AppendToOutgoingContext(ctx, HeaderAuthorization, AuthorizationBearer+raw)
	ctx = metadata.AppendToOutgoingContext(ctx, HeaderWithIPCAuthorizationValidation, "true")
	return ctx
}

func ContextWithRequestTokenToContext(ctx context.Context, req connect.AnyRequest) context.Context {
	token := req.Header().Get(HeaderAuthorization)

	return context.WithValue(ctx, authnContextKey, &authContext{
		nil,
		nil,
		token,
	})
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

func GetTokenFromContextOrRequestHeader(ctx context.Context, r connect.AnyRequest) string {
	if token := GetRawAccessTokenFromContext(ctx, nil); token != "" {
		return token
	}

	at := r.Header().Get("Authorization")
	if at == "" {
		return ""
	}
	return at
}
