package auth

import (
	"context"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
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

func ContextWithRequestTokenToContext(ctx context.Context, req connect.AnyRequest) context.Context {
	token := req.Header().Get("Authorization")

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
