package auth

import (
	"context"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
)

var authnContextKey = authContextKey{}

type authContextKey struct{}

type authContext struct {
	Key      jwk.Key
	Token    jwt.Token
	TokenRaw string
	UserInfo []byte
}

func ContextWithAuthNInfo(ctx context.Context, key jwk.Key, token jwt.Token, tokenRaw string, userInfo []byte) context.Context {
	return context.WithValue(ctx, authnContextKey, &authContext{
		key,
		token,
		tokenRaw,
		userInfo,
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
		return c.Key
	}
	return nil
}

func GetAccessTokenFromContext(ctx context.Context, l *logger.Logger) jwt.Token {
	if c := getContextDetails(ctx, l); c != nil {
		return c.Token
	}
	return nil
}

func GetRawAccessTokenFromContext(ctx context.Context, l *logger.Logger) string {
	if c := getContextDetails(ctx, l); c != nil {
		return c.TokenRaw
	}
	return ""
}

func GetUserInfoFromContext(ctx context.Context, l *logger.Logger) []byte {
	if c := getContextDetails(ctx, l); c != nil {
		return c.UserInfo
	}
	return nil
}
