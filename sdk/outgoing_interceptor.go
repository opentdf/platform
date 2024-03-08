package sdk

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type outgoingInterceptor struct {
	tokenSource AccessTokenSource
}

func (i outgoingInterceptor) addCredentials(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		slog.Error("couldn't get metadata from outgoing context")
	}

	newMetadata := make([]string, 0)
	accessToken, err := i.tokenSource.AccessToken()
	if err != nil {
		slog.Error("error getting access token: %w. Request will be unauthenticated", err)
	} else {
		newMetadata = append(newMetadata, "Authorization", fmt.Sprintf("Bearer %s", accessToken))
	}

	dpopTok, err := i.getDPOPToken(md)
	if err != nil {
		slog.Error("error adding dpop token to outgoing request", err)
	} else {
		newMetadata = append(newMetadata, "DPoP", dpopTok)
	}

	newCtx := metadata.AppendToOutgoingContext(ctx, newMetadata...)

	return invoker(newCtx, method, req, reply, cc, opts...)
}

func (i outgoingInterceptor) getDPOPToken(md metadata.MD) (string, error) {
	httpMethod := "POST"
	methods := md.Get("method")
	if len(methods) > 0 {
		httpMethod = methods[0]
	}
	paths := md.Get("path")
	if len(paths) == 0 {
		return "", errors.New("couldn't get a path to sign in the DPOP token")
	}

	path := paths[0]

	tok, err := i.tokenSource.MakeToken(func(key jwk.Key) ([]byte, error) {
		jtiBytes := make([]byte, 14)
		_, err := rand.Read(jtiBytes)
		if err != nil {
			return nil, fmt.Errorf("error creating jti for dpop jwt: %w", err)
		}

		headers := jws.NewHeaders()
		headers.Set(jws.JWKKey, key)
		headers.Set(jws.TypeKey, "dpop+jwt")
		headers.Set(jws.AlgorithmKey, key.Algorithm())
		headers.Set("jti", base64.StdEncoding.EncodeToString(jtiBytes))

		dpopTok, err := jwt.NewBuilder().
			Claim("htu", path).
			Claim("htm", httpMethod).
			IssuedAt(time.Now()).
			Build()

		if err != nil {
			return nil, fmt.Errorf("error creating dpop jwt: %w", err)
		}

		signedToken, err := jwt.Sign(dpopTok, jwt.WithKey(key.Algorithm(), key, jws.WithProtectedHeaders(headers)))
		if err != nil {
			return nil, fmt.Errorf("error signing dpop jwt: %w", err)
		}

		return signedToken, nil
	})

	if err != nil {
		return "", err
	}

	return string(tok), nil
}
