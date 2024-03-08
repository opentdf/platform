package sdk

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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
	newMetadata := make([]string, 0)
	accessToken, err := i.tokenSource.AccessToken()
	if err == nil {
		newMetadata = append(newMetadata, "Authorization", fmt.Sprintf("Bearer %s", accessToken))
	} else {
		slog.Error("error getting access token: %w. Request will be unauthenticated", err)
	}

	dpopTok, err := i.getDPOPToken(method)
	if err == nil {
		newMetadata = append(newMetadata, "DPoP", dpopTok)
	} else {
		slog.Error("error adding dpop token to outgoing request. Request will not have DPoP token", err)
	}

	newCtx := metadata.AppendToOutgoingContext(ctx, newMetadata...)

	return invoker(newCtx, method, req, reply, cc, opts...)
}

func (i outgoingInterceptor) getDPOPToken(method string) (string, error) {
	tok, err := i.tokenSource.MakeToken(func(key jwk.Key) ([]byte, error) {
		jtiBytes := make([]byte, 14)
		_, err := rand.Read(jtiBytes)
		if err != nil {
			return nil, fmt.Errorf("error creating jti for dpop jwt: %w", err)
		}

		publicKey, err := key.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("error getting public key from DPOP key: %w", err)
		}

		headers := jws.NewHeaders()
		headers.Set(jws.JWKKey, publicKey)
		headers.Set(jws.TypeKey, "dpop+jwt")
		headers.Set(jws.AlgorithmKey, key.Algorithm())
		headers.Set("jti", base64.StdEncoding.EncodeToString(jtiBytes))

		dpopTok, err := jwt.NewBuilder().
			Claim("htu", method).
			Claim("htm", "POST").
			IssuedAt(time.Now()).
			Build()

		if err != nil {
			return nil, fmt.Errorf("error creating dpop jwt: %w", err)
		}

		signedToken, err := jwt.Sign(dpopTok, jwt.WithKey(key.Algorithm(), key, jws.WithProtectedHeaders(headers)))
		fmt.Printf("%s\n\n\n", signedToken)
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
