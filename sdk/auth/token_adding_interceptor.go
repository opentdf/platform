package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	JTILength = 14
)

func NewTokenAddingInterceptor(t AccessTokenSource, c *tls.Config) TokenAddingInterceptor {
	return TokenAddingInterceptor{
		tokenSource: t,
		tlsConfig:   c,
	}
}

type TokenAddingInterceptor struct {
	tokenSource AccessTokenSource
	tlsConfig   *tls.Config
}

func (i TokenAddingInterceptor) AddCredentials(
	ctx context.Context,
	method string,
	req, reply any,
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	newMetadata := make([]string, 0)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: i.tlsConfig,
		},
	}
	accessToken, err := i.tokenSource.AccessToken(ctx, client)
	if err == nil {
		newMetadata = append(newMetadata, "Authorization", fmt.Sprintf("DPoP %s", accessToken))
	} else {
		slog.ErrorContext(ctx, "error getting access token. request will be unauthenticated", "error", err)
		return invoker(ctx, method, req, reply, cc, opts...)
	}

	dpopTok, err := i.GetDPoPToken(method, http.MethodPost, string(accessToken))
	if err == nil {
		newMetadata = append(newMetadata, "DPoP", dpopTok)
	} else {
		slog.ErrorContext(ctx, "error adding dpop token to outgoing request. Request will not have DPoP token", "error", err)
	}

	newCtx := metadata.AppendToOutgoingContext(ctx, newMetadata...)

	err = invoker(newCtx, method, req, reply, cc, opts...)

	// this is the error from the RPC service. we can determine when the current token is no longer valid
	// by inspecting this error
	return err
}

func (i TokenAddingInterceptor) GetDPoPToken(path, method, accessToken string) (string, error) {
	tok, err := i.tokenSource.MakeToken(func(key jwk.Key) ([]byte, error) {
		jtiBytes := make([]byte, JTILength)
		_, err := rand.Read(jtiBytes)
		if err != nil {
			return nil, fmt.Errorf("error creating jti for dpop jwt: %w", err)
		}

		publicKey, err := key.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("error getting public key from DPoP key: %w", err)
		}

		headers := jws.NewHeaders()
		err = headers.Set(jws.JWKKey, publicKey)
		if err != nil {
			return nil, fmt.Errorf("error setting the key on the DPoP token: %w", err)
		}
		err = headers.Set(jws.TypeKey, "dpop+jwt")
		if err != nil {
			return nil, fmt.Errorf("error setting the type on the DPoP token: %w", err)
		}
		err = headers.Set(jws.AlgorithmKey, key.Algorithm())
		if err != nil {
			return nil, fmt.Errorf("error setting the algorithm on the DPoP token: %w", err)
		}

		h := sha256.New()
		h.Write([]byte(accessToken))
		ath := h.Sum(nil)

		dpopTok, err := jwt.NewBuilder().
			Claim("htu", path).
			Claim("htm", method).
			Claim("ath", base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(ath)).
			Claim("jti", base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(jtiBytes)).
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
		return "", fmt.Errorf("error creating DPoP token in interceptor: %w", err)
	}

	return string(tok), nil
}
