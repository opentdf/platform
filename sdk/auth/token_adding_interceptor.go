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

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/sdk/httputil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	JTILength = 14
)

type TokenAddingInterceptor struct {
	tokenSource AccessTokenSource
	httpClient  *http.Client
}

// Deprecated: NewTokenAddingInterceptor is deprecated, use NewTokenAddingInterceptorWithClient instead. A http client
// can be constructed using httputil.SafeHTTPClientWithTLSConfig, but should be reused as much as possible.
func NewTokenAddingInterceptor(t AccessTokenSource, c *tls.Config) TokenAddingInterceptor {
	return NewTokenAddingInterceptorWithClient(t, httputil.SafeHTTPClientWithTLSConfig(c))
}

func NewTokenAddingInterceptorWithClient(t AccessTokenSource, c *http.Client) TokenAddingInterceptor {
	if c == nil {
		c = httputil.SafeHTTPClient()
	}
	return TokenAddingInterceptor{
		tokenSource: t,
		httpClient:  c,
	}
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
	accessToken, err := i.tokenSource.AccessToken(ctx, i.httpClient)
	if err == nil {
		newMetadata = append(newMetadata, "Authorization", fmt.Sprintf("DPoP %s", accessToken))
	} else {
		slog.ErrorContext(ctx, "error getting access token", slog.Any("error", err))
		return status.Error(codes.Unauthenticated, err.Error())
	}

	dpopTok, err := i.GetDPoPToken(method, http.MethodPost, string(accessToken))
	if err == nil {
		newMetadata = append(newMetadata, "DPoP", dpopTok)
	} else {
		// since we don't have a setting about whether DPoP is in use on the client and this request _could_ succeed if
		// they are talking to a server where DPoP is not required we will just let this through. this method is extremely
		// unlikely to fail so hopefully this isn't confusing
		slog.ErrorContext(ctx, "error getting DPoP token for outgoing request. Request will not have DPoP token", slog.Any("error", err))
	}

	newCtx := metadata.AppendToOutgoingContext(ctx, newMetadata...)

	err = invoker(newCtx, method, req, reply, cc, opts...)

	// this is the error from the RPC service. we can determine when the current token is no longer valid
	// by inspecting this error
	return err
}

func (i TokenAddingInterceptor) AddCredentialsConnect() connect.UnaryInterceptorFunc {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(
			ctx context.Context,
			req connect.AnyRequest,
		) (connect.AnyResponse, error) {
			accessToken, err := i.tokenSource.AccessToken(ctx, i.httpClient)
			if err != nil {
				slog.ErrorContext(ctx, "error getting access token", slog.Any("error", err))
				return nil, connect.NewError(connect.CodeUnauthenticated, err)
			}

			// Add Authorization header
			req.Header().Set("Authorization", fmt.Sprintf("DPoP %s", accessToken))

			// Add DPoP header if possible
			dpopTok, err := i.GetDPoPToken(req.Spec().Procedure, http.MethodPost, string(accessToken))
			if err == nil {
				req.Header().Set("DPoP", dpopTok)
			} else {
				// since we don't have a setting about whether DPoP is in use on the client and this request _could_ succeed if
				// they are talking to a server where DPoP is not required we will just let this through. this method is extremely
				// unlikely to fail so hopefully this isn't confusing
				slog.ErrorContext(ctx, "error getting DPoP token for outgoing request. Request will not have DPoP token", slog.Any("error", err))
			}

			// Proceed with the RPC
			return next(ctx, req)
		}
	})
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
