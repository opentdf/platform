package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/sdk/httputil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestAddingTokensToOutgoingRequest(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "error generating key")

	key, err := jwk.FromRaw(privateKey)
	require.NoError(t, err, "error getting raw key")

	err = key.Set(jwk.AlgorithmKey, jwa.RS256)
	require.NoError(t, err, "error setting the algorithm on the JWK")

	ts := FakeTokenSource{
		key:         key,
		accessToken: "thisisafakeaccesstoken",
	}
	server := FakeAccessServiceServer{}
	oo := NewTokenAddingInterceptorWithClient(&ts, httputil.SafeHTTPClientWithTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12,
	}))

	client, stop := runServer(&server, oo)
	defer stop()

	_, err = client.PublicKey(t.Context(), &kas.PublicKeyRequest{})
	require.NoError(t, err, "error making call")

	assert.ElementsMatch(t, server.accessToken, []string{"DPoP thisisafakeaccesstoken"})
	require.Len(t, server.dpopToken, 1, "incorrect dpop token headers")

	dpopToken := server.dpopToken[0]
	alg, ok := key.Algorithm().(jwa.SignatureAlgorithm)
	assert.True(t, ok, "got a bad signing algorithm")

	_, err = jws.Verify([]byte(dpopToken), jws.WithKey(alg, key))
	require.NoError(t, err, "error verifying signature")

	parsedSignature, _ := jws.Parse([]byte(dpopToken))
	require.Len(t, parsedSignature.Signatures(), 1, "incorrect number of signatures")

	sig := parsedSignature.Signatures()[0]
	tokenKey, ok := sig.ProtectedHeaders().Get("jwk")
	require.True(t, ok, "didn't get jwk token key")
	tkkey, ok := tokenKey.(jwk.Key)
	require.True(t, ok, "wrong type for jwk token key", tokenKey)

	tp, _ := tkkey.Thumbprint(crypto.SHA256)
	ktp, _ := key.Thumbprint(crypto.SHA256)
	assert.Equal(t, tp, ktp, "got the wrong key from the token")

	parsedToken, _ := jwt.Parse([]byte(dpopToken), jwt.WithVerify(false))

	method, ok := parsedToken.Get("htm")
	require.True(t, ok, "error getting htm claim")
	assert.Equal(t, http.MethodPost, method, "got a bad method")

	path, ok := parsedToken.Get("htu")
	require.True(t, ok, "error getting htu claim")
	assert.Equal(t, "/kas.AccessService/PublicKey", path, "got a bad path")

	h := sha256.New()
	h.Write([]byte("thisisafakeaccesstoken"))
	expectedHash := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h.Sum(nil))

	ath, ok := parsedToken.Get("ath")
	require.True(t, ok, "error getting ath claim")
	assert.Equal(t, expectedHash, ath, "invalid ath claim in token")
}

func Test_InvalidCredentials_DoesNotSendMessage(t *testing.T) {
	ts := FakeTokenSource{key: nil, accessToken: ""}
	server := FakeAccessServiceServer{}
	oo := NewTokenAddingInterceptorWithClient(&ts, httputil.SafeHTTPClientWithTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12,
	}))

	client, stop := runServer(&server, oo)
	defer stop()

	_, err := client.PublicKey(t.Context(), &kas.PublicKeyRequest{})
	require.Error(t, err, "should not have sent message because the token source returned an error")
}

type FakeAccessServiceServer struct {
	accessToken []string
	dpopToken   []string
	dpopKey     jwk.Key
	kas.UnimplementedAccessServiceServer
}

func (f *FakeAccessServiceServer) PublicKey(ctx context.Context, _ *kas.PublicKeyRequest) (*kas.PublicKeyResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		f.accessToken = md.Get("authorization")
		f.dpopToken = md.Get("dpop")
	}
	var ok bool
	f.dpopKey, ok = ctx.Value("dpop-jwk").(jwk.Key)
	if !ok {
		f.dpopKey = nil
	}
	return &kas.PublicKeyResponse{}, nil
}

func (f *FakeAccessServiceServer) LegacyPublicKey(context.Context, *kas.LegacyPublicKeyRequest) (*wrapperspb.StringValue, error) {
	return &wrapperspb.StringValue{}, nil
}
func (f *FakeAccessServiceServer) Rewrap(context.Context, *kas.RewrapRequest) (*kas.RewrapResponse, error) {
	return &kas.RewrapResponse{}, nil
}

type FakeTokenSource struct {
	key         jwk.Key
	accessToken string
}

func (fts *FakeTokenSource) AccessToken(context.Context, *http.Client) (AccessToken, error) {
	if fts.accessToken == "" {
		return "", errors.New("no token to provide")
	}
	return AccessToken(fts.accessToken), nil
}
func (fts *FakeTokenSource) MakeToken(f func(jwk.Key) ([]byte, error)) ([]byte, error) {
	if fts.key == nil {
		return nil, errors.New("no such key")
	}
	return f(fts.key)
}

func runServer( //nolint:ireturn // this is pretty concrete
	f *FakeAccessServiceServer, oo TokenAddingInterceptor) (kas.AccessServiceClient, func()) {
	buffer := 1024 * 1024
	listener := bufconn.Listen(buffer)

	s := grpc.NewServer()
	kas.RegisterAccessServiceServer(s, f)
	go func() {
		if err := s.Serve(listener); err != nil {
			panic(err)
		}
	}()

	conn, _ := grpc.NewClient("passthrough:///bufconn", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithUnaryInterceptor(oo.AddCredentials))

	client := kas.NewAccessServiceClient(conn)

	return client, s.Stop
}
