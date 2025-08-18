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
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	"github.com/opentdf/platform/sdk/httputil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func setupTokenAddingInterceptor(t *testing.T) (TokenAddingInterceptor, jwk.Key) {
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

	oo := NewTokenAddingInterceptorWithClient(&ts, httputil.SafeHTTPClientWithTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12,
	}))
	return oo, key
}

func checkAccessAndDpopTokens(t *testing.T, accessToken []string, dpopToken []string, key jwk.Key) {
	assert.ElementsMatch(t, accessToken, []string{"DPoP thisisafakeaccesstoken"})
	require.Len(t, dpopToken, 1, "incorrect dpop token headers")
	alg, ok := key.Algorithm().(jwa.SignatureAlgorithm)
	assert.True(t, ok, "got a bad signing algorithm")

	thisDpopToken := dpopToken[0]
	_, err := jws.Verify([]byte(thisDpopToken), jws.WithKey(alg, key))
	require.NoError(t, err, "error verifying signature")

	parsedSignature, _ := jws.Parse([]byte(thisDpopToken))
	require.Len(t, parsedSignature.Signatures(), 1, "incorrect number of signatures")

	sig := parsedSignature.Signatures()[0]
	tokenKey, ok := sig.ProtectedHeaders().Get("jwk")
	require.True(t, ok, "didn't get jwk token key")
	tkkey, ok := tokenKey.(jwk.Key)
	require.True(t, ok, "wrong type for jwk token key", tokenKey)

	tp, _ := tkkey.Thumbprint(crypto.SHA256)
	ktp, _ := key.Thumbprint(crypto.SHA256)
	assert.Equal(t, tp, ktp, "got the wrong key from the token")

	parsedToken, _ := jwt.Parse([]byte(thisDpopToken), jwt.WithVerify(false))

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

func TestAddingTokensToOutgoingRequest(t *testing.T) {
	oo, key := setupTokenAddingInterceptor(t)

	serverGrpc := FakeAccessServiceServer{}

	clientGrpc, stopG := runServer(&serverGrpc, oo)
	defer stopG()
	_, err := clientGrpc.PublicKey(t.Context(), &kas.PublicKeyRequest{})
	require.NoError(t, err, "error making call")

	checkAccessAndDpopTokens(t, serverGrpc.accessToken, serverGrpc.dpopToken, key)
}

func TestAddingTokensToOutgoingRequest_Connect(t *testing.T) {
	oo, key := setupTokenAddingInterceptor(t)

	serverConnect := FakeAccessServiceServerConnect{}
	clientConnect, stopC := runConnectServer(&serverConnect, oo)
	defer stopC()
	_, err := clientConnect.PublicKey(t.Context(), connect.NewRequest(&kas.PublicKeyRequest{}))
	require.NoError(t, err, "error making call")

	checkAccessAndDpopTokens(t, serverConnect.accessToken, serverConnect.dpopToken, key)
}

func Test_InvalidCredentials_DoesNotSendMessage(t *testing.T) {
	ts := FakeTokenSource{key: nil, accessToken: ""}
	serverGrpc := FakeAccessServiceServer{}
	oo := NewTokenAddingInterceptorWithClient(&ts, httputil.SafeHTTPClientWithTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12,
	}))

	clientGrpc, stopG := runServer(&serverGrpc, oo)
	defer stopG()

	_, err := clientGrpc.PublicKey(t.Context(), &kas.PublicKeyRequest{})
	require.Error(t, err, "should not have sent message because the token source returned an error")
}

func Test_InvalidCredentials_DoesNotSendMessage_Connect(t *testing.T) {
	ts := FakeTokenSource{key: nil, accessToken: ""}
	serverConnect := FakeAccessServiceServerConnect{}
	oo := NewTokenAddingInterceptorWithClient(&ts, httputil.SafeHTTPClientWithTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12,
	}))

	clientConnect, stopC := runConnectServer(&serverConnect, oo)
	defer stopC()

	_, err := clientConnect.PublicKey(t.Context(), connect.NewRequest(&kas.PublicKeyRequest{}))
	require.Error(t, err, "should not have sent message because the token source returned an error")
}

type FakeAccessServiceServerConnect struct {
	accessToken []string
	dpopToken   []string
	dpopKey     jwk.Key
	kasconnect.UnimplementedAccessServiceHandler
}

func (f *FakeAccessServiceServerConnect) PublicKey(ctx context.Context, req *connect.Request[kas.PublicKeyRequest]) (*connect.Response[kas.PublicKeyResponse], error) {
	f.accessToken = []string{req.Header().Get("authorization")}
	f.dpopToken = []string{req.Header().Get("dpop")}
	var ok bool
	f.dpopKey, ok = ctx.Value("dpop-jwk").(jwk.Key)
	if !ok {
		f.dpopKey = nil
	}
	return connect.NewResponse(&kas.PublicKeyResponse{}), nil
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

func runConnectServer(
	f *FakeAccessServiceServerConnect, oo TokenAddingInterceptor,
) (kasconnect.AccessServiceClient, func()) {
	mux := http.NewServeMux()
	path, handler := kasconnect.NewAccessServiceHandler(f)
	mux.Handle(path, handler)

	server := httptest.NewServer(mux)

	client := kasconnect.NewAccessServiceClient(
		server.Client(),
		server.URL,
		connect.WithInterceptors(oo.AddCredentialsConnect()),
	)

	return client, func() {
		// Safely close the server
		if server != nil {
			server.Close()
		}
	}
}

func runServer( //nolint:ireturn // this is pretty concrete
	f *FakeAccessServiceServer, oo TokenAddingInterceptor,
) (kas.AccessServiceClient, func()) {
	buffer := 1024 * 1024
	listener := bufconn.Listen(buffer)

	s := grpc.NewServer()
	kas.RegisterAccessServiceServer(s, f)
	serverError := make(chan error, 1)
	go func() {
		if err := s.Serve(listener); err != nil {
			serverError <- err
		}
		close(serverError)
	}()

	conn, _ := grpc.NewClient("passthrough:///bufconn", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithUnaryInterceptor(oo.AddCredentials))

	client := kas.NewAccessServiceClient(conn)

	return client, func() {
		// Gracefully stop the server
		s.GracefulStop()
		// Wait for server to complete or stop immediately if already stopped
		select {
		case <-serverError:
			// Server already stopped, nothing to do
		default:
			s.Stop()
		}
	}
}
