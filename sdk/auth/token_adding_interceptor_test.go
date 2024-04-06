package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"slices"
	"testing"

	"github.com/arkavo-org/opentdf-platform/protocol/go/kas"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestAddingTokensToOutgoingRequest(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("error generating key: %v", err)
	}

	key, err := jwk.FromRaw(privateKey)
	if err != nil {
		t.Fatalf("error getting raw key")
	}

	err = key.Set(jwk.AlgorithmKey, jwa.RS256)
	if err != nil {
		t.Fatalf("error setting the algorithm on the JWK")
	}
	ts := FakeTokenSource{
		key:         key,
		accessToken: "thisisafakeaccesstoken",
	}
	server := FakeAccessServiceServer{}
	oo := NewTokenAddingInterceptor(&ts)

	client, stop := runServer(context.Background(), &server, oo)
	defer stop()

	_, err = client.Info(context.Background(), &kas.InfoRequest{})
	if err != nil {
		t.Fatalf("error making call: %v", err)
	}

	if len(server.accessToken) != 1 || server.accessToken[0] != "DPoP thisisafakeaccesstoken" {
		t.Fatalf("got incorrect access token: %v", server.accessToken)
	}

	if len(server.dpopToken) != 1 {
		t.Fatalf("Got incorrect dpop token headers: %v", server.dpopToken)
	}

	dpopToken := server.dpopToken[0]

	alg, ok := key.Algorithm().(jwa.SignatureAlgorithm)
	if !ok {
		t.Fatalf("got a bad signing algorithm")
	}

	_, err = jws.Verify([]byte(dpopToken), jws.WithKey(alg, key))
	if err != nil {
		t.Fatalf("error verifying signature: %v", err)
	}

	parsedSignature, _ := jws.Parse([]byte(dpopToken))

	if len(parsedSignature.Signatures()) == 0 {
		t.Fatalf("didn't get signature from jwt")
	}

	sig := parsedSignature.Signatures()[0]
	tokenKey, ok := sig.ProtectedHeaders().Get("jwk")
	if !ok {
		t.Fatalf("didn't get error getting key from token")
	}

	tp, _ := tokenKey.(jwk.Key).Thumbprint(crypto.SHA256)
	ktp, _ := key.Thumbprint(crypto.SHA256)
	if !slices.Equal(tp, ktp) {
		t.Fatalf("got the wrong key from the token")
	}

	parsedToken, _ := jwt.Parse([]byte(dpopToken), jwt.WithVerify(false))

	if method, _ := parsedToken.Get("htm"); method != http.MethodPost {
		t.Fatalf("we got a bad method: %v", method)
	}

	if path, _ := parsedToken.Get("htu"); path != "/kas.AccessService/Info" {
		t.Fatalf("we got a bad method: %v", path)
	}

	h := sha256.New()
	h.Write([]byte("thisisafakeaccesstoken"))
	expectedHash := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h.Sum(nil))

	if ath, _ := parsedToken.Get("ath"); ath != expectedHash {
		t.Fatalf("got invalid ath claim in token: %v", ath)
	}
}

func Test_InvalidCredentials_StillSendMessage(t *testing.T) {
	ts := FakeTokenSource{key: nil}
	server := FakeAccessServiceServer{}
	oo := NewTokenAddingInterceptor(&ts)

	client, stop := runServer(context.Background(), &server, oo)
	defer stop()

	_, err := client.Info(context.Background(), &kas.InfoRequest{})

	if err != nil {
		t.Fatalf("got an error when sending the message")
	}
}

type FakeAccessServiceServer struct {
	accessToken []string
	dpopToken   []string
	dpopKey     jwk.Key
	kas.UnimplementedAccessServiceServer
}

func (f *FakeAccessServiceServer) Info(ctx context.Context, _ *kas.InfoRequest) (*kas.InfoResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		f.accessToken = md.Get("authorization")
		f.dpopToken = md.Get("dpop")
	}
	var ok bool
	f.dpopKey, ok = ctx.Value("dpop-jwk").(jwk.Key)
	if !ok {
		f.dpopKey = nil
	}
	return &kas.InfoResponse{}, nil
}
func (f *FakeAccessServiceServer) PublicKey(context.Context, *kas.PublicKeyRequest) (*kas.PublicKeyResponse, error) {
	return &kas.PublicKeyResponse{}, status.Error(codes.Unauthenticated, "no public key for you")
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

func (fts *FakeTokenSource) AccessToken() (AccessToken, error) {
	return AccessToken(fts.accessToken), nil
}
func (fts *FakeTokenSource) MakeToken(f func(jwk.Key) ([]byte, error)) ([]byte, error) {
	if fts.key == nil {
		return nil, errors.New("no such key")
	}
	return f(fts.key)
}
func runServer(ctx context.Context, //nolint:ireturn // this is pretty concrete
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

	conn, _ := grpc.DialContext(ctx, "", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock(), grpc.WithUnaryInterceptor(oo.AddCredentials))

	client := kas.NewAccessServiceClient(conn)

	return client, s.Stop
}
