package sdk

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"

	gocrypto "crypto"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	kas "github.com/opentdf/backend-go/pkg/access"
	"github.com/opentdf/platform/sdk/internal/crypto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type FakeAccessServiceServer struct {
	accessToken []string
	dpopToken   []string
	kas.UnimplementedAccessServiceServer
}

func (f *FakeAccessServiceServer) Info(ctx context.Context, _ *kas.InfoRequest) (*kas.InfoResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		f.accessToken = md.Get("authorization")
		f.dpopToken = md.Get("dpop")
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
func (*FakeTokenSource) AsymDecryption() crypto.AsymDecryption {
	return crypto.AsymDecryption{}
}
func (fts *FakeTokenSource) MakeToken(f func(jwk.Key) ([]byte, error)) ([]byte, error) {
	if fts.key == nil {
		return nil, errors.New("no such key")
	}
	return f(fts.key)
}
func (*FakeTokenSource) DPOPPublicKeyPEM() string {
	return ""
}
func (*FakeTokenSource) RefreshAccessToken() error {
	return nil
}

func runServer(ctx context.Context, f *FakeAccessServiceServer, oo tokenAddingInterceptor) (kas.AccessServiceClient, func()) {
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
	}), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock(), grpc.WithUnaryInterceptor(oo.addCredentials))

	client := kas.NewAccessServiceClient(conn)

	return client, s.Stop
}

func TestAddingTokensToOutgoingRequest(t *testing.T) {

	_, key, _, _ := getNewDPoPKey()
	ts := FakeTokenSource{
		key:         key,
		accessToken: "thisisafakeaccesstoken",
	}
	server := FakeAccessServiceServer{}
	oo := newOutgoingInterceptor(&ts)

	client, stop := runServer(context.Background(), &server, oo)
	defer stop()

	client.Info(context.Background(), &kas.InfoRequest{})

	if len(server.accessToken) != 1 || server.accessToken[0] != "Bearer thisisafakeaccesstoken" {
		t.Fatalf("Got incorrect access token: %v", server.accessToken)
	}

	if len(server.dpopToken) != 1 {
		t.Fatalf("Got incorrect dpop token headers: %v", server.dpopToken)
	}

	dpopToken := server.dpopToken[0]

	alg := key.Algorithm().(jwa.SignatureAlgorithm)

	_, err := jws.Verify([]byte(dpopToken), jws.WithKey(alg, key))
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

	tp, _ := tokenKey.(jwk.Key).Thumbprint(gocrypto.SHA256)
	ktp, _ := key.Thumbprint(gocrypto.SHA256)
	if !slices.Equal(tp, ktp) {
		t.Fatalf("got the wrong key from the token")
	}

	parsedToken, _ := jwt.Parse([]byte(dpopToken), jwt.WithVerify(false))

	if method, ok := parsedToken.Get("htm"); !ok || method.(string) != "POST" {
		t.Fatalf("we got a bad method: %v", method)
	}

	if path, ok := parsedToken.Get("htu"); !ok || path.(string) != "/access.AccessService/Info" {
		t.Fatalf("we got a bad method: %v", path)
	}
}

func Test_ErrorsCredentials_StillSendMessage(t *testing.T) {
	ts := FakeTokenSource{key: nil}
	server := FakeAccessServiceServer{}
	oo := newOutgoingInterceptor(&ts)

	client, stop := runServer(context.Background(), &server, oo)
	defer stop()

	_, err := client.Info(context.Background(), &kas.InfoRequest{})

	if err != nil {
		t.Fatalf("got an error when sending the message")
	}
}
