package audit

import (
	"context"
	"net"
	"testing"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/kas"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

type FakeAccessServiceServer struct {
	requestID uuid.UUID
	requestIP string
	actorID   string
	kas.UnimplementedAccessServiceServer
}

func (f *FakeAccessServiceServer) PublicKey(ctx context.Context, _ *kas.PublicKeyRequest) (*kas.PublicKeyResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		requestIDFromMetadata := md.Get(string(RequestIDHeaderKey))
		if len(requestIDFromMetadata) > 0 {
			f.requestID, _ = uuid.Parse(requestIDFromMetadata[0])
		}

		requestIPFromMetadata := md.Get(string(RequestIPHeaderKey))
		if len(requestIPFromMetadata) > 0 {
			f.requestIP = requestIPFromMetadata[0]
		}

		actorIDFromMetadata := md.Get(string(ActorIDHeaderKey))
		if len(actorIDFromMetadata) > 0 {
			f.actorID = actorIDFromMetadata[0]
		}
	}
	return &kas.PublicKeyResponse{}, nil
}

func TestAddingAuditMetadataToOutgoingRequest(t *testing.T) {
	server := FakeAccessServiceServer{}
	client, stop := runServer(context.Background(), &server)
	defer stop()

	contextRequestID := uuid.New()
	contextActorID := "actorID"
	ctx := context.Background()
	ctx = context.WithValue(ctx, RequestIDContextKey, contextRequestID)
	ctx = context.WithValue(ctx, ActorIDContextKey, contextActorID)

	_, err := client.PublicKey(ctx, &kas.PublicKeyRequest{})
	if err != nil {
		t.Fatalf("error making call: %v", err)
	}

	if server.requestID != contextRequestID {
		t.Fatalf("request ID did not match: %v", server.requestID)
	}

	if server.actorID != contextActorID {
		t.Fatalf("actor ID did not match: %v", server.actorID)
	}
}

func TestIsOKWithNoContextValues(t *testing.T) {
	server := FakeAccessServiceServer{}
	client, stop := runServer(context.Background(), &server)
	defer stop()

	_, err := client.PublicKey(context.Background(), &kas.PublicKeyRequest{})
	if err != nil {
		t.Fatalf("error making call: %v", err)
	}

	generatedRequestID, err := uuid.Parse(server.requestID.String())
	if err != nil || generatedRequestID == uuid.Nil {
		t.Fatalf("did not generate request ID: %v", err)
	}

	if server.actorID != "" {
		t.Fatalf("actor ID not defaulted correctly: %v", server.actorID)
	}
}

func runServer(ctx context.Context, f *FakeAccessServiceServer) (kas.AccessServiceClient, func()) {
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
	}), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock(), grpc.WithUnaryInterceptor(MetadataAddingClientInterceptor))

	client := kas.NewAccessServiceClient(conn)

	return client, s.Stop
}
