package audit

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

type FakeAccessServiceServerConnect struct {
	requestID uuid.UUID
	requestIP string
	actorID   string
	kasconnect.UnimplementedAccessServiceHandler
}

func (f *FakeAccessServiceServerConnect) PublicKey(_ context.Context, req *connect.Request[kas.PublicKeyRequest]) (*connect.Response[kas.PublicKeyResponse], error) {
	requestIDFromHeader := req.Header().Get(string(RequestIDHeaderKey))
	if requestIDFromHeader != "" {
		f.requestID, _ = uuid.Parse(requestIDFromHeader)
	}

	requestIPFromHeader := req.Header().Get(string(RequestIPHeaderKey))
	if requestIPFromHeader != "" {
		f.requestIP = requestIPFromHeader
	}

	actorIDFromHeader := req.Header().Get(string(ActorIDHeaderKey))
	if actorIDFromHeader != "" {
		f.actorID = actorIDFromHeader
	}
	return connect.NewResponse(&kas.PublicKeyResponse{}), nil
}

func TestAddingAuditMetadataToOutgoingRequest(t *testing.T) {
	serverConnect := FakeAccessServiceServerConnect{}
	serverGrpc := FakeAccessServiceServer{}
	clientConnect, stopC := runConnectServer(&serverConnect)
	defer stopC()
	clientGrpc, stopG := runServer(&serverGrpc)
	defer stopG()

	contextRequestID := uuid.New()
	contextActorID := "actorID"
	ctx := t.Context()
	ctx = context.WithValue(ctx, RequestIDContextKey, contextRequestID)
	ctx = context.WithValue(ctx, ActorIDContextKey, contextActorID)

	_, err := clientConnect.PublicKey(ctx, connect.NewRequest(&kas.PublicKeyRequest{}))
	require.NoError(t, err)
	_, err = clientGrpc.PublicKey(ctx, &kas.PublicKeyRequest{})
	require.NoError(t, err)

	for _, ids := range []struct {
		actorID   string
		requestID uuid.UUID
	}{
		{requestID: serverConnect.requestID, actorID: serverConnect.actorID},
		{requestID: serverGrpc.requestID, actorID: serverGrpc.actorID},
	} {
		assert.Equal(t, contextRequestID, ids.requestID, "request ID did not match")
		assert.Equal(t, contextActorID, ids.actorID, "actor ID did not match")
	}
}

func TestIsOKWithNoContextValues(t *testing.T) {
	serverConnect := FakeAccessServiceServerConnect{}
	serverGrpc := FakeAccessServiceServer{}
	clientConnect, stopC := runConnectServer(&serverConnect)
	defer stopC()
	clientGrpc, stopG := runServer(&serverGrpc)
	defer stopG()

	_, err := clientConnect.PublicKey(t.Context(), connect.NewRequest(&kas.PublicKeyRequest{}))
	if err != nil {
		t.Fatalf("error making call: %v", err)
	}
	_, err = clientGrpc.PublicKey(t.Context(), &kas.PublicKeyRequest{})
	if err != nil {
		t.Fatalf("error making call: %v", err)
	}

	for _, ids := range []struct {
		actorID   string
		requestID uuid.UUID
	}{
		{requestID: serverConnect.requestID, actorID: serverConnect.actorID},
		{requestID: serverGrpc.requestID, actorID: serverGrpc.actorID},
	} {
		generatedRequestIDConnect, err := uuid.Parse(ids.requestID.String())
		if err != nil || generatedRequestIDConnect == uuid.Nil {
			t.Fatalf("did not generate request ID: %v", err)
		}

		if ids.actorID != "" {
			t.Fatalf("actor ID not defaulted correctly: %v", ids.actorID)
		}
	}
}

func runConnectServer(f *FakeAccessServiceServerConnect) (kasconnect.AccessServiceClient, func()) {
	mux := http.NewServeMux()
	path, handler := kasconnect.NewAccessServiceHandler(f)
	mux.Handle(path, handler)

	server := httptest.NewServer(mux)

	client := kasconnect.NewAccessServiceClient(
		server.Client(),
		server.URL,
		connect.WithInterceptors(MetadataAddingConnectInterceptor(slog.Default())),
	)

	return client, func() {
		server.Close()
	}
}

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

func runServer(f *FakeAccessServiceServer) (kas.AccessServiceClient, func()) {
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
	}), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithUnaryInterceptor(MetadataAddingClientInterceptor))

	client := kas.NewAccessServiceClient(conn)

	return client, s.Stop
}
