package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/kas/kasconnect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	clientConnect, stopC := runConnectServer(&serverConnect)
	defer stopC()

	contextRequestID := uuid.New()
	contextActorID := "actorID"
	ctx := t.Context()
	ctx = context.WithValue(ctx, RequestIDContextKey, contextRequestID)
	ctx = context.WithValue(ctx, ActorIDContextKey, contextActorID)

	_, err := clientConnect.PublicKey(ctx, connect.NewRequest(&kas.PublicKeyRequest{}))
	require.NoError(t, err)

	assert.Equal(t, contextRequestID, serverConnect.requestID, "request ID did not match")
	assert.Equal(t, contextActorID, serverConnect.actorID, "actor ID did not match")
}

func TestIsOKWithNoContextValues(t *testing.T) {
	serverConnect := FakeAccessServiceServerConnect{}
	clientConnect, stopC := runConnectServer(&serverConnect)
	defer stopC()

	_, err := clientConnect.PublicKey(t.Context(), connect.NewRequest(&kas.PublicKeyRequest{}))
	if err != nil {
		t.Fatalf("error making call: %v", err)
	}
	generatedRequestIDConnect, err := uuid.Parse(serverConnect.requestID.String())
	if err != nil || generatedRequestIDConnect == uuid.Nil {
		t.Fatalf("did not generate request ID: %v", err)
	}

	if serverConnect.actorID != "" {
		t.Fatalf("actor ID not defaulted correctly: %v", serverConnect.actorID)
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
		connect.WithInterceptors(MetadataAddingConnectInterceptor()),
	)

	return client, func() {
		server.Close()
	}
}
