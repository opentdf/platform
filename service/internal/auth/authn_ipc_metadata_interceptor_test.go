package auth

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/service/logger"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestIPCMetadataClientInterceptor(t *testing.T) {
	testLogger := logger.CreateTestLogger()
	mockClientID := "test-client-id"

	tests := []struct {
		name            string
		setupContext    func() context.Context
		isClient        bool
		expectedHeaders map[string]string
	}{
		{
			name: "transfers client_id from outgoing metadata to headers",
			setupContext: func() context.Context {
				ctx := context.Background()
				return metadata.AppendToOutgoingContext(ctx, ctxAuth.ClientIDKey, mockClientID)
			},
			isClient:        true,
			expectedHeaders: map[string]string{canonicalHeaderClientIDKey: mockClientID},
		},
		{
			name: "does not add headers when no metadata present",
			setupContext: func() context.Context {
				return context.Background()
			},
			isClient:        true,
			expectedHeaders: map[string]string{},
		},
		{
			name: "does not process server requests",
			setupContext: func() context.Context {
				ctx := context.Background()
				return metadata.AppendToOutgoingContext(ctx, ctxAuth.ClientIDKey, mockClientID)
			},
			isClient:        false,
			expectedHeaders: map[string]string{},
		},
		{
			name: "handles multiple metadata values",
			setupContext: func() context.Context {
				ctx := context.Background()
				ctx = metadata.AppendToOutgoingContext(ctx, ctxAuth.ClientIDKey, "test-client-id-123")
				ctx = metadata.AppendToOutgoingContext(ctx, "custom-key", "custom-value")
				return ctx
			},
			isClient: true,
			expectedHeaders: map[string]string{
				canonicalHeaderClientIDKey: "test-client-id-123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interceptor := IPCMetadataClientInterceptor(testLogger)

			// Create a mock request
			ctx := tt.setupContext()
			req := connect.NewRequest(&kas.PublicKeyRequest{})

			// Mock the spec to control IsClient
			var called bool
			mockNext := func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				called = true

				// Verify headers were added correctly
				if len(tt.expectedHeaders) > 0 {
					for key, expectedValue := range tt.expectedHeaders {
						actualValue := req.Header().Get(key)
						assert.Equal(t, expectedValue, actualValue, "header %s should match", key)
					}
				} else {
					// Verify no headers were added
					assert.Empty(t, req.Header())
				}

				return connect.NewResponse(&kas.PublicKeyResponse{}), nil
			}

			// Create a wrapper to control IsClient behavior
			wrappedReq := &mockAnyRequest{
				Request:  req,
				isClient: tt.isClient,
			}

			interceptorFunc := interceptor(mockNext)
			_, err := interceptorFunc(ctx, wrappedReq)

			require.NoError(t, err)
			assert.True(t, called, "next handler should have been called")
		})
	}
}

func TestIPCMetadataClientInterceptor_Integration(t *testing.T) {
	testLogger := logger.CreateTestLogger()

	t.Run("client_id propagated through interceptor chain", func(t *testing.T) {
		clientID := "integration-test-client"
		ctx := context.Background()
		ctx = metadata.AppendToOutgoingContext(ctx, ctxAuth.ClientIDKey, clientID)

		interceptor := IPCMetadataClientInterceptor(testLogger)

		req := connect.NewRequest(&kas.PublicKeyRequest{})

		var receivedClientID string
		mockNext := func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			receivedClientID = req.Header().Get(canonicalHeaderClientIDKey)
			return connect.NewResponse(&kas.PublicKeyResponse{}), nil
		}

		wrappedReq := &mockAnyRequest{
			Request:  req,
			isClient: true,
		}

		interceptorFunc := interceptor(mockNext)
		_, err := interceptorFunc(ctx, wrappedReq)

		require.NoError(t, err)
		assert.Equal(t, clientID, receivedClientID)
	})
}

// mockAnyRequest implements connect.AnyRequest for testing
type mockAnyRequest struct {
	*connect.Request[kas.PublicKeyRequest]
	isClient bool
}

func (m *mockAnyRequest) Spec() connect.Spec {
	return connect.Spec{
		IsClient: m.isClient,
	}
}

func (m *mockAnyRequest) Peer() connect.Peer {
	return connect.Peer{}
}

func (m *mockAnyRequest) Any() any {
	return m.Request.Msg
}

func TestIPCUnaryServerInterceptor(t *testing.T) {
	testLogger := logger.CreateTestLogger()

	// Create a minimal authentication instance
	auth := &Authentication{
		logger:          testLogger,
		ipcReauthRoutes: []string{},
	}

	tests := []struct {
		name                   string
		setupRequest           func() connect.AnyRequest
		expectedIncomingMDKeys []string
		expectMetadata         bool
	}{
		{
			name: "transfers client_id from headers to incoming metadata",
			setupRequest: func() connect.AnyRequest {
				req := connect.NewRequest(&kas.PublicKeyRequest{})
				req.Header().Set(canonicalHeaderClientIDKey, "test-client-from-header")
				return &mockAnyRequest{
					Request:  req,
					isClient: false,
				}
			},
			expectedIncomingMDKeys: []string{ctxAuth.ClientIDKey},
			expectMetadata:         true,
		},
		{
			name: "does not add metadata when no headers present",
			setupRequest: func() connect.AnyRequest {
				req := connect.NewRequest(&kas.PublicKeyRequest{})
				return &mockAnyRequest{
					Request:  req,
					isClient: false,
				}
			},
			expectedIncomingMDKeys: []string{},
			expectMetadata:         false,
		},
		{
			name: "merges with existing incoming metadata",
			setupRequest: func() connect.AnyRequest {
				req := connect.NewRequest(&kas.PublicKeyRequest{})
				req.Header().Set(canonicalHeaderClientIDKey, "merged-client-id")
				return &mockAnyRequest{
					Request:  req,
					isClient: false,
				}
			},
			expectedIncomingMDKeys: []string{ctxAuth.ClientIDKey},
			expectMetadata:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interceptor := auth.IPCUnaryServerInterceptor()

			ctx := context.Background()
			req := tt.setupRequest()

			var receivedCtx context.Context
			mockNext := func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				receivedCtx = ctx
				return connect.NewResponse(&kas.PublicKeyResponse{}), nil
			}

			interceptorFunc := interceptor(mockNext)
			_, err := interceptorFunc(ctx, req)

			require.NoError(t, err)
			require.NotNil(t, receivedCtx)

			// Verify incoming metadata
			md, ok := metadata.FromIncomingContext(receivedCtx)
			if tt.expectMetadata {
				assert.True(t, ok, "should have incoming metadata")
				for _, key := range tt.expectedIncomingMDKeys {
					assert.NotEmpty(t, md.Get(key), "metadata key %s should exist", key)
				}
			}
		})
	}
}

func TestIPCUnaryServerInterceptor_Integration(t *testing.T) {
	testLogger := logger.CreateTestLogger()

	auth := &Authentication{
		logger:          testLogger,
		ipcReauthRoutes: []string{},
	}

	t.Run("client_id from header available in context metadata", func(t *testing.T) {
		clientID := "integration-client-id"

		req := connect.NewRequest(&kas.PublicKeyRequest{})
		req.Header().Set(canonicalHeaderClientIDKey, clientID)

		wrappedReq := &mockAnyRequest{
			Request:  req,
			isClient: false,
		}

		interceptor := auth.IPCUnaryServerInterceptor()

		ctx := context.Background()

		var receivedClientID string
		mockNext := func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			md, ok := metadata.FromIncomingContext(ctx)
			require.True(t, ok)
			clientIDs := md.Get(ctxAuth.ClientIDKey)
			if len(clientIDs) > 0 {
				receivedClientID = clientIDs[0]
			}
			return connect.NewResponse(&kas.PublicKeyResponse{}), nil
		}

		interceptorFunc := interceptor(mockNext)
		_, err := interceptorFunc(ctx, wrappedReq)

		require.NoError(t, err)
		assert.Equal(t, clientID, receivedClientID)
	})
}
