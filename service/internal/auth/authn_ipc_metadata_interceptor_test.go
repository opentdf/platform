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
		setupContext    func(ctx context.Context) context.Context
		isClient        bool
		expectedHeaders map[string]string
	}{
		{
			name: "transfers client_id from outgoing metadata to headers",
			setupContext: func(ctx context.Context) context.Context {
				return metadata.AppendToOutgoingContext(ctx, ctxAuth.ClientIDKey, mockClientID)
			},
			isClient:        true,
			expectedHeaders: map[string]string{canonicalIPCHeaderClientID: mockClientID},
		},
		{
			name: "does not add headers when no metadata present",
			setupContext: func(ctx context.Context) context.Context {
				return ctx
			},
			isClient:        true,
			expectedHeaders: map[string]string{},
		},
		{
			name: "does not process server requests",
			setupContext: func(ctx context.Context) context.Context {
				return metadata.AppendToOutgoingContext(ctx, ctxAuth.ClientIDKey, mockClientID)
			},
			isClient:        false,
			expectedHeaders: map[string]string{},
		},
		{
			name: "handles multiple metadata values",
			setupContext: func(ctx context.Context) context.Context {
				ctx = metadata.AppendToOutgoingContext(ctx, ctxAuth.ClientIDKey, "test-client-id-123")
				ctx = metadata.AppendToOutgoingContext(ctx, "custom-key", "custom-value")
				return ctx
			},
			isClient: true,
			expectedHeaders: map[string]string{
				canonicalIPCHeaderClientID: "test-client-id-123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interceptor := IPCMetadataClientInterceptor(testLogger)

			// Create a mock request
			ctx := tt.setupContext(t.Context())
			req := connect.NewRequest(&kas.PublicKeyRequest{})

			// Mock the spec to control IsClient
			var called bool
			mockNext := func(_ context.Context, r connect.AnyRequest) (connect.AnyResponse, error) {
				called = true

				// Verify headers were added correctly
				if len(tt.expectedHeaders) > 0 {
					for key, expectedValue := range tt.expectedHeaders {
						actualValue := r.Header().Get(key)
						assert.Equal(t, expectedValue, actualValue, "header %s should match", key)
					}
				} else {
					// Verify no headers were added
					assert.Empty(t, r.Header())
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
		ctx := t.Context()
		ctx = metadata.AppendToOutgoingContext(ctx, ctxAuth.ClientIDKey, clientID)

		interceptor := IPCMetadataClientInterceptor(testLogger)

		req := connect.NewRequest(&kas.PublicKeyRequest{})

		var receivedClientID string
		mockNext := func(_ context.Context, r connect.AnyRequest) (connect.AnyResponse, error) {
			receivedClientID = r.Header().Get(canonicalIPCHeaderClientID)
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
				req.Header().Set(canonicalIPCHeaderClientID, "test-client-from-header")
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
				req.Header().Set(canonicalIPCHeaderClientID, "merged-client-id")
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

			ctx := t.Context()
			req := tt.setupRequest()

			mockNext := func(postInterceptorCtx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
				ctx = postInterceptorCtx
				return connect.NewResponse(&kas.PublicKeyResponse{}), nil
			}

			interceptorFunc := interceptor(mockNext)
			_, err := interceptorFunc(ctx, req)

			require.NoError(t, err)
			require.NotNil(t, ctx)

			// Verify incoming metadata
			md, ok := metadata.FromIncomingContext(ctx)
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
		req.Header().Set(canonicalIPCHeaderClientID, clientID)

		wrappedReq := &mockAnyRequest{
			Request:  req,
			isClient: false,
		}

		interceptor := auth.IPCUnaryServerInterceptor()

		ctx := t.Context()

		var receivedClientID string
		mockNext := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
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
