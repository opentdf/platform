package auth

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
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
	mockAccessToken := "test-access-token"
	mockToken := jwt.New()
	var mockJWK jwk.Key

	tests := []struct {
		name            string
		setupContext    func(ctx context.Context) context.Context
		isClient        bool
		expectedHeaders map[string]string
	}{
		{
			name: "transfers clientID and access token from incoming metadata to headers",
			setupContext: func(ctx context.Context) context.Context {
				md := metadata.New(map[string]string{
					ctxAuth.ClientIDKey: mockClientID,
				})
				ctx = ctxAuth.ContextWithAuthNInfo(ctx, mockJWK, mockToken, mockAccessToken)
				return metadata.NewIncomingContext(ctx, md)
			},
			isClient: true,
			expectedHeaders: map[string]string{
				canonicalIPCHeaderClientID:    mockClientID,
				canonicalIPCHeaderAccessToken: mockAccessToken,
			},
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
				md := metadata.New(map[string]string{ctxAuth.ClientIDKey: mockClientID})
				return metadata.NewIncomingContext(ctx, md)
			},
			isClient:        false,
			expectedHeaders: map[string]string{},
		},
		{
			name: "handles multiple metadata values including generic forwarding",
			setupContext: func(ctx context.Context) context.Context {
				md := metadata.New(map[string]string{
					ctxAuth.ClientIDKey: mockClientID,
					"custom-key":        "custom-value",
				})
				ctx = ctxAuth.ContextWithAuthNInfo(ctx, mockJWK, mockToken, mockAccessToken)
				return metadata.NewIncomingContext(ctx, md)
			},
			isClient: true,
			expectedHeaders: map[string]string{
				canonicalIPCHeaderClientID:    mockClientID,
				canonicalIPCHeaderAccessToken: mockAccessToken,
				"X-Ipc-Meta-Custom-Key":       "custom-value",
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

	t.Run("clientID and accessToken propagated through interceptor chain", func(t *testing.T) {
		clientID := "integration-test-client"
		accessToken := "integration-test-token"
		ctx := t.Context()
		var mockJWK jwk.Key
		mockToken := jwt.New()

		md := metadata.New(map[string]string{
			ctxAuth.ClientIDKey: clientID,
		})
		ctx = ctxAuth.ContextWithAuthNInfo(ctx, mockJWK, mockToken, accessToken)

		ctx = metadata.NewIncomingContext(ctx, md)

		interceptor := IPCMetadataClientInterceptor(testLogger)

		req := connect.NewRequest(&kas.PublicKeyRequest{})

		var receivedClientID, receivedAccessToken string
		mockNext := func(_ context.Context, r connect.AnyRequest) (connect.AnyResponse, error) {
			receivedClientID = r.Header().Get(canonicalIPCHeaderClientID)
			receivedAccessToken = r.Header().Get(canonicalIPCHeaderAccessToken)
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
		assert.Equal(t, accessToken, receivedAccessToken)
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
	return m.Msg
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
	}{
		{
			name: "transfers clientID and access token from headers to incoming metadata",
			setupRequest: func() connect.AnyRequest {
				req := connect.NewRequest(&kas.PublicKeyRequest{})
				req.Header().Set(canonicalIPCHeaderClientID, "test-client-from-header")
				req.Header().Set(canonicalIPCHeaderAccessToken, "test-token-from-header")
				return &mockAnyRequest{
					Request:  req,
					isClient: false,
				}
			},
			expectedIncomingMDKeys: []string{ctxAuth.ClientIDKey, ctxAuth.AccessTokenKey},
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
		},
		{
			name: "merges with existing incoming metadata",
			setupRequest: func() connect.AnyRequest {
				req := connect.NewRequest(&kas.PublicKeyRequest{})
				req.Header().Set(canonicalIPCHeaderClientID, "merged-client-id")
				req.Header().Set(canonicalIPCHeaderAccessToken, "merged-token")
				return &mockAnyRequest{
					Request:  req,
					isClient: false,
				}
			},
			expectedIncomingMDKeys: []string{ctxAuth.ClientIDKey, ctxAuth.AccessTokenKey},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interceptor := auth.IPCUnaryServerInterceptor()

			ctx := t.Context()
			req := tt.setupRequest()

			mockNext := func(postInterceptorCtx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
				// Verify incoming metadata inside the next function
				require.NotNil(t, postInterceptorCtx)
				md, ok := metadata.FromIncomingContext(postInterceptorCtx)
				if len(tt.expectedIncomingMDKeys) > 0 {
					assert.True(t, ok, "should have incoming metadata")
					for _, key := range tt.expectedIncomingMDKeys {
						assert.NotEmpty(t, md.Get(key), "metadata key %s should exist", key)
					}
				} else {
					assert.Zero(t, md.Len())
				}
				return connect.NewResponse(&kas.PublicKeyResponse{}), nil
			}

			interceptorFunc := interceptor(mockNext)
			_, err := interceptorFunc(ctx, req)

			require.NoError(t, err)
		})
	}
}

func TestIPCMetadataClientInterceptor_ForwardsGenericMetadata(t *testing.T) {
	testLogger := logger.CreateTestLogger()
	interceptor := IPCMetadataClientInterceptor(testLogger)

	// Set up incoming context with generic metadata (simulating what tenant interceptors set)
	md := metadata.New(map[string]string{
		"jwt_tenant_id":  "tenant-abc",
		"host_tenant_id": "tenant-xyz",
		"custom_key":     "custom_value",
	})
	ctx := metadata.NewIncomingContext(t.Context(), md)

	req := connect.NewRequest(&kas.PublicKeyRequest{})
	wrappedReq := &mockAnyRequest{Request: req, isClient: true}

	_, err := interceptor(func(_ context.Context, r connect.AnyRequest) (connect.AnyResponse, error) {
		assert.Equal(t, "tenant-abc", r.Header().Get("X-Ipc-Meta-Jwt_tenant_id"))
		assert.Equal(t, "tenant-xyz", r.Header().Get("X-Ipc-Meta-Host_tenant_id"))
		assert.Equal(t, "custom_value", r.Header().Get("X-Ipc-Meta-Custom_key"))
		return connect.NewResponse(&kas.PublicKeyResponse{}), nil
	})(ctx, wrappedReq)

	require.NoError(t, err)
}

func TestIPCMetadataClientInterceptor_SkipsClientIDAndAccessToken(t *testing.T) {
	testLogger := logger.CreateTestLogger()
	mockToken := jwt.New()
	var mockJWK jwk.Key

	// Set up context with client_id and access_token alongside other metadata
	md := metadata.New(map[string]string{
		ctxAuth.ClientIDKey:    "my-client",
		ctxAuth.AccessTokenKey: "my-token",
		"jwt_tenant_id":        "tenant-abc",
	})
	ctx := ctxAuth.ContextWithAuthNInfo(t.Context(), mockJWK, mockToken, "my-token")
	ctx = metadata.NewIncomingContext(ctx, md)

	interceptor := IPCMetadataClientInterceptor(testLogger)

	req := connect.NewRequest(&kas.PublicKeyRequest{})
	wrappedReq := &mockAnyRequest{Request: req, isClient: true}

	_, err := interceptor(func(_ context.Context, r connect.AnyRequest) (connect.AnyResponse, error) {
		// client_id and access_token should NOT be in x-ipc-meta-* headers (handled separately)
		assert.Empty(t, r.Header().Get("X-Ipc-Meta-Client_id"))
		assert.Empty(t, r.Header().Get("X-Ipc-Meta-Access_token"))
		// jwt_tenant_id should be forwarded
		assert.Equal(t, "tenant-abc", r.Header().Get("X-Ipc-Meta-Jwt_tenant_id"))
		return connect.NewResponse(&kas.PublicKeyResponse{}), nil
	})(ctx, wrappedReq)

	require.NoError(t, err)
}

func TestIPCUnaryServerInterceptor_RestoresGenericMetadata(t *testing.T) {
	testLogger := logger.CreateTestLogger()
	auth := &Authentication{
		logger:          testLogger,
		ipcReauthRoutes: []string{},
	}

	interceptor := auth.IPCUnaryServerInterceptor()

	req := connect.NewRequest(&kas.PublicKeyRequest{})
	req.Header().Set("X-Ipc-Meta-Jwt_tenant_id", "tenant-abc")
	req.Header().Set("X-Ipc-Meta-Host_tenant_id", "tenant-xyz")
	req.Header().Set("X-Ipc-Meta-Custom_key", "custom_value")
	wrappedReq := &mockAnyRequest{Request: req, isClient: false}

	_, err := interceptor(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		require.True(t, ok)
		assert.Equal(t, []string{"tenant-abc"}, md.Get("jwt_tenant_id"))
		assert.Equal(t, []string{"tenant-xyz"}, md.Get("host_tenant_id"))
		assert.Equal(t, []string{"custom_value"}, md.Get("custom_key"))
		return connect.NewResponse(&kas.PublicKeyResponse{}), nil
	})(t.Context(), wrappedReq)

	require.NoError(t, err)
}

func TestIPCMetadata_RoundTrip(t *testing.T) {
	testLogger := logger.CreateTestLogger()

	// 1. Set up the original metadata (as set by tenant interceptors)
	originalMD := metadata.New(map[string]string{
		"jwt_tenant_id":  "tenant-jwt-123",
		"host_tenant_id": "tenant-host-456",
	})
	ctx := metadata.NewIncomingContext(t.Context(), originalMD)

	// 2. Run through client interceptor
	clientInterceptor := IPCMetadataClientInterceptor(testLogger)

	req := connect.NewRequest(&kas.PublicKeyRequest{})
	wrappedReq := &mockAnyRequest{Request: req, isClient: true}

	var capturedHeaders map[string][]string
	_, err := clientInterceptor(func(_ context.Context, r connect.AnyRequest) (connect.AnyResponse, error) {
		capturedHeaders = r.Header().Clone()
		return connect.NewResponse(&kas.PublicKeyResponse{}), nil
	})(ctx, wrappedReq)
	require.NoError(t, err)

	// 3. Simulate server side: create a request with the captured headers
	auth := &Authentication{
		logger:          testLogger,
		ipcReauthRoutes: []string{},
	}
	serverInterceptor := auth.IPCUnaryServerInterceptor()

	serverReq := connect.NewRequest(&kas.PublicKeyRequest{})
	for key, vals := range capturedHeaders {
		for _, v := range vals {
			serverReq.Header().Add(key, v)
		}
	}
	wrappedServerReq := &mockAnyRequest{Request: serverReq, isClient: false}

	_, err = serverInterceptor(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		// 4. Verify the metadata round-tripped correctly
		finalMD, ok := metadata.FromIncomingContext(ctx)
		require.True(t, ok)
		assert.Equal(t, []string{"tenant-jwt-123"}, finalMD.Get("jwt_tenant_id"))
		assert.Equal(t, []string{"tenant-host-456"}, finalMD.Get("host_tenant_id"))
		return connect.NewResponse(&kas.PublicKeyResponse{}), nil
	})(t.Context(), wrappedServerReq)
	require.NoError(t, err)
}

func TestIPCUnaryServerInterceptor_Integration(t *testing.T) {
	testLogger := logger.CreateTestLogger()

	auth := &Authentication{
		logger:          testLogger,
		ipcReauthRoutes: []string{},
	}

	t.Run("clientID and access token from headers available in context metadata", func(t *testing.T) {
		clientID := "integration-client-id"
		accessToken := "integration-access-token"

		req := connect.NewRequest(&kas.PublicKeyRequest{})
		req.Header().Set(canonicalIPCHeaderClientID, clientID)
		req.Header().Set(canonicalIPCHeaderAccessToken, accessToken)

		wrappedReq := &mockAnyRequest{
			Request:  req,
			isClient: false,
		}

		interceptor := auth.IPCUnaryServerInterceptor()

		ctx := t.Context()

		var receivedClientID, receivedAccessToken string
		mockNext := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
			md, ok := metadata.FromIncomingContext(ctx)
			require.True(t, ok)
			clientIDs := md.Get(ctxAuth.ClientIDKey)
			if len(clientIDs) > 0 {
				receivedClientID = clientIDs[0]
			}
			accessTokens := md.Get(ctxAuth.AccessTokenKey)
			if len(accessTokens) > 0 {
				receivedAccessToken = accessTokens[0]
			}
			return connect.NewResponse(&kas.PublicKeyResponse{}), nil
		}

		interceptorFunc := interceptor(mockNext)
		_, err := interceptorFunc(ctx, wrappedReq)

		require.NoError(t, err)
		assert.Equal(t, clientID, receivedClientID)
		assert.Equal(t, accessToken, receivedAccessToken)
	})
}
