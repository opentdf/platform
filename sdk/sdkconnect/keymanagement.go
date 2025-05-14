// Wrapper for KeyManagementServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"context"
	"connectrpc.com/connect"
	"google.golang.org/grpc"
	"github.com/opentdf/platform/protocol/go/policy/keymanagement"
	"github.com/opentdf/platform/protocol/go/policy/keymanagement/keymanagementconnect"

)

type KeyManagementServiceClientConnectWrapper struct {
	keymanagementconnect.KeyManagementServiceClient
}

func NewKeyManagementServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *KeyManagementServiceClientConnectWrapper {
	return &KeyManagementServiceClientConnectWrapper{KeyManagementServiceClient: keymanagementconnect.NewKeyManagementServiceClient(httpClient, baseURL, opts...)}
}

func (w *KeyManagementServiceClientConnectWrapper) CreateProviderConfig(ctx context.Context, req *keymanagement.CreateProviderConfigRequest, _ ...grpc.CallOption) (*keymanagement.CreateProviderConfigResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyManagementServiceClient.CreateProviderConfig(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyManagementServiceClientConnectWrapper) GetProviderConfig(ctx context.Context, req *keymanagement.GetProviderConfigRequest, _ ...grpc.CallOption) (*keymanagement.GetProviderConfigResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyManagementServiceClient.GetProviderConfig(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyManagementServiceClientConnectWrapper) ListProviderConfigs(ctx context.Context, req *keymanagement.ListProviderConfigsRequest, _ ...grpc.CallOption) (*keymanagement.ListProviderConfigsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyManagementServiceClient.ListProviderConfigs(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyManagementServiceClientConnectWrapper) UpdateProviderConfig(ctx context.Context, req *keymanagement.UpdateProviderConfigRequest, _ ...grpc.CallOption) (*keymanagement.UpdateProviderConfigResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyManagementServiceClient.UpdateProviderConfig(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyManagementServiceClientConnectWrapper) DeleteProviderConfig(ctx context.Context, req *keymanagement.DeleteProviderConfigRequest, _ ...grpc.CallOption) (*keymanagement.DeleteProviderConfigResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyManagementServiceClient.DeleteProviderConfig(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
