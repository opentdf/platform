package sdkconnect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/keymanagement"
	"github.com/opentdf/platform/protocol/go/policy/keymanagement/keymanagementconnect"
	"google.golang.org/grpc"
)

// KeyManagement Client
type KeyManagementConnectClient struct {
	keymanagementconnect.KeyManagementServiceClient
}

func NewKeyManagementConnectClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) KeyManagementConnectClient {
	return KeyManagementConnectClient{
		KeyManagementServiceClient: keymanagementconnect.NewKeyManagementServiceClient(httpClient, baseURL, opts...),
	}
}

func (c KeyManagementConnectClient) CreateProviderConfig(ctx context.Context, req *keymanagement.CreateProviderConfigRequest, _ ...grpc.CallOption) (*keymanagement.CreateProviderConfigResponse, error) {
	res, err := c.KeyManagementServiceClient.CreateProviderConfig(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c KeyManagementConnectClient) GetProviderConfig(ctx context.Context, req *keymanagement.GetProviderConfigRequest, _ ...grpc.CallOption) (*keymanagement.GetProviderConfigResponse, error) {
	res, err := c.KeyManagementServiceClient.GetProviderConfig(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c KeyManagementConnectClient) ListProviderConfigs(ctx context.Context, req *keymanagement.ListProviderConfigsRequest, _ ...grpc.CallOption) (*keymanagement.ListProviderConfigsResponse, error) {
	res, err := c.KeyManagementServiceClient.ListProviderConfigs(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c KeyManagementConnectClient) UpdateProviderConfig(ctx context.Context, req *keymanagement.UpdateProviderConfigRequest, _ ...grpc.CallOption) (*keymanagement.UpdateProviderConfigResponse, error) {
	res, err := c.KeyManagementServiceClient.UpdateProviderConfig(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c KeyManagementConnectClient) DeleteProviderConfig(ctx context.Context, req *keymanagement.DeleteProviderConfigRequest, _ ...grpc.CallOption) (*keymanagement.DeleteProviderConfigResponse, error) {
	res, err := c.KeyManagementServiceClient.DeleteProviderConfig(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
