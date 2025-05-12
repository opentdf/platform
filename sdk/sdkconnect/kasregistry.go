package sdkconnect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry/kasregistryconnect"
	"google.golang.org/grpc"
)

// KeyAccessServerRegistry Client
type KeyAccessServerRegistryConnectClient struct {
	kasregistryconnect.KeyAccessServerRegistryServiceClient
}

func NewKeyAccessServerRegistryConnectClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) KeyAccessServerRegistryConnectClient {
	return KeyAccessServerRegistryConnectClient{
		KeyAccessServerRegistryServiceClient: kasregistryconnect.NewKeyAccessServerRegistryServiceClient(httpClient, baseURL, opts...),
	}
}
func (c KeyAccessServerRegistryConnectClient) ListKeyAccessServers(ctx context.Context, req *kasregistry.ListKeyAccessServersRequest, _ ...grpc.CallOption) (*kasregistry.ListKeyAccessServersResponse, error) {
	res, err := c.KeyAccessServerRegistryServiceClient.ListKeyAccessServers(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c KeyAccessServerRegistryConnectClient) GetKeyAccessServer(ctx context.Context, req *kasregistry.GetKeyAccessServerRequest, _ ...grpc.CallOption) (*kasregistry.GetKeyAccessServerResponse, error) {
	res, err := c.KeyAccessServerRegistryServiceClient.GetKeyAccessServer(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c KeyAccessServerRegistryConnectClient) CreateKeyAccessServer(ctx context.Context, req *kasregistry.CreateKeyAccessServerRequest, _ ...grpc.CallOption) (*kasregistry.CreateKeyAccessServerResponse, error) {
	res, err := c.KeyAccessServerRegistryServiceClient.CreateKeyAccessServer(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c KeyAccessServerRegistryConnectClient) UpdateKeyAccessServer(ctx context.Context, req *kasregistry.UpdateKeyAccessServerRequest, _ ...grpc.CallOption) (*kasregistry.UpdateKeyAccessServerResponse, error) {
	res, err := c.KeyAccessServerRegistryServiceClient.UpdateKeyAccessServer(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c KeyAccessServerRegistryConnectClient) DeleteKeyAccessServer(ctx context.Context, req *kasregistry.DeleteKeyAccessServerRequest, _ ...grpc.CallOption) (*kasregistry.DeleteKeyAccessServerResponse, error) {
	res, err := c.KeyAccessServerRegistryServiceClient.DeleteKeyAccessServer(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c KeyAccessServerRegistryConnectClient) ListKeyAccessServerGrants(ctx context.Context, req *kasregistry.ListKeyAccessServerGrantsRequest, _ ...grpc.CallOption) (*kasregistry.ListKeyAccessServerGrantsResponse, error) {
	res, err := c.KeyAccessServerRegistryServiceClient.ListKeyAccessServerGrants(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c KeyAccessServerRegistryConnectClient) CreateKey(ctx context.Context, req *kasregistry.CreateKeyRequest, _ ...grpc.CallOption) (*kasregistry.CreateKeyResponse, error) {
	res, err := c.KeyAccessServerRegistryServiceClient.CreateKey(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c KeyAccessServerRegistryConnectClient) GetKey(ctx context.Context, req *kasregistry.GetKeyRequest, _ ...grpc.CallOption) (*kasregistry.GetKeyResponse, error) {
	res, err := c.KeyAccessServerRegistryServiceClient.GetKey(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c KeyAccessServerRegistryConnectClient) ListKeys(ctx context.Context, req *kasregistry.ListKeysRequest, _ ...grpc.CallOption) (*kasregistry.ListKeysResponse, error) {
	res, err := c.KeyAccessServerRegistryServiceClient.ListKeys(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c KeyAccessServerRegistryConnectClient) UpdateKey(ctx context.Context, req *kasregistry.UpdateKeyRequest, _ ...grpc.CallOption) (*kasregistry.UpdateKeyResponse, error) {
	res, err := c.KeyAccessServerRegistryServiceClient.UpdateKey(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c KeyAccessServerRegistryConnectClient) RotateKey(ctx context.Context, req *kasregistry.RotateKeyRequest, _ ...grpc.CallOption) (*kasregistry.RotateKeyResponse, error) {
	res, err := c.KeyAccessServerRegistryServiceClient.RotateKey(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
