// Wrapper for KeyAccessServerRegistryServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry/kasregistryconnect"
	"google.golang.org/grpc"
)

type KeyAccessServerRegistryServiceClientConnectWrapper struct {
	kasregistryconnect.KeyAccessServerRegistryServiceClient
}

func NewKeyAccessServerRegistryServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *KeyAccessServerRegistryServiceClientConnectWrapper {
	return &KeyAccessServerRegistryServiceClientConnectWrapper{KeyAccessServerRegistryServiceClient: kasregistryconnect.NewKeyAccessServerRegistryServiceClient(httpClient, baseURL, opts...)}
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) ListKeyAccessServers(ctx context.Context, req *kasregistry.ListKeyAccessServersRequest, _ ...grpc.CallOption) (*kasregistry.ListKeyAccessServersResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.ListKeyAccessServers(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) GetKeyAccessServer(ctx context.Context, req *kasregistry.GetKeyAccessServerRequest, _ ...grpc.CallOption) (*kasregistry.GetKeyAccessServerResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.GetKeyAccessServer(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) CreateKeyAccessServer(ctx context.Context, req *kasregistry.CreateKeyAccessServerRequest, _ ...grpc.CallOption) (*kasregistry.CreateKeyAccessServerResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.CreateKeyAccessServer(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) UpdateKeyAccessServer(ctx context.Context, req *kasregistry.UpdateKeyAccessServerRequest, _ ...grpc.CallOption) (*kasregistry.UpdateKeyAccessServerResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.UpdateKeyAccessServer(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) DeleteKeyAccessServer(ctx context.Context, req *kasregistry.DeleteKeyAccessServerRequest, _ ...grpc.CallOption) (*kasregistry.DeleteKeyAccessServerResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.DeleteKeyAccessServer(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) ListKeyAccessServerGrants(ctx context.Context, req *kasregistry.ListKeyAccessServerGrantsRequest, _ ...grpc.CallOption) (*kasregistry.ListKeyAccessServerGrantsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.ListKeyAccessServerGrants(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) CreateKey(ctx context.Context, req *kasregistry.CreateKeyRequest, _ ...grpc.CallOption) (*kasregistry.CreateKeyResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.CreateKey(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) GetKey(ctx context.Context, req *kasregistry.GetKeyRequest, _ ...grpc.CallOption) (*kasregistry.GetKeyResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.GetKey(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) ListKeys(ctx context.Context, req *kasregistry.ListKeysRequest, _ ...grpc.CallOption) (*kasregistry.ListKeysResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.ListKeys(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) UpdateKey(ctx context.Context, req *kasregistry.UpdateKeyRequest, _ ...grpc.CallOption) (*kasregistry.UpdateKeyResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.UpdateKey(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) RotateKey(ctx context.Context, req *kasregistry.RotateKeyRequest, _ ...grpc.CallOption) (*kasregistry.RotateKeyResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.RotateKey(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
