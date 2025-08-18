// Wrapper for KeyAccessServerRegistryServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry/kasregistryconnect"
)

type KeyAccessServerRegistryServiceClientConnectWrapper struct {
	kasregistryconnect.KeyAccessServerRegistryServiceClient
}

func NewKeyAccessServerRegistryServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *KeyAccessServerRegistryServiceClientConnectWrapper {
	return &KeyAccessServerRegistryServiceClientConnectWrapper{KeyAccessServerRegistryServiceClient: kasregistryconnect.NewKeyAccessServerRegistryServiceClient(httpClient, baseURL, opts...)}
}

type KeyAccessServerRegistryServiceClient interface {
	ListKeyAccessServers(ctx context.Context, req *kasregistry.ListKeyAccessServersRequest) (*kasregistry.ListKeyAccessServersResponse, error)
	GetKeyAccessServer(ctx context.Context, req *kasregistry.GetKeyAccessServerRequest) (*kasregistry.GetKeyAccessServerResponse, error)
	CreateKeyAccessServer(ctx context.Context, req *kasregistry.CreateKeyAccessServerRequest) (*kasregistry.CreateKeyAccessServerResponse, error)
	UpdateKeyAccessServer(ctx context.Context, req *kasregistry.UpdateKeyAccessServerRequest) (*kasregistry.UpdateKeyAccessServerResponse, error)
	DeleteKeyAccessServer(ctx context.Context, req *kasregistry.DeleteKeyAccessServerRequest) (*kasregistry.DeleteKeyAccessServerResponse, error)
	ListKeyAccessServerGrants(ctx context.Context, req *kasregistry.ListKeyAccessServerGrantsRequest) (*kasregistry.ListKeyAccessServerGrantsResponse, error)
	CreateKey(ctx context.Context, req *kasregistry.CreateKeyRequest) (*kasregistry.CreateKeyResponse, error)
	GetKey(ctx context.Context, req *kasregistry.GetKeyRequest) (*kasregistry.GetKeyResponse, error)
	ListKeys(ctx context.Context, req *kasregistry.ListKeysRequest) (*kasregistry.ListKeysResponse, error)
	UpdateKey(ctx context.Context, req *kasregistry.UpdateKeyRequest) (*kasregistry.UpdateKeyResponse, error)
	RotateKey(ctx context.Context, req *kasregistry.RotateKeyRequest) (*kasregistry.RotateKeyResponse, error)
	SetBaseKey(ctx context.Context, req *kasregistry.SetBaseKeyRequest) (*kasregistry.SetBaseKeyResponse, error)
	GetBaseKey(ctx context.Context, req *kasregistry.GetBaseKeyRequest) (*kasregistry.GetBaseKeyResponse, error)
	ListKeyMappings(ctx context.Context, req *kasregistry.ListKeyMappingsRequest) (*kasregistry.ListKeyMappingsResponse, error)
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) ListKeyAccessServers(ctx context.Context, req *kasregistry.ListKeyAccessServersRequest) (*kasregistry.ListKeyAccessServersResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.ListKeyAccessServers(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) GetKeyAccessServer(ctx context.Context, req *kasregistry.GetKeyAccessServerRequest) (*kasregistry.GetKeyAccessServerResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.GetKeyAccessServer(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) CreateKeyAccessServer(ctx context.Context, req *kasregistry.CreateKeyAccessServerRequest) (*kasregistry.CreateKeyAccessServerResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.CreateKeyAccessServer(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) UpdateKeyAccessServer(ctx context.Context, req *kasregistry.UpdateKeyAccessServerRequest) (*kasregistry.UpdateKeyAccessServerResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.UpdateKeyAccessServer(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) DeleteKeyAccessServer(ctx context.Context, req *kasregistry.DeleteKeyAccessServerRequest) (*kasregistry.DeleteKeyAccessServerResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.DeleteKeyAccessServer(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) ListKeyAccessServerGrants(ctx context.Context, req *kasregistry.ListKeyAccessServerGrantsRequest) (*kasregistry.ListKeyAccessServerGrantsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.ListKeyAccessServerGrants(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) CreateKey(ctx context.Context, req *kasregistry.CreateKeyRequest) (*kasregistry.CreateKeyResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.CreateKey(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) GetKey(ctx context.Context, req *kasregistry.GetKeyRequest) (*kasregistry.GetKeyResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.GetKey(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) ListKeys(ctx context.Context, req *kasregistry.ListKeysRequest) (*kasregistry.ListKeysResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.ListKeys(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) UpdateKey(ctx context.Context, req *kasregistry.UpdateKeyRequest) (*kasregistry.UpdateKeyResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.UpdateKey(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) RotateKey(ctx context.Context, req *kasregistry.RotateKeyRequest) (*kasregistry.RotateKeyResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.RotateKey(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) SetBaseKey(ctx context.Context, req *kasregistry.SetBaseKeyRequest) (*kasregistry.SetBaseKeyResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.SetBaseKey(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) GetBaseKey(ctx context.Context, req *kasregistry.GetBaseKeyRequest) (*kasregistry.GetBaseKeyResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.GetBaseKey(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *KeyAccessServerRegistryServiceClientConnectWrapper) ListKeyMappings(ctx context.Context, req *kasregistry.ListKeyMappingsRequest) (*kasregistry.ListKeyMappingsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.KeyAccessServerRegistryServiceClient.ListKeyMappings(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
