// Wrapper for RegisteredResourcesServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources/registeredresourcesconnect"
)

type RegisteredResourcesServiceClientConnectWrapper struct {
	registeredresourcesconnect.RegisteredResourcesServiceClient
}

func NewRegisteredResourcesServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *RegisteredResourcesServiceClientConnectWrapper {
	return &RegisteredResourcesServiceClientConnectWrapper{RegisteredResourcesServiceClient: registeredresourcesconnect.NewRegisteredResourcesServiceClient(httpClient, baseURL, opts...)}
}

type RegisteredResourcesServiceClient interface {
	CreateRegisteredResource(ctx context.Context, req *registeredresources.CreateRegisteredResourceRequest) (*registeredresources.CreateRegisteredResourceResponse, error)
	GetRegisteredResource(ctx context.Context, req *registeredresources.GetRegisteredResourceRequest) (*registeredresources.GetRegisteredResourceResponse, error)
	ListRegisteredResources(ctx context.Context, req *registeredresources.ListRegisteredResourcesRequest) (*registeredresources.ListRegisteredResourcesResponse, error)
	UpdateRegisteredResource(ctx context.Context, req *registeredresources.UpdateRegisteredResourceRequest) (*registeredresources.UpdateRegisteredResourceResponse, error)
	DeleteRegisteredResource(ctx context.Context, req *registeredresources.DeleteRegisteredResourceRequest) (*registeredresources.DeleteRegisteredResourceResponse, error)
	CreateRegisteredResourceValue(ctx context.Context, req *registeredresources.CreateRegisteredResourceValueRequest) (*registeredresources.CreateRegisteredResourceValueResponse, error)
	GetRegisteredResourceValue(ctx context.Context, req *registeredresources.GetRegisteredResourceValueRequest) (*registeredresources.GetRegisteredResourceValueResponse, error)
	GetRegisteredResourceValuesByFQNs(ctx context.Context, req *registeredresources.GetRegisteredResourceValuesByFQNsRequest) (*registeredresources.GetRegisteredResourceValuesByFQNsResponse, error)
	ListRegisteredResourceValues(ctx context.Context, req *registeredresources.ListRegisteredResourceValuesRequest) (*registeredresources.ListRegisteredResourceValuesResponse, error)
	UpdateRegisteredResourceValue(ctx context.Context, req *registeredresources.UpdateRegisteredResourceValueRequest) (*registeredresources.UpdateRegisteredResourceValueResponse, error)
	DeleteRegisteredResourceValue(ctx context.Context, req *registeredresources.DeleteRegisteredResourceValueRequest) (*registeredresources.DeleteRegisteredResourceValueResponse, error)
}

func (w *RegisteredResourcesServiceClientConnectWrapper) CreateRegisteredResource(ctx context.Context, req *registeredresources.CreateRegisteredResourceRequest) (*registeredresources.CreateRegisteredResourceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.RegisteredResourcesServiceClient.CreateRegisteredResource(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *RegisteredResourcesServiceClientConnectWrapper) GetRegisteredResource(ctx context.Context, req *registeredresources.GetRegisteredResourceRequest) (*registeredresources.GetRegisteredResourceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.RegisteredResourcesServiceClient.GetRegisteredResource(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *RegisteredResourcesServiceClientConnectWrapper) ListRegisteredResources(ctx context.Context, req *registeredresources.ListRegisteredResourcesRequest) (*registeredresources.ListRegisteredResourcesResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.RegisteredResourcesServiceClient.ListRegisteredResources(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *RegisteredResourcesServiceClientConnectWrapper) UpdateRegisteredResource(ctx context.Context, req *registeredresources.UpdateRegisteredResourceRequest) (*registeredresources.UpdateRegisteredResourceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.RegisteredResourcesServiceClient.UpdateRegisteredResource(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *RegisteredResourcesServiceClientConnectWrapper) DeleteRegisteredResource(ctx context.Context, req *registeredresources.DeleteRegisteredResourceRequest) (*registeredresources.DeleteRegisteredResourceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.RegisteredResourcesServiceClient.DeleteRegisteredResource(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *RegisteredResourcesServiceClientConnectWrapper) CreateRegisteredResourceValue(ctx context.Context, req *registeredresources.CreateRegisteredResourceValueRequest) (*registeredresources.CreateRegisteredResourceValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.RegisteredResourcesServiceClient.CreateRegisteredResourceValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *RegisteredResourcesServiceClientConnectWrapper) GetRegisteredResourceValue(ctx context.Context, req *registeredresources.GetRegisteredResourceValueRequest) (*registeredresources.GetRegisteredResourceValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.RegisteredResourcesServiceClient.GetRegisteredResourceValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *RegisteredResourcesServiceClientConnectWrapper) GetRegisteredResourceValuesByFQNs(ctx context.Context, req *registeredresources.GetRegisteredResourceValuesByFQNsRequest) (*registeredresources.GetRegisteredResourceValuesByFQNsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.RegisteredResourcesServiceClient.GetRegisteredResourceValuesByFQNs(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *RegisteredResourcesServiceClientConnectWrapper) ListRegisteredResourceValues(ctx context.Context, req *registeredresources.ListRegisteredResourceValuesRequest) (*registeredresources.ListRegisteredResourceValuesResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.RegisteredResourcesServiceClient.ListRegisteredResourceValues(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *RegisteredResourcesServiceClientConnectWrapper) UpdateRegisteredResourceValue(ctx context.Context, req *registeredresources.UpdateRegisteredResourceValueRequest) (*registeredresources.UpdateRegisteredResourceValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.RegisteredResourcesServiceClient.UpdateRegisteredResourceValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *RegisteredResourcesServiceClientConnectWrapper) DeleteRegisteredResourceValue(ctx context.Context, req *registeredresources.DeleteRegisteredResourceValueRequest) (*registeredresources.DeleteRegisteredResourceValueResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.RegisteredResourcesServiceClient.DeleteRegisteredResourceValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
