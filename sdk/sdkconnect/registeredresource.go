package sdkconnect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources/registeredresourcesconnect"
	"google.golang.org/grpc"
)

// RegisteredResources Client
type RegisteredResourcesConnectClient struct {
	registeredresourcesconnect.RegisteredResourcesServiceClient
}

func NewRegisteredResourcesConnectClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) RegisteredResourcesConnectClient {
	return RegisteredResourcesConnectClient{
		RegisteredResourcesServiceClient: registeredresourcesconnect.NewRegisteredResourcesServiceClient(httpClient, baseURL, opts...),
	}
}
func (c RegisteredResourcesConnectClient) CreateRegisteredResource(ctx context.Context, req *registeredresources.CreateRegisteredResourceRequest, _ ...grpc.CallOption) (*registeredresources.CreateRegisteredResourceResponse, error) {
	res, err := c.RegisteredResourcesServiceClient.CreateRegisteredResource(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c RegisteredResourcesConnectClient) GetRegisteredResource(ctx context.Context, req *registeredresources.GetRegisteredResourceRequest, _ ...grpc.CallOption) (*registeredresources.GetRegisteredResourceResponse, error) {
	res, err := c.RegisteredResourcesServiceClient.GetRegisteredResource(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c RegisteredResourcesConnectClient) ListRegisteredResources(ctx context.Context, req *registeredresources.ListRegisteredResourcesRequest, _ ...grpc.CallOption) (*registeredresources.ListRegisteredResourcesResponse, error) {
	res, err := c.RegisteredResourcesServiceClient.ListRegisteredResources(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c RegisteredResourcesConnectClient) UpdateRegisteredResource(ctx context.Context, req *registeredresources.UpdateRegisteredResourceRequest, _ ...grpc.CallOption) (*registeredresources.UpdateRegisteredResourceResponse, error) {
	res, err := c.RegisteredResourcesServiceClient.UpdateRegisteredResource(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c RegisteredResourcesConnectClient) DeleteRegisteredResource(ctx context.Context, req *registeredresources.DeleteRegisteredResourceRequest, _ ...grpc.CallOption) (*registeredresources.DeleteRegisteredResourceResponse, error) {
	res, err := c.RegisteredResourcesServiceClient.DeleteRegisteredResource(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c RegisteredResourcesConnectClient) CreateRegisteredResourceValue(ctx context.Context, req *registeredresources.CreateRegisteredResourceValueRequest, _ ...grpc.CallOption) (*registeredresources.CreateRegisteredResourceValueResponse, error) {
	res, err := c.RegisteredResourcesServiceClient.CreateRegisteredResourceValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c RegisteredResourcesConnectClient) GetRegisteredResourceValue(ctx context.Context, req *registeredresources.GetRegisteredResourceValueRequest, _ ...grpc.CallOption) (*registeredresources.GetRegisteredResourceValueResponse, error) {
	res, err := c.RegisteredResourcesServiceClient.GetRegisteredResourceValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c RegisteredResourcesConnectClient) GetRegisteredResourceValuesByFQNs(ctx context.Context, req *registeredresources.GetRegisteredResourceValuesByFQNsRequest, _ ...grpc.CallOption) (*registeredresources.GetRegisteredResourceValuesByFQNsResponse, error) {
	res, err := c.RegisteredResourcesServiceClient.GetRegisteredResourceValuesByFQNs(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c RegisteredResourcesConnectClient) ListRegisteredResourceValues(ctx context.Context, req *registeredresources.ListRegisteredResourceValuesRequest, _ ...grpc.CallOption) (*registeredresources.ListRegisteredResourceValuesResponse, error) {
	res, err := c.RegisteredResourcesServiceClient.ListRegisteredResourceValues(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c RegisteredResourcesConnectClient) UpdateRegisteredResourceValue(ctx context.Context, req *registeredresources.UpdateRegisteredResourceValueRequest, _ ...grpc.CallOption) (*registeredresources.UpdateRegisteredResourceValueResponse, error) {
	res, err := c.RegisteredResourcesServiceClient.UpdateRegisteredResourceValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c RegisteredResourcesConnectClient) DeleteRegisteredResourceValue(ctx context.Context, req *registeredresources.DeleteRegisteredResourceValueRequest, _ ...grpc.CallOption) (*registeredresources.DeleteRegisteredResourceValueResponse, error) {
	res, err := c.RegisteredResourcesServiceClient.DeleteRegisteredResourceValue(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
