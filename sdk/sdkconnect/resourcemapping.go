// Wrapper for ResourceMappingServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"context"
	"connectrpc.com/connect"
	"google.golang.org/grpc"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping/resourcemappingconnect"

)

type ResourceMappingServiceClientConnectWrapper struct {
	resourcemappingconnect.ResourceMappingServiceClient
}

func NewResourceMappingServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *ResourceMappingServiceClientConnectWrapper {
	return &ResourceMappingServiceClientConnectWrapper{ResourceMappingServiceClient: resourcemappingconnect.NewResourceMappingServiceClient(httpClient, baseURL, opts...)}
}

func (w *ResourceMappingServiceClientConnectWrapper) ListResourceMappingGroups(ctx context.Context, req *resourcemapping.ListResourceMappingGroupsRequest, _ ...grpc.CallOption) (*resourcemapping.ListResourceMappingGroupsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ResourceMappingServiceClient.ListResourceMappingGroups(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ResourceMappingServiceClientConnectWrapper) GetResourceMappingGroup(ctx context.Context, req *resourcemapping.GetResourceMappingGroupRequest, _ ...grpc.CallOption) (*resourcemapping.GetResourceMappingGroupResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ResourceMappingServiceClient.GetResourceMappingGroup(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ResourceMappingServiceClientConnectWrapper) CreateResourceMappingGroup(ctx context.Context, req *resourcemapping.CreateResourceMappingGroupRequest, _ ...grpc.CallOption) (*resourcemapping.CreateResourceMappingGroupResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ResourceMappingServiceClient.CreateResourceMappingGroup(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ResourceMappingServiceClientConnectWrapper) UpdateResourceMappingGroup(ctx context.Context, req *resourcemapping.UpdateResourceMappingGroupRequest, _ ...grpc.CallOption) (*resourcemapping.UpdateResourceMappingGroupResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ResourceMappingServiceClient.UpdateResourceMappingGroup(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ResourceMappingServiceClientConnectWrapper) DeleteResourceMappingGroup(ctx context.Context, req *resourcemapping.DeleteResourceMappingGroupRequest, _ ...grpc.CallOption) (*resourcemapping.DeleteResourceMappingGroupResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ResourceMappingServiceClient.DeleteResourceMappingGroup(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ResourceMappingServiceClientConnectWrapper) ListResourceMappings(ctx context.Context, req *resourcemapping.ListResourceMappingsRequest, _ ...grpc.CallOption) (*resourcemapping.ListResourceMappingsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ResourceMappingServiceClient.ListResourceMappings(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ResourceMappingServiceClientConnectWrapper) ListResourceMappingsByGroupFqns(ctx context.Context, req *resourcemapping.ListResourceMappingsByGroupFqnsRequest, _ ...grpc.CallOption) (*resourcemapping.ListResourceMappingsByGroupFqnsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ResourceMappingServiceClient.ListResourceMappingsByGroupFqns(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ResourceMappingServiceClientConnectWrapper) GetResourceMapping(ctx context.Context, req *resourcemapping.GetResourceMappingRequest, _ ...grpc.CallOption) (*resourcemapping.GetResourceMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ResourceMappingServiceClient.GetResourceMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ResourceMappingServiceClientConnectWrapper) CreateResourceMapping(ctx context.Context, req *resourcemapping.CreateResourceMappingRequest, _ ...grpc.CallOption) (*resourcemapping.CreateResourceMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ResourceMappingServiceClient.CreateResourceMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ResourceMappingServiceClientConnectWrapper) UpdateResourceMapping(ctx context.Context, req *resourcemapping.UpdateResourceMappingRequest, _ ...grpc.CallOption) (*resourcemapping.UpdateResourceMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ResourceMappingServiceClient.UpdateResourceMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ResourceMappingServiceClientConnectWrapper) DeleteResourceMapping(ctx context.Context, req *resourcemapping.DeleteResourceMappingRequest, _ ...grpc.CallOption) (*resourcemapping.DeleteResourceMappingResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ResourceMappingServiceClient.DeleteResourceMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
