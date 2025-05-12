package sdkconnect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping/resourcemappingconnect"
	"google.golang.org/grpc"
)

// RegisteredResources Client
type ResourceMappingConnectClient struct {
	resourcemappingconnect.ResourceMappingServiceClient
}

func NewResourceMappingConnectClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) ResourceMappingConnectClient {
	return ResourceMappingConnectClient{
		ResourceMappingServiceClient: resourcemappingconnect.NewResourceMappingServiceClient(httpClient, baseURL, opts...),
	}
}

func (c ResourceMappingConnectClient) ListResourceMappingGroups(ctx context.Context, req *resourcemapping.ListResourceMappingGroupsRequest, _ ...grpc.CallOption) (*resourcemapping.ListResourceMappingGroupsResponse, error) {
	res, err := c.ResourceMappingServiceClient.ListResourceMappingGroups(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c ResourceMappingConnectClient) GetResourceMappingGroup(ctx context.Context, req *resourcemapping.GetResourceMappingGroupRequest, _ ...grpc.CallOption) (*resourcemapping.GetResourceMappingGroupResponse, error) {
	res, err := c.ResourceMappingServiceClient.GetResourceMappingGroup(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c ResourceMappingConnectClient) CreateResourceMappingGroup(ctx context.Context, req *resourcemapping.CreateResourceMappingGroupRequest, _ ...grpc.CallOption) (*resourcemapping.CreateResourceMappingGroupResponse, error) {
	res, err := c.ResourceMappingServiceClient.CreateResourceMappingGroup(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c ResourceMappingConnectClient) UpdateResourceMappingGroup(ctx context.Context, req *resourcemapping.UpdateResourceMappingGroupRequest, _ ...grpc.CallOption) (*resourcemapping.UpdateResourceMappingGroupResponse, error) {
	res, err := c.ResourceMappingServiceClient.UpdateResourceMappingGroup(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c ResourceMappingConnectClient) DeleteResourceMappingGroup(ctx context.Context, req *resourcemapping.DeleteResourceMappingGroupRequest, _ ...grpc.CallOption) (*resourcemapping.DeleteResourceMappingGroupResponse, error) {
	res, err := c.ResourceMappingServiceClient.DeleteResourceMappingGroup(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c ResourceMappingConnectClient) ListResourceMappings(ctx context.Context, req *resourcemapping.ListResourceMappingsRequest, _ ...grpc.CallOption) (*resourcemapping.ListResourceMappingsResponse, error) {
	res, err := c.ResourceMappingServiceClient.ListResourceMappings(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c ResourceMappingConnectClient) ListResourceMappingsByGroupFqns(ctx context.Context, req *resourcemapping.ListResourceMappingsByGroupFqnsRequest, _ ...grpc.CallOption) (*resourcemapping.ListResourceMappingsByGroupFqnsResponse, error) {
	res, err := c.ResourceMappingServiceClient.ListResourceMappingsByGroupFqns(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c ResourceMappingConnectClient) GetResourceMapping(ctx context.Context, req *resourcemapping.GetResourceMappingRequest, _ ...grpc.CallOption) (*resourcemapping.GetResourceMappingResponse, error) {
	res, err := c.ResourceMappingServiceClient.GetResourceMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c ResourceMappingConnectClient) CreateResourceMapping(ctx context.Context, req *resourcemapping.CreateResourceMappingRequest, _ ...grpc.CallOption) (*resourcemapping.CreateResourceMappingResponse, error) {
	res, err := c.ResourceMappingServiceClient.CreateResourceMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c ResourceMappingConnectClient) UpdateResourceMapping(ctx context.Context, req *resourcemapping.UpdateResourceMappingRequest, _ ...grpc.CallOption) (*resourcemapping.UpdateResourceMappingResponse, error) {
	res, err := c.ResourceMappingServiceClient.UpdateResourceMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c ResourceMappingConnectClient) DeleteResourceMapping(ctx context.Context, req *resourcemapping.DeleteResourceMappingRequest, _ ...grpc.CallOption) (*resourcemapping.DeleteResourceMappingResponse, error) {
	res, err := c.ResourceMappingServiceClient.DeleteResourceMapping(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
