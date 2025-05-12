package sdkconnect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/entityresolution/entityresolutionconnect"
	"google.golang.org/grpc"
)

// EntityResolution Client
type EntityResolutionConnectClient struct {
	entityresolutionconnect.EntityResolutionServiceClient
}

func NewEntityResolutionConnectClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) EntityResolutionConnectClient {
	return EntityResolutionConnectClient{
		EntityResolutionServiceClient: entityresolutionconnect.NewEntityResolutionServiceClient(httpClient, baseURL, opts...),
	}
}

func (c EntityResolutionConnectClient) ResolveEntities(ctx context.Context, req *entityresolution.ResolveEntitiesRequest, _ ...grpc.CallOption) (*entityresolution.ResolveEntitiesResponse, error) {
	res, err := c.EntityResolutionServiceClient.ResolveEntities(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c EntityResolutionConnectClient) CreateEntityChainFromJwt(ctx context.Context, req *entityresolution.CreateEntityChainFromJwtRequest, _ ...grpc.CallOption) (*entityresolution.CreateEntityChainFromJwtResponse, error) {
	res, err := c.EntityResolutionServiceClient.CreateEntityChainFromJwt(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
