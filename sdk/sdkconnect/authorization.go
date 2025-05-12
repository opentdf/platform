package sdkconnect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/authorization/authorizationconnect"
	"google.golang.org/grpc"
)

type AuthorizationConnectClient struct {
	authorizationconnect.AuthorizationServiceClient
}

func NewAuthorizationConnectClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) AuthorizationConnectClient {
	return AuthorizationConnectClient{
		AuthorizationServiceClient: authorizationconnect.NewAuthorizationServiceClient(httpClient, baseURL, opts...),
	}
}
func (c AuthorizationConnectClient) GetDecisions(ctx context.Context, req *authorization.GetDecisionsRequest, _ ...grpc.CallOption) (*authorization.GetDecisionsResponse, error) {
	res, err := c.AuthorizationServiceClient.GetDecisions(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c AuthorizationConnectClient) GetDecisionsByToken(ctx context.Context, req *authorization.GetDecisionsByTokenRequest, _ ...grpc.CallOption) (*authorization.GetDecisionsByTokenResponse, error) {
	res, err := c.AuthorizationServiceClient.GetDecisionsByToken(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
func (c AuthorizationConnectClient) GetEntitlements(ctx context.Context, req *authorization.GetEntitlementsRequest, _ ...grpc.CallOption) (*authorization.GetEntitlementsResponse, error) {
	res, err := c.AuthorizationServiceClient.GetEntitlements(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
