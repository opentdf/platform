// Wrapper for AuthorizationServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/authorization/authorizationconnect"
	"google.golang.org/grpc"
)

type AuthorizationServiceClientConnectWrapper struct {
	authorizationconnect.AuthorizationServiceClient
}

func NewAuthorizationServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *AuthorizationServiceClientConnectWrapper {
	return &AuthorizationServiceClientConnectWrapper{AuthorizationServiceClient: authorizationconnect.NewAuthorizationServiceClient(httpClient, baseURL, opts...)}
}

func (w *AuthorizationServiceClientConnectWrapper) GetDecisions(ctx context.Context, req *authorization.GetDecisionsRequest, _ ...grpc.CallOption) (*authorization.GetDecisionsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AuthorizationServiceClient.GetDecisions(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AuthorizationServiceClientConnectWrapper) GetDecisionsByToken(ctx context.Context, req *authorization.GetDecisionsByTokenRequest, _ ...grpc.CallOption) (*authorization.GetDecisionsByTokenResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AuthorizationServiceClient.GetDecisionsByToken(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AuthorizationServiceClientConnectWrapper) GetEntitlements(ctx context.Context, req *authorization.GetEntitlementsRequest, _ ...grpc.CallOption) (*authorization.GetEntitlementsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AuthorizationServiceClient.GetEntitlements(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
