// Wrapper for AuthorizationServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/authorization/v2/authorizationv2connect"
)

type AuthorizationServiceClientV2ConnectWrapper struct {
	authorizationv2connect.AuthorizationServiceClient
}

func NewAuthorizationServiceClientV2ConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *AuthorizationServiceClientV2ConnectWrapper {
	return &AuthorizationServiceClientV2ConnectWrapper{AuthorizationServiceClient: authorizationv2connect.NewAuthorizationServiceClient(httpClient, baseURL, opts...)}
}

type AuthorizationServiceClientV2 interface {
	GetDecision(ctx context.Context, req *authorizationv2.GetDecisionRequest) (*authorizationv2.GetDecisionResponse, error)
	GetDecisionMultiResource(ctx context.Context, req *authorizationv2.GetDecisionMultiResourceRequest) (*authorizationv2.GetDecisionMultiResourceResponse, error)
	GetDecisionBulk(ctx context.Context, req *authorizationv2.GetDecisionBulkRequest) (*authorizationv2.GetDecisionBulkResponse, error)
	GetEntitlements(ctx context.Context, req *authorizationv2.GetEntitlementsRequest) (*authorizationv2.GetEntitlementsResponse, error)
}

func (w *AuthorizationServiceClientV2ConnectWrapper) GetDecision(ctx context.Context, req *authorizationv2.GetDecisionRequest) (*authorizationv2.GetDecisionResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AuthorizationServiceClient.GetDecision(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AuthorizationServiceClientV2ConnectWrapper) GetDecisionMultiResource(ctx context.Context, req *authorizationv2.GetDecisionMultiResourceRequest) (*authorizationv2.GetDecisionMultiResourceResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AuthorizationServiceClient.GetDecisionMultiResource(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AuthorizationServiceClientV2ConnectWrapper) GetDecisionBulk(ctx context.Context, req *authorizationv2.GetDecisionBulkRequest) (*authorizationv2.GetDecisionBulkResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AuthorizationServiceClient.GetDecisionBulk(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *AuthorizationServiceClientV2ConnectWrapper) GetEntitlements(ctx context.Context, req *authorizationv2.GetEntitlementsRequest) (*authorizationv2.GetEntitlementsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.AuthorizationServiceClient.GetEntitlements(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
