// Wrapper for ActionServiceClient (generated code) DO NOT EDIT
package sdkconnect

import (
	"connectrpc.com/connect"
	"context"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/actions/actionsconnect"
	"google.golang.org/grpc"
)

type ActionServiceClientConnectWrapper struct {
	actionsconnect.ActionServiceClient
}

func NewActionServiceClientConnectWrapper(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *ActionServiceClientConnectWrapper {
	return &ActionServiceClientConnectWrapper{ActionServiceClient: actionsconnect.NewActionServiceClient(httpClient, baseURL, opts...)}
}

func (w *ActionServiceClientConnectWrapper) GetAction(ctx context.Context, req *actions.GetActionRequest, _ ...grpc.CallOption) (*actions.GetActionResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ActionServiceClient.GetAction(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ActionServiceClientConnectWrapper) ListActions(ctx context.Context, req *actions.ListActionsRequest, _ ...grpc.CallOption) (*actions.ListActionsResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ActionServiceClient.ListActions(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ActionServiceClientConnectWrapper) CreateAction(ctx context.Context, req *actions.CreateActionRequest, _ ...grpc.CallOption) (*actions.CreateActionResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ActionServiceClient.CreateAction(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ActionServiceClientConnectWrapper) UpdateAction(ctx context.Context, req *actions.UpdateActionRequest, _ ...grpc.CallOption) (*actions.UpdateActionResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ActionServiceClient.UpdateAction(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (w *ActionServiceClientConnectWrapper) DeleteAction(ctx context.Context, req *actions.DeleteActionRequest, _ ...grpc.CallOption) (*actions.DeleteActionResponse, error) {
	// Wrap Connect RPC client request
	res, err := w.ActionServiceClient.DeleteAction(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
