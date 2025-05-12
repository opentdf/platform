package sdkconnect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/actions/actionsconnect"
	"google.golang.org/grpc"
)

type ActionsConnectClient struct {
	actionsconnect.ActionServiceClient
}

func NewActionsConnectClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) ActionsConnectClient {
	return ActionsConnectClient{
		ActionServiceClient: actionsconnect.NewActionServiceClient(httpClient, baseURL, opts...),
	}
}

func (c ActionsConnectClient) GetAction(ctx context.Context, req *actions.GetActionRequest, _ ...grpc.CallOption) (*actions.GetActionResponse, error) {
	res, err := c.ActionServiceClient.GetAction(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c ActionsConnectClient) ListActions(ctx context.Context, req *actions.ListActionsRequest, _ ...grpc.CallOption) (*actions.ListActionsResponse, error) {
	res, err := c.ActionServiceClient.ListActions(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c ActionsConnectClient) CreateAction(ctx context.Context, req *actions.CreateActionRequest, _ ...grpc.CallOption) (*actions.CreateActionResponse, error) {
	res, err := c.ActionServiceClient.CreateAction(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c ActionsConnectClient) UpdateAction(ctx context.Context, req *actions.UpdateActionRequest, _ ...grpc.CallOption) (*actions.UpdateActionResponse, error) {
	res, err := c.ActionServiceClient.UpdateAction(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}

func (c ActionsConnectClient) DeleteAction(ctx context.Context, req *actions.DeleteActionRequest, _ ...grpc.CallOption) (*actions.DeleteActionResponse, error) {
	res, err := c.ActionServiceClient.DeleteAction(ctx, connect.NewRequest(req))
	if res == nil {
		return nil, err
	}
	return res.Msg, err
}
