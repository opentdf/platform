package handlers

import (
	"context"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
)

func (h Handler) GetAction(ctx context.Context, id string, name string) (*policy.Action, error) {
	req := &actions.GetActionRequest{}
	if id != "" {
		req.Identifier = &actions.GetActionRequest_Id{
			Id: id,
		}
	} else {
		req.Identifier = &actions.GetActionRequest_Name{
			Name: name,
		}
	}

	resp, err := h.sdk.Actions.GetAction(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.GetAction(), nil
}

func (h Handler) ListActions(ctx context.Context, limit, offset int32) (*actions.ListActionsResponse, error) {
	return h.sdk.Actions.ListActions(ctx, &actions.ListActionsRequest{
		Pagination: &policy.PageRequest{
			Limit:  limit,
			Offset: offset,
		},
	})
}

func (h Handler) CreateAction(ctx context.Context, name string, metadata *common.MetadataMutable) (*policy.Action, error) {
	resp, err := h.sdk.Actions.CreateAction(ctx, &actions.CreateActionRequest{
		Name:     name,
		Metadata: metadata,
	})
	if err != nil {
		return nil, err
	}

	return resp.GetAction(), nil
}

func (h Handler) UpdateAction(ctx context.Context, id, name string, metadata *common.MetadataMutable, behavior common.MetadataUpdateEnum) (*policy.Action, error) {
	_, err := h.sdk.Actions.UpdateAction(ctx, &actions.UpdateActionRequest{
		Id:                     id,
		Metadata:               metadata,
		Name:                   name,
		MetadataUpdateBehavior: behavior,
	})
	if err != nil {
		return nil, err
	}
	return h.GetAction(ctx, id, "")
}

func (h Handler) DeleteAction(ctx context.Context, id string) error {
	_, err := h.sdk.Actions.DeleteAction(ctx, &actions.DeleteActionRequest{
		Id: id,
	})
	return err
}
