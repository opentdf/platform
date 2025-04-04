package db

import (
	"context"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
)

func (c PolicyDBClient) GetAction(ctx context.Context, req *actions.GetActionRequest) (*actions.GetActionResponse, error) {
	getActionParams := getActionParams{}
	if req.GetId() != "" {
		getActionParams.ID = pgtypeUUID(req.GetId())
	} else if req.GetName() != "" {
		getActionParams.Name = pgtypeText(req.GetName())
	} else {
		return nil, db.ErrSelectIdentifierInvalid
	}

	got, err := c.Queries.getAction(ctx, getActionParams)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadata := &common.Metadata{}
	if err := protojson.Unmarshal(got.Metadata, metadata); err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &actions.GetActionResponse{
		Action: &policy.Action{
			Id:       got.ID,
			Name:     got.Name,
			Metadata: metadata,
		},
	}, nil
}

func (c PolicyDBClient) ListActions(ctx context.Context, req *actions.ListActionsRequest) (*actions.ListActionsResponse, error) {
	listActionParams := listActionsParams{}

	// Execute the query
	got, err := c.Queries.listActions(ctx, listActionParams)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	// Map the results to the response
	var actionsList []*policy.Action
	for _, action := range got {
		metadata := &common.Metadata{}
		if err := protojson.Unmarshal(action.Metadata, metadata); err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}
		actionsList = append(actionsList, &policy.Action{
			Id:       action.ID,
			Name:     action.Name,
			Metadata: metadata,
		})
	}

	return &actions.ListActionsResponse{
		Actions: actionsList,
	}, nil
}

func (c PolicyDBClient) CreateAction(ctx context.Context, req *actions.CreateActionRequest) (*actions.CreateActionResponse, error) {
	// Define parameters for the query
	createParams := createCustomActionParams{
		ID:       pgtypeUUID(req.GetAction().GetId()),
		Name:     pgtypeText(req.GetAction().GetName()),
		Metadata: protojson.Marshal(req.GetAction().GetMetadata()),
	}

	// Execute the query
	created, err := c.Queries.createCustomAction(ctx, createParams)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &actions.CreateActionResponse{}, nil
}

func (c PolicyDBClient) UpdateAction(ctx context.Context, req *actions.UpdateActionRequest) (*actions.UpdateActionResponse, error) {
	// Define parameters for the query
	updateParams := updateCustomActionParams{
		ID:       pgtypeUUID(req.GetAction().GetId()),
		Name:     pgtypeText(req.GetAction().GetName()),
		Metadata: protojson.Marshal(req.GetAction().GetMetadata()),
	}

	// Execute the query
	updated, err := c.Queries.updateCustomAction(ctx, updateParams)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &actions.UpdateActionResponse{}, nil
}

func (c PolicyDBClient) DeleteAction(ctx context.Context, req *actions.DeleteActionRequest) (*actions.DeleteActionResponse, error) {
	count, err := c.Queries.deleteCustomAction(ctx, req.GetId())
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &actions.DeleteActionResponse{
		Action: &policy.Action{
			Id: req.GetId(),
		},
	}, nil
}
