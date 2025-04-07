package db

import (
	"context"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
)

func (c PolicyDBClient) GetAction(ctx context.Context, req *actions.GetActionRequest) (*policy.Action, error) {
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

	return &policy.Action{
		Id:       got.ID,
		Name:     got.Name,
		Metadata: metadata,
	}, nil
}

func (c PolicyDBClient) ListActions(ctx context.Context, req *actions.ListActionsRequest) (*actions.ListActionsResponse, error) {
	limit, offset := c.getRequestedLimitOffset(req.GetPagination())

	list, err := c.Queries.listActions(ctx, listActionsParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	var (
		actionsStandard []*policy.Action
		actionsCustom   []*policy.Action
	)
	for _, a := range list {
		metadata := &common.Metadata{}
		if err := unmarshalMetadata(a.Metadata, metadata); err != nil {
			return nil, err
		}
		action := &policy.Action{
			Id:       a.ID,
			Name:     a.Name,
			Metadata: metadata,
		}
		if a.IsStandard {
			actionsStandard = append(actionsStandard, action)
		} else {
			actionsCustom = append(actionsCustom, action)
		}
	}

	var total int32
	var nextOffset int32
	if len(list) > 0 {
		total = int32(list[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &actions.ListActionsResponse{
		ActionsStandard: actionsStandard,
		ActionsCustom:   actionsCustom,
		Pagination: &policy.PageResponse{
			CurrentOffset: offset,
			NextOffset:    nextOffset,
			Total:         total,
		},
	}, nil
}

func (c PolicyDBClient) CreateAction(ctx context.Context, req *actions.CreateActionRequest) (*policy.Action, error) {
	metadataJSON, _, err := db.MarshalCreateMetadata(req.GetMetadata())
	if err != nil {
		return nil, err
	}
	createParams := createCustomActionParams{
		Name:     req.GetName(),
		Metadata: metadataJSON,
	}

	createdID, err := c.Queries.createCustomAction(ctx, createParams)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return c.GetAction(ctx, &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Id{
			Id: createdID,
		},
	})
}

func (c PolicyDBClient) UpdateAction(ctx context.Context, req *actions.UpdateActionRequest) (*policy.Action, error) {
	// if extend we need to merge the metadata
	metadataJSON, metadata, err := db.MarshalUpdateMetadata(req.GetMetadata(), req.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		a, err := c.GetAction(ctx, &actions.GetActionRequest{
			Identifier: &actions.GetActionRequest_Id{
				Id: req.GetId(),
			},
		})
		if err != nil {
			return nil, err
		}
		if a.GetMetadata() == nil {
			return nil, nil //nolint:nilnil // no metadata does not mean no error
		}
		return a.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	// Update what fields were patched to update
	updateParams := updateCustomActionParams{
		ID: req.GetId(),
	}
	if metadataJSON != nil {
		updateParams.Metadata = metadataJSON
	}
	if req.GetName() != "" {
		updateParams.Name = pgtypeText(req.GetName())
	}

	count, err := c.Queries.updateCustomAction(ctx, updateParams)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Action{
		Id:       req.GetId(),
		Name:     req.GetName(),
		Metadata: metadata,
	}, nil
}

func (c PolicyDBClient) DeleteAction(ctx context.Context, req *actions.DeleteActionRequest) (*policy.Action, error) {
	count, err := c.Queries.deleteCustomAction(ctx, req.GetId())
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Action{
		Id: req.GetId(),
	}, nil
}
