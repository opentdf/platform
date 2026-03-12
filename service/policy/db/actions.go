package db

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
)

type ActionStandard string

const (
	ActionCreate ActionStandard = "create"
	ActionRead   ActionStandard = "read"
	ActionUpdate ActionStandard = "update"
	ActionDelete ActionStandard = "delete"
)

// Add a validation method
func (a ActionStandard) IsValid() bool {
	switch a {
	case ActionCreate, ActionRead, ActionUpdate, ActionDelete:
		return true
	}
	return false
}

// If needed, implement the Stringer interface explicitly
func (a ActionStandard) String() string {
	return string(a)
}

func (c PolicyDBClient) GetAction(ctx context.Context, req *actions.GetActionRequest) (*policy.Action, error) {
	getActionParams := getActionParams{}

	switch {
	case req.GetId() != "":
		getActionParams.ID = pgtypeUUID(req.GetId())
	case req.GetName() != "":
		getActionParams.Name = pgtypeText(strings.ToLower(req.GetName()))
	default:
		return nil, db.ErrSelectIdentifierInvalid
	}

	got, err := c.queries.getAction(ctx, getActionParams)
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

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	list, err := c.queries.listActions(ctx, listActionsParams{
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
		Name:     strings.ToLower(req.GetName()),
		Metadata: metadataJSON,
	}

	createdID, err := c.queries.createCustomAction(ctx, createParams)
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
		return a.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	// Update what fields were patched to update
	updateParams := updateCustomActionParams{
		ID:       req.GetId(),
		Name:     pgtypeText(strings.ToLower(req.GetName())),
		Metadata: metadataJSON,
	}

	count, err := c.queries.updateCustomAction(ctx, updateParams)
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
	count, err := c.queries.deleteCustomAction(ctx, req.GetId())
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	// if did not delete, was either not found or was a standard action
	if count == 0 {
		got, err := c.GetAction(ctx, &actions.GetActionRequest{
			Identifier: &actions.GetActionRequest_Id{
				Id: req.GetId(),
			},
		})
		// not found
		if err != nil && errors.Is(err, db.ErrNotFound) {
			return nil, err
		}
		// standard action
		name := strings.ToLower(got.GetName())
		if ActionStandard(name).IsValid() {
			return nil, fmt.Errorf("cannot delete standard action %s: %w", name, db.ErrRestrictViolation)
		}
		return nil, db.ErrNotFound
	}

	return &policy.Action{
		Id: req.GetId(),
	}, nil
}
