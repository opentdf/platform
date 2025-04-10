package db

import (
	"context"
	"errors"
	"strings"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/nondataresources"
	"github.com/opentdf/platform/service/pkg/db"
)

///
/// Non Data Resource Groups
///

func (c PolicyDBClient) CreateNonDataResourceGroup(ctx context.Context, r *nondataresources.CreateNonDataResourceGroupRequest) (*policy.NonDataResourceGroup, error) {
	name := strings.ToLower(r.GetName())
	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	createdID, err := c.Queries.CreateNonDataResourceGroup(ctx, CreateNonDataResourceGroupParams{
		Name:     name,
		Metadata: metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return c.GetNonDataResourceGroup(ctx, createdID)
}

func (c PolicyDBClient) GetNonDataResourceGroup(ctx context.Context, identifier any) (*policy.NonDataResourceGroup, error) {
	return nil, errors.New("not implemented")
}

func (c PolicyDBClient) UpdateNonDataResourceGroup(ctx context.Context, r nondataresources.UpdateNonDataResourceGroupRequest) (*policy.NonDataResourceGroup, error) {
	return nil, errors.New("not implemented")
}

func (c PolicyDBClient) ListNonDataResourceGroups(ctx context.Context, r *nondataresources.ListNonDataResourceGroupsRequest) (*nondataresources.ListNonDataResourceGroupsResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	list, err := c.Queries.ListNonDataResourceGroups(ctx, ListNonDataResourceGroupsParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	ndrgList := make([]*policy.NonDataResourceGroup, len(list))
	for i, ndrg := range list {
		metadata := &common.Metadata{}
		if err := unmarshalMetadata(ndrg.Metadata, metadata); err != nil {
			return nil, err
		}

		ndrgList[i] = &policy.NonDataResourceGroup{
			Id:       ndrg.ID,
			Name:     ndrg.Name,
			Metadata: metadata,
		}
	}

	var total int32
	var nextOffset int32
	if len(list) > 0 {
		total = int32(list[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &nondataresources.ListNonDataResourceGroupsResponse{
		Groups: ndrgList,
		Pagination: &policy.PageResponse{
			CurrentOffset: offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

func (c PolicyDBClient) DeleteNonDataResourceGroup(ctx context.Context, id string) (*policy.NonDataResourceGroup, error) {
	count, err := c.Queries.DeleteNonDataResourceGroup(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.NonDataResourceGroup{
		Id: id,
	}, nil
}

///
/// Non Data Resource Values
///

func (c PolicyDBClient) CreateNonDataResourceValue(ctx context.Context, r *nondataresources.CreateNonDataResourceValueRequest) (*policy.NonDataResourceValue, error) {
	return nil, errors.New("not implemented")
}

func (c PolicyDBClient) GetNonDataResourceValue(ctx context.Context, identifier any) (*policy.NonDataResourceValue, error) {
	return nil, errors.New("not implemented")
}

func (c PolicyDBClient) ListNonDataResourceValues(ctx context.Context, r *nondataresources.ListNonDataResourceValuesRequest) (*nondataresources.ListNonDataResourceValuesResponse, error) {
	return nil, errors.New("not implemented")
}

func (c PolicyDBClient) UpdateNonDataResourceValue(ctx context.Context, r *nondataresources.UpdateNonDataResourceValueRequest) (*policy.NonDataResourceValue, error) {
	return nil, errors.New("not implemented")
}

func (c PolicyDBClient) DeleteNonDataResourceValue(ctx context.Context, id string) (*policy.NonDataResourceValue, error) {
	count, err := c.Queries.DeleteNonDataResourceValue(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.NonDataResourceValue{
		Id: id,
	}, nil
}
