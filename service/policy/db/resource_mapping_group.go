package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/resourcemappinggroup"
	"github.com/opentdf/platform/service/pkg/db"
)

func (c PolicyDBClient) ListResourceMappingGroups(ctx context.Context) ([]*policy.ResourceMappingGroup, error) {
	list, err := c.Queries.ListResourceMappingGroups(ctx)
	if err != nil {
		return nil, err
	}

	resourceMappingGroups := make([]*policy.ResourceMappingGroup, len(list))

	for i, rmGroup := range list {
		resourceMappingGroups[i] = &policy.ResourceMappingGroup{
			Id:          rmGroup.ID,
			NamespaceId: rmGroup.NamespaceID,
			Name:        rmGroup.Name,
		}
	}

	return resourceMappingGroups, nil
}

func (c PolicyDBClient) GetResourceMappingGroup(ctx context.Context, id string) (*policy.ResourceMappingGroup, error) {
	rmGroup, err := c.Queries.GetResourceMappingGroup(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.ResourceMappingGroup{
		Id:          rmGroup.ID,
		NamespaceId: rmGroup.NamespaceID,
		Name:        rmGroup.Name,
	}, nil
}

func (c PolicyDBClient) CreateResourceMappingGroup(ctx context.Context, r *resourcemappinggroup.CreateResourceMappingGroupRequest) (*policy.ResourceMappingGroup, error) {
	createdId, err := c.Queries.CreateResourceMappingGroup(ctx, CreateResourceMappingGroupParams{
		NamespaceID: r.GetNamespaceId(),
		Name:        r.GetName(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.ResourceMappingGroup{
		Id: createdId,
	}, nil
}

func (c PolicyDBClient) UpdateResourceMappingGroup(ctx context.Context, id string, r *resourcemappinggroup.UpdateResourceMappingGroupRequest) (*policy.ResourceMappingGroup, error) {
	namespaceID := r.GetNamespaceId()
	var bytes [16]byte
	copy(bytes[:], namespaceID)
	pgNamespaceID := pgtype.UUID{
		Bytes: bytes,
		Valid: namespaceID != "",
	}

	name := r.GetName()
	pgName := pgtype.Text{
		String: name,
		Valid:  name != "",
	}

	createdID, err := c.Queries.UpdateResourceMappingGroup(ctx, UpdateResourceMappingGroupParams{
		ID:          id,
		NamespaceID: pgNamespaceID,
		Name:        pgName,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.ResourceMappingGroup{
		Id: createdID,
	}, nil
}

func (c PolicyDBClient) DeleteResourceMappingGroup(ctx context.Context, id string) (*policy.ResourceMappingGroup, error) {
	count, err := c.Queries.DeleteResourceMappingGroup(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.ResourceMappingGroup{
		Id: id,
	}, nil
}
