package db

import (
	"context"
	"log/slog"
	"strings"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/util"
	"google.golang.org/protobuf/encoding/protojson"
)

/*
	Resource Mapping CRUD
*/

func (c PolicyDBClient) ListResourceMappingGroups(ctx context.Context, r *resourcemapping.ListResourceMappingGroupsRequest) (*resourcemapping.ListResourceMappingGroupsResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	list, err := c.Queries.ListResourceMappingGroups(ctx, ListResourceMappingGroupsParams{
		NamespaceID: r.GetNamespaceId(),
		Limit:       limit,
		Offset:      offset,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	rmGroups := make([]*policy.ResourceMappingGroup, len(list))

	for i, rmGroup := range list {
		metadata := new(common.Metadata)
		if err := unmarshalMetadata(rmGroup.Metadata, metadata); err != nil {
			return nil, err
		}

		rmGroups[i] = &policy.ResourceMappingGroup{
			Id:          rmGroup.ID,
			NamespaceId: rmGroup.NamespaceID,
			Name:        rmGroup.Name,
			Metadata:    metadata,
		}
	}

	var total int32
	var nextOffset int32
	if len(list) > 0 {
		total = int32(list[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &resourcemapping.ListResourceMappingGroupsResponse{
		ResourceMappingGroups: rmGroups,
		Pagination: &policy.PageResponse{
			CurrentOffset: offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

func (c PolicyDBClient) GetResourceMappingGroup(ctx context.Context, id string) (*policy.ResourceMappingGroup, error) {
	rmGroup, err := c.Queries.GetResourceMappingGroup(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadata := new(common.Metadata)
	if err := unmarshalMetadata(rmGroup.Metadata, metadata); err != nil {
		return nil, err
	}

	return &policy.ResourceMappingGroup{
		Id:          rmGroup.ID,
		NamespaceId: rmGroup.NamespaceID,
		Name:        rmGroup.Name,
		Metadata:    metadata,
	}, nil
}

func (c PolicyDBClient) CreateResourceMappingGroup(ctx context.Context, r *resourcemapping.CreateResourceMappingGroupRequest) (*policy.ResourceMappingGroup, error) {
	namespaceID := r.GetNamespaceId()
	name := strings.ToLower(r.GetName())

	metadataJSON, metadata, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	createdID, err := c.Queries.CreateResourceMappingGroup(ctx, CreateResourceMappingGroupParams{
		NamespaceID: namespaceID,
		Name:        name,
		Metadata:    metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.ResourceMappingGroup{
		Id:          createdID,
		NamespaceId: namespaceID,
		Name:        name,
		Metadata:    metadata,
	}, nil
}

func (c PolicyDBClient) UpdateResourceMappingGroup(ctx context.Context, id string, r *resourcemapping.UpdateResourceMappingGroupRequest) (*policy.ResourceMappingGroup, error) {
	namespaceID := r.GetNamespaceId()
	name := strings.ToLower(r.GetName())

	metadataJSON, metadata, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		rmGroup, err := c.GetResourceMappingGroup(ctx, id)
		if err != nil {
			return nil, err
		}
		return rmGroup.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	count, err := c.Queries.UpdateResourceMappingGroup(ctx, UpdateResourceMappingGroupParams{
		ID:          id,
		NamespaceID: pgtypeUUID(namespaceID),
		Name:        pgtypeText(name),
		Metadata:    metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.ResourceMappingGroup{
		Id:          id,
		NamespaceId: namespaceID,
		Name:        name,
		Metadata:    metadata,
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

/*
 Resource Mapping CRUD
*/

func (c PolicyDBClient) ListResourceMappings(ctx context.Context, r *resourcemapping.ListResourceMappingsRequest) (*resourcemapping.ListResourceMappingsResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	list, err := c.Queries.ListResourceMappings(ctx, ListResourceMappingsParams{
		GroupID: r.GetGroupId(),
		Limit:   limit,
		Offset:  offset,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	mappings := make([]*policy.ResourceMapping, len(list))

	for i, rm := range list {
		var (
			metadata       = new(common.Metadata)
			attributeValue = new(policy.Value)
		)

		if err = unmarshalMetadata(rm.Metadata, metadata); err != nil {
			return nil, err
		}

		if err = unmarshalAttributeValue(rm.AttributeValue, attributeValue); err != nil {
			return nil, err
		}

		mapping := &policy.ResourceMapping{
			Id:             rm.ID,
			AttributeValue: attributeValue,
			Terms:          rm.Terms,
			Metadata:       metadata,
		}

		if rm.GroupID != "" {
			mapping.Group = &policy.ResourceMappingGroup{Id: rm.GroupID}
		}

		mappings[i] = mapping
	}

	var total int32
	var nextOffset int32
	if len(list) > 0 {
		total = int32(list[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &resourcemapping.ListResourceMappingsResponse{
		ResourceMappings: mappings,
		Pagination: &policy.PageResponse{
			CurrentOffset: offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

func (c PolicyDBClient) ListResourceMappingsByGroupFqns(ctx context.Context, fqns []string) (map[string]*resourcemapping.ResourceMappingsByGroup, error) {
	resp := make(map[string]*resourcemapping.ResourceMappingsByGroup)
	resultCount := 0

	for _, fqn := range fqns {
		fullyQualifiedGroup, err := util.ParseResourceMappingGroupFqn(fqn)
		if err != nil {
			// invalid FQNs not included in the response - ignore and continue, but log for investigation
			slog.DebugContext(ctx, "error parsing Resource Mapping Group FQN", slog.String("rmg_fqn", fqn))
			continue
		}

		rows, err := c.Queries.ListResourceMappingsByFullyQualifiedGroup(ctx, ListResourceMappingsByFullyQualifiedGroupParams{
			NamespaceName: fullyQualifiedGroup.Namespace,
			GroupName:     fullyQualifiedGroup.GroupName,
		})
		if err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}

		if len(rows) == 0 {
			// no rows found for this FQN - ignore and continue
			continue
		}

		resultCount++

		mappings := make([]*policy.ResourceMapping, len(rows))
		for i, row := range rows {
			metadata := &common.Metadata{}
			if err := unmarshalMetadata(row.Metadata, metadata); err != nil {
				return nil, err
			}

			value := &policy.Value{}
			if err := unmarshalAttributeValue(row.AttributeValue, value); err != nil {
				return nil, err
			}

			mappings[i] = &policy.ResourceMapping{
				Id:             row.ID,
				AttributeValue: value,
				Terms:          row.Terms,
				Metadata:       metadata,
			}
		}

		// all rows will have the same group values, so just use first row for group object population
		group := &policy.ResourceMappingGroup{}
		if err := protojson.Unmarshal(rows[0].Group, group); err != nil {
			return nil, err
		}

		mappingsByGroup := &resourcemapping.ResourceMappingsByGroup{
			Group:    group,
			Mappings: mappings,
		}

		resp[fqn] = mappingsByGroup
	}

	if resultCount == 0 {
		// should return an error if none of the FQNs are found
		return nil, db.ErrNotFound
	}

	return resp, nil
}

func (c PolicyDBClient) GetResourceMapping(ctx context.Context, id string) (*policy.ResourceMapping, error) {
	rm, err := c.Queries.GetResourceMapping(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	var (
		metadata       = new(common.Metadata)
		attributeValue = new(policy.Value)
	)

	if err = unmarshalMetadata(rm.Metadata, metadata); err != nil {
		return nil, err
	}

	if err = unmarshalAttributeValue(rm.AttributeValue, attributeValue); err != nil {
		return nil, err
	}

	policyRM := &policy.ResourceMapping{
		Id:             rm.ID,
		AttributeValue: attributeValue,
		Terms:          rm.Terms,
		Metadata:       metadata,
	}

	if rm.GroupID != "" {
		policyRM.Group = &policy.ResourceMappingGroup{Id: rm.GroupID}
	}

	return policyRM, nil
}

func (c PolicyDBClient) CreateResourceMapping(ctx context.Context, r *resourcemapping.CreateResourceMappingRequest) (*policy.ResourceMapping, error) {
	attributeValueID := r.GetAttributeValueId()
	terms := r.GetTerms()
	groupID := r.GetGroupId()
	metadataJSON, metadata, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	createdID, err := c.Queries.CreateResourceMapping(ctx, CreateResourceMappingParams{
		AttributeValueID: attributeValueID,
		Terms:            terms,
		Metadata:         metadataJSON,
		GroupID:          pgtypeUUID(groupID),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	rm := &policy.ResourceMapping{
		Id:             createdID,
		AttributeValue: &policy.Value{Id: attributeValueID},
		Terms:          terms,
		Metadata:       metadata,
	}

	if groupID != "" {
		rm.Group = &policy.ResourceMappingGroup{Id: groupID}
	}

	return rm, nil
}

func (c PolicyDBClient) UpdateResourceMapping(ctx context.Context, id string, r *resourcemapping.UpdateResourceMappingRequest) (*policy.ResourceMapping, error) {
	attributeValueID := r.GetAttributeValueId()
	terms := r.GetTerms()
	groupID := r.GetGroupId()
	metadataJSON, metadata, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		rm, err := c.GetResourceMapping(ctx, id)
		if err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}
		return rm.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	count, err := c.Queries.UpdateResourceMapping(ctx, UpdateResourceMappingParams{
		ID:               id,
		AttributeValueID: pgtypeUUID(attributeValueID),
		Terms:            terms,
		Metadata:         metadataJSON,
		GroupID:          pgtypeUUID(groupID),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	rm := &policy.ResourceMapping{
		Id:       id,
		Terms:    terms,
		Metadata: metadata,
	}

	if attributeValueID != "" {
		rm.AttributeValue = &policy.Value{Id: attributeValueID}
	}

	if groupID != "" {
		rm.Group = &policy.ResourceMappingGroup{Id: groupID}
	}

	return rm, nil
}

func (c PolicyDBClient) DeleteResourceMapping(ctx context.Context, id string) (*policy.ResourceMapping, error) {
	count, err := c.Queries.DeleteResourceMapping(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.ResourceMapping{
		Id: id,
	}, nil
}
