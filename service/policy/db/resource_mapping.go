package db

import (
	"context"
	"log/slog"
	"strings"

	"github.com/opentdf/platform/lib/identifier"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/service/pkg/db"
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

	list, err := c.queries.listResourceMappingGroups(ctx, listResourceMappingGroupsParams{
		NamespaceID:  pgtypeUUID(r.GetNamespaceId()),
		NamespaceFqn: pgtypeText(r.GetNamespaceFqn()),
		Limit:        limit,
		Offset:       offset,
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
			Fqn:         rmGroup.Fqn,
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
	rmGroup, err := c.queries.getResourceMappingGroup(ctx, id)
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
		Fqn:         rmGroup.Fqn,
		Metadata:    metadata,
	}, nil
}

func (c PolicyDBClient) CreateResourceMappingGroup(ctx context.Context, r *resourcemapping.CreateResourceMappingGroupRequest) (*policy.ResourceMappingGroup, error) {
	name := strings.ToLower(r.GetName())

	namespaceID, err := c.resolveNamespaceID(ctx, r.GetNamespaceId(), r.GetNamespaceFqn())
	if err != nil {
		return nil, err
	}

	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	createdID, err := c.queries.createResourceMappingGroup(ctx, createResourceMappingGroupParams{
		NamespaceID: namespaceID,
		Name:        name,
		Metadata:    metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return c.GetResourceMappingGroup(ctx, createdID)
}

func (c PolicyDBClient) UpdateResourceMappingGroup(ctx context.Context, id string, r *resourcemapping.UpdateResourceMappingGroupRequest) (*policy.ResourceMappingGroup, error) {
	name := strings.ToLower(r.GetName())

	namespaceID, err := c.resolveNamespaceID(ctx, r.GetNamespaceId(), r.GetNamespaceFqn())
	if err != nil {
		return nil, err
	}

	metadataJSON, _, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		rmGroup, err := c.GetResourceMappingGroup(ctx, id)
		if err != nil {
			return nil, err
		}
		return rmGroup.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	count, err := c.queries.updateResourceMappingGroup(ctx, updateResourceMappingGroupParams{
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

	return c.GetResourceMappingGroup(ctx, id)
}

func (c PolicyDBClient) DeleteResourceMappingGroup(ctx context.Context, id string) (*policy.ResourceMappingGroup, error) {
	rmGroup, err := c.GetResourceMappingGroup(ctx, id)
	if err != nil {
		return nil, err
	}

	count, err := c.queries.deleteResourceMappingGroup(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return rmGroup, nil
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

	list, err := c.queries.listResourceMappings(ctx, listResourceMappingsParams{
		GroupID:      pgtypeUUID(r.GetGroupId()),
		NamespaceID:  pgtypeUUID(r.GetNamespaceId()),
		NamespaceFqn: pgtypeText(r.GetNamespaceFqn()),
		Limit:        limit,
		Offset:       offset,
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

		var resourceMappingGroup *policy.ResourceMappingGroup
		if rm.Group != nil {
			resourceMappingGroup = new(policy.ResourceMappingGroup)
			if err = unmarshalResourceMappingGroup(rm.Group, resourceMappingGroup); err != nil {
				return nil, err
			}
		}

		var namespace *policy.Namespace
		if rm.Namespace != nil {
			namespace = new(policy.Namespace)
			if err = unmarshalNamespace(rm.Namespace, namespace); err != nil {
				return nil, err
			}
		}

		mapping := &policy.ResourceMapping{
			Id:             rm.ID,
			AttributeValue: attributeValue,
			Terms:          rm.Terms,
			Metadata:       metadata,
			Group:          resourceMappingGroup,
			Namespace:      namespace,
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
		fullyQualifiedGroup, err := identifier.Parse[*identifier.FullyQualifiedResourceMappingGroup](fqn)
		if err != nil {
			// invalid FQNs not included in the response - ignore and continue, but log for investigation
			slog.DebugContext(ctx, "error parsing Resource Mapping Group FQN", slog.String("rmg_fqn", fqn))
			continue
		}

		rows, err := c.queries.listResourceMappingsByFullyQualifiedGroup(ctx, listResourceMappingsByFullyQualifiedGroupParams{
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

			var namespace *policy.Namespace
			if row.Namespace != nil {
				namespace = new(policy.Namespace)
				if err := unmarshalNamespace(row.Namespace, namespace); err != nil {
					return nil, err
				}
			}

			mappings[i] = &policy.ResourceMapping{
				Id:             row.ID,
				AttributeValue: value,
				Terms:          row.Terms,
				Metadata:       metadata,
				Namespace:      namespace,
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
	rm, err := c.queries.getResourceMapping(ctx, id)
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

	var resourceMappingGroup *policy.ResourceMappingGroup
	if rm.Group != nil {
		resourceMappingGroup = new(policy.ResourceMappingGroup)
		if err = unmarshalResourceMappingGroup(rm.Group, resourceMappingGroup); err != nil {
			return nil, err
		}
	}

	var namespace *policy.Namespace
	if rm.Namespace != nil {
		namespace = new(policy.Namespace)
		if err = unmarshalNamespace(rm.Namespace, namespace); err != nil {
			return nil, err
		}
	}

	policyRM := &policy.ResourceMapping{
		Id:             rm.ID,
		AttributeValue: attributeValue,
		Terms:          rm.Terms,
		Metadata:       metadata,
		Group:          resourceMappingGroup,
		Namespace:      namespace,
	}

	return policyRM, nil
}

// resolveResourceMappingNamespaceID determines the owning namespace UUID for a
// resource mapping from the optional namespace_id / namespace_fqn fields and the
// optional group it belongs to. A mapping that belongs to a group must share the
// group's namespace, so any explicitly provided namespace must match it (and may
// be omitted to inherit it). The mapped attribute value's namespace is
// independent and intentionally not constrained here, allowing mappings to cross
// namespaces to the attribute values they map. Returns an empty string when the
// mapping has no owning namespace (legacy/global).
// resolveNamespaceID resolves an optional namespace reference provided as either
// a UUID or an FQN to its namespace UUID. Returns an empty string when neither
// is provided.
func (c PolicyDBClient) resolveNamespaceID(ctx context.Context, namespaceID, namespaceFqn string) (string, error) {
	switch {
	case namespaceID != "":
		if !pgtypeUUID(namespaceID).Valid {
			return "", db.ErrUUIDInvalid
		}
		return namespaceID, nil
	case namespaceFqn != "":
		ns, err := c.GetNamespace(ctx, &namespaces.GetNamespaceRequest_Fqn{Fqn: namespaceFqn})
		if err != nil {
			return "", err
		}
		return ns.GetId(), nil
	}
	return "", nil
}

func (c PolicyDBClient) resolveResourceMappingNamespaceID(ctx context.Context, namespaceID, namespaceFqn, groupID string) (string, error) {
	// Resolve any explicitly provided namespace to its UUID.
	namespaceID, err := c.resolveNamespaceID(ctx, namespaceID, namespaceFqn)
	if err != nil {
		return "", err
	}

	// If the mapping belongs to a group, it must live in the group's namespace.
	if groupID != "" {
		group, err := c.GetResourceMappingGroup(ctx, groupID)
		if err != nil {
			return "", db.WrapIfKnownInvalidQueryErr(err)
		}
		groupNamespaceID := group.GetNamespaceId()
		if namespaceID != "" && namespaceID != groupNamespaceID {
			return "", db.ErrNamespaceMismatch
		}
		namespaceID = groupNamespaceID
	}

	return namespaceID, nil
}

func (c PolicyDBClient) CreateResourceMapping(ctx context.Context, r *resourcemapping.CreateResourceMappingRequest) (*policy.ResourceMapping, error) {
	attributeValueID := r.GetAttributeValueId()
	terms := r.GetTerms()
	groupID := r.GetGroupId()
	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	namespaceID, err := c.resolveResourceMappingNamespaceID(ctx, r.GetNamespaceId(), r.GetNamespaceFqn(), groupID)
	if err != nil {
		return nil, err
	}

	createdID, err := c.queries.createResourceMapping(ctx, createResourceMappingParams{
		AttributeValueID: attributeValueID,
		Terms:            terms,
		Metadata:         metadataJSON,
		GroupID:          pgtypeUUID(groupID),
		NamespaceID:      pgtypeUUID(namespaceID),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return c.GetResourceMapping(ctx, createdID)
}

func (c PolicyDBClient) UpdateResourceMapping(ctx context.Context, id string, r *resourcemapping.UpdateResourceMappingRequest) (*policy.ResourceMapping, error) {
	attributeValueID := r.GetAttributeValueId()
	terms := r.GetTerms()
	groupID := r.GetGroupId()
	metadataJSON, _, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		rm, err := c.GetResourceMapping(ctx, id)
		if err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}
		return rm.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	// Determine the group that governs namespace consistency: the group set in
	// this request, or (when only a namespace is being changed) the mapping's
	// existing group.
	effectiveGroupID := groupID
	if effectiveGroupID == "" && (r.GetNamespaceId() != "" || r.GetNamespaceFqn() != "") {
		existing, err := c.GetResourceMapping(ctx, id)
		if err != nil {
			return nil, err
		}
		effectiveGroupID = existing.GetGroup().GetId()
	}

	namespaceID, err := c.resolveResourceMappingNamespaceID(ctx, r.GetNamespaceId(), r.GetNamespaceFqn(), effectiveGroupID)
	if err != nil {
		return nil, err
	}

	count, err := c.queries.updateResourceMapping(ctx, updateResourceMappingParams{
		ID:               id,
		AttributeValueID: pgtypeUUID(attributeValueID),
		Terms:            terms,
		Metadata:         metadataJSON,
		GroupID:          pgtypeUUID(groupID),
		NamespaceID:      pgtypeUUID(namespaceID),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return c.GetResourceMapping(ctx, id)
}

func (c PolicyDBClient) DeleteResourceMapping(ctx context.Context, id string) (*policy.ResourceMapping, error) {
	count, err := c.queries.deleteResourceMapping(ctx, id)
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
