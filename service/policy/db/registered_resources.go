package db

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/opentdf/platform/lib/identifier"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
)

func unmarshalRegisteredResourceValuesProto(valuesJSON []byte, values *[]*policy.RegisteredResourceValue) error {
	if valuesJSON == nil {
		return nil
	}

	raw := []json.RawMessage{}
	if err := json.Unmarshal(valuesJSON, &raw); err != nil {
		return fmt.Errorf("failed to unmarshal values array [%s]: %w", string(valuesJSON), err)
	}

	for _, r := range raw {
		v := &policy.RegisteredResourceValue{}
		if err := protojson.Unmarshal(r, v); err != nil {
			return fmt.Errorf("failed to unmarshal value [%s]: %w", string(r), err)
		}
		*values = append(*values, v)
	}

	return nil
}

func unmarshalRegisteredResourceActionAttributeValuesProto(actionAttrValuesJSON []byte, values *[]*policy.RegisteredResourceValue_ActionAttributeValue) error {
	if actionAttrValuesJSON == nil {
		return nil
	}

	raw := []json.RawMessage{}
	if err := json.Unmarshal(actionAttrValuesJSON, &raw); err != nil {
		return fmt.Errorf("failed to unmarshal action attribute values array [%s]: %w", string(actionAttrValuesJSON), err)
	}

	for _, r := range raw {
		v := &policy.RegisteredResourceValue_ActionAttributeValue{}
		if err := protojson.Unmarshal(r, v); err != nil {
			return fmt.Errorf("failed to unmarshal action attribute value [%s]: %w", string(r), err)
		}
		*values = append(*values, v)
	}

	return nil
}

///
/// Registered Resources
///

func (c PolicyDBClient) CreateRegisteredResource(ctx context.Context, r *registeredresources.CreateRegisteredResourceRequest) (*policy.RegisteredResource, error) {
	name := strings.ToLower(r.GetName())
	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	createdID, err := c.queries.createRegisteredResource(ctx, createRegisteredResourceParams{
		Name:     name,
		Metadata: metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	for _, v := range r.GetValues() {
		req := &registeredresources.CreateRegisteredResourceValueRequest{
			ResourceId: createdID,
			Value:      v,
		}
		_, err := c.CreateRegisteredResourceValue(ctx, req)
		if err != nil {
			return nil, err
		}
	}

	return c.GetRegisteredResource(ctx, &registeredresources.GetRegisteredResourceRequest{
		Identifier: &registeredresources.GetRegisteredResourceRequest_Id{
			Id: createdID,
		},
	})
}

func (c PolicyDBClient) GetRegisteredResource(ctx context.Context, r *registeredresources.GetRegisteredResourceRequest) (*policy.RegisteredResource, error) {
	params := getRegisteredResourceParams{}

	switch {
	case r.GetId() != "":
		params.ID = r.GetId()
	case r.GetName() != "":
		params.Name = strings.ToLower(r.GetName())
	default:
		return nil, db.ErrSelectIdentifierInvalid
	}

	rr, err := c.queries.getRegisteredResource(ctx, params)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadata := &common.Metadata{}
	if err = unmarshalMetadata(rr.Metadata, metadata); err != nil {
		return nil, err
	}

	values := []*policy.RegisteredResourceValue{}
	if err = unmarshalRegisteredResourceValuesProto(rr.Values, &values); err != nil {
		return nil, err
	}

	return &policy.RegisteredResource{
		Id:       rr.ID,
		Name:     rr.Name,
		Metadata: metadata,
		Values:   values,
	}, nil
}

func (c PolicyDBClient) ListRegisteredResources(ctx context.Context, r *registeredresources.ListRegisteredResourcesRequest) (*registeredresources.ListRegisteredResourcesResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	list, err := c.queries.listRegisteredResources(ctx, listRegisteredResourcesParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	rrList := make([]*policy.RegisteredResource, len(list))

	for i, r := range list {
		metadata := &common.Metadata{}
		if err = unmarshalMetadata(r.Metadata, metadata); err != nil {
			return nil, err
		}

		values := []*policy.RegisteredResourceValue{}
		if err = unmarshalRegisteredResourceValuesProto(r.Values, &values); err != nil {
			return nil, err
		}

		rrList[i] = &policy.RegisteredResource{
			Id:       r.ID,
			Name:     r.Name,
			Metadata: metadata,
			Values:   values,
		}
	}

	var total int32
	var nextOffset int32
	if len(list) > 0 {
		total = int32(list[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &registeredresources.ListRegisteredResourcesResponse{
		Resources: rrList,
		Pagination: &policy.PageResponse{
			CurrentOffset: offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

func (c PolicyDBClient) UpdateRegisteredResource(ctx context.Context, r *registeredresources.UpdateRegisteredResourceRequest) (*policy.RegisteredResource, error) {
	id := r.GetId()
	name := strings.ToLower(r.GetName())
	metadataJSON, metadata, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		v, err := c.GetRegisteredResource(ctx, &registeredresources.GetRegisteredResourceRequest{
			Identifier: &registeredresources.GetRegisteredResourceRequest_Id{
				Id: id,
			},
		})
		if err != nil {
			return nil, err
		}
		return v.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	count, err := c.queries.updateRegisteredResource(ctx, updateRegisteredResourceParams{
		ID:       id,
		Name:     pgtypeText(name),
		Metadata: metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.RegisteredResource{
		Id:       id,
		Name:     name,
		Metadata: metadata,
	}, nil
}

func (c PolicyDBClient) DeleteRegisteredResource(ctx context.Context, id string) (*policy.RegisteredResource, error) {
	count, err := c.queries.deleteRegisteredResource(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.RegisteredResource{
		Id: id,
	}, nil
}

///
/// Registered Resource Values
///

func (c PolicyDBClient) CreateRegisteredResourceValue(ctx context.Context, r *registeredresources.CreateRegisteredResourceValueRequest) (*policy.RegisteredResourceValue, error) {
	resourceID := r.GetResourceId()
	value := strings.ToLower(r.GetValue())
	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	createdID, err := c.queries.createRegisteredResourceValue(ctx, createRegisteredResourceValueParams{
		RegisteredResourceID: resourceID,
		Value:                value,
		Metadata:             metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	err = c.createRegisteredResourceActionAttributeValues(ctx, createdID, r.GetActionAttributeValues())
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return c.GetRegisteredResourceValue(ctx, &registeredresources.GetRegisteredResourceValueRequest{
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_Id{
			Id: createdID,
		},
	})
}

func (c PolicyDBClient) GetRegisteredResourceValue(ctx context.Context, r *registeredresources.GetRegisteredResourceValueRequest) (*policy.RegisteredResourceValue, error) {
	params := getRegisteredResourceValueParams{}

	switch {
	case r.GetId() != "":
		params.ID = r.GetId()
	case r.GetFqn() != "":
		fqn := strings.ToLower(r.GetFqn())
		parsed, err := identifier.Parse[*identifier.FullyQualifiedRegisteredResourceValue](fqn)
		if err != nil {
			return nil, err
		}
		params.Name = parsed.Name
		params.Value = parsed.Value
	default:
		// unexpected type
		return nil, db.ErrSelectIdentifierInvalid
	}

	rv, err := c.queries.getRegisteredResourceValue(ctx, params)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadata := &common.Metadata{}
	if err = unmarshalMetadata(rv.Metadata, metadata); err != nil {
		return nil, err
	}

	actionAttrValues := []*policy.RegisteredResourceValue_ActionAttributeValue{}
	if err = unmarshalRegisteredResourceActionAttributeValuesProto(rv.ActionAttributeValues, &actionAttrValues); err != nil {
		return nil, err
	}

	return &policy.RegisteredResourceValue{
		Id:       rv.ID,
		Value:    rv.Value,
		Metadata: metadata,
		Resource: &policy.RegisteredResource{
			Id: rv.RegisteredResourceID,
		},
		ActionAttributeValues: actionAttrValues,
	}, nil
}

func (c PolicyDBClient) GetRegisteredResourceValuesByFQNs(ctx context.Context, r *registeredresources.GetRegisteredResourceValuesByFQNsRequest) (map[string]*policy.RegisteredResourceValue, error) {
	resp := make(map[string]*policy.RegisteredResourceValue)
	count := 0

	for _, fqn := range r.GetFqns() {
		normalizedFQN := strings.ToLower(fqn)

		rv, err := c.GetRegisteredResourceValue(ctx, &registeredresources.GetRegisteredResourceValueRequest{
			Identifier: &registeredresources.GetRegisteredResourceValueRequest_Fqn{
				Fqn: normalizedFQN,
			},
		})
		if err != nil {
			c.logger.ErrorContext(ctx,
				"registered resource value for FQN not found",
				slog.String("fqn", fqn),
				slog.Any("err", err),
			)
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}

		count++

		resp[normalizedFQN] = rv
	}

	if count == 0 {
		return nil, db.ErrNotFound
	}

	return resp, nil
}

func (c PolicyDBClient) ListRegisteredResourceValues(ctx context.Context, r *registeredresources.ListRegisteredResourceValuesRequest) (*registeredresources.ListRegisteredResourceValuesResponse, error) {
	resourceID := r.GetResourceId()
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	list, err := c.queries.listRegisteredResourceValues(ctx, listRegisteredResourceValuesParams{
		RegisteredResourceID: resourceID,
		Limit:                limit,
		Offset:               offset,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	rvList := make([]*policy.RegisteredResourceValue, len(list))

	for i, r := range list {
		metadata := &common.Metadata{}
		if err = unmarshalMetadata(r.Metadata, metadata); err != nil {
			return nil, err
		}

		actionAttrValues := []*policy.RegisteredResourceValue_ActionAttributeValue{}
		if err = unmarshalRegisteredResourceActionAttributeValuesProto(r.ActionAttributeValues, &actionAttrValues); err != nil {
			return nil, err
		}

		rvList[i] = &policy.RegisteredResourceValue{
			Id:       r.ID,
			Value:    r.Value,
			Metadata: metadata,
			Resource: &policy.RegisteredResource{
				Id: r.RegisteredResourceID,
			},
			ActionAttributeValues: actionAttrValues,
		}
	}

	var total int32
	var nextOffset int32
	if len(list) > 0 {
		total = int32(list[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &registeredresources.ListRegisteredResourceValuesResponse{
		Values: rvList,
		Pagination: &policy.PageResponse{
			CurrentOffset: offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

func (c PolicyDBClient) UpdateRegisteredResourceValue(ctx context.Context, r *registeredresources.UpdateRegisteredResourceValueRequest) (*policy.RegisteredResourceValue, error) {
	id := r.GetId()
	value := strings.ToLower(r.GetValue())
	metadataJSON, _, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		v, err := c.GetRegisteredResourceValue(ctx, &registeredresources.GetRegisteredResourceValueRequest{
			Identifier: &registeredresources.GetRegisteredResourceValueRequest_Id{
				Id: id,
			},
		})
		if err != nil {
			return nil, err
		}
		return v.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	count, err := c.queries.updateRegisteredResourceValue(ctx, updateRegisteredResourceValueParams{
		ID:       id,
		Value:    pgtypeText(value),
		Metadata: metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	actionAttrValues := r.GetActionAttributeValues()
	if len(actionAttrValues) > 0 {
		// update overwrites all action attribute values with those provided in the request, so clear all existing ones first
		_, err = c.queries.deleteRegisteredResourceActionAttributeValues(ctx, id)
		if err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}

		err = c.createRegisteredResourceActionAttributeValues(ctx, id, actionAttrValues)
		if err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}
	}

	return c.GetRegisteredResourceValue(ctx, &registeredresources.GetRegisteredResourceValueRequest{
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_Id{
			Id: id,
		},
	})
}

func (c PolicyDBClient) DeleteRegisteredResourceValue(ctx context.Context, id string) (*policy.RegisteredResourceValue, error) {
	count, err := c.queries.deleteRegisteredResourceValue(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.RegisteredResourceValue{
		Id: id,
	}, nil
}

///
/// Registered Resource Action Attribute Values
///

func (c PolicyDBClient) createRegisteredResourceActionAttributeValues(ctx context.Context, registeredResourceValueID string, actionAttrValues []*registeredresources.ActionAttributeValue) error {
	if len(actionAttrValues) == 0 {
		return nil
	}

	createActionAttributeValueParams := make([]createRegisteredResourceActionAttributeValuesParams, len(actionAttrValues))
	var actionID, attributeValueID string
	for i, aav := range actionAttrValues {
		switch identifier := aav.GetActionIdentifier().(type) {
		case *registeredresources.ActionAttributeValue_ActionId:
			actionID = identifier.ActionId
		case *registeredresources.ActionAttributeValue_ActionName:
			a, err := c.queries.getAction(ctx, getActionParams{
				Name: pgtypeText(strings.ToLower(identifier.ActionName)),
			})
			if err != nil {
				return db.WrapIfKnownInvalidQueryErr(err)
			}
			actionID = a.ID
		default:
			return db.ErrSelectIdentifierInvalid
		}

		switch identifier := aav.GetAttributeValueIdentifier().(type) {
		case *registeredresources.ActionAttributeValue_AttributeValueId:
			attributeValueID = identifier.AttributeValueId
		case *registeredresources.ActionAttributeValue_AttributeValueFqn:
			av, err := c.queries.getAttributeValue(ctx, getAttributeValueParams{
				Fqn: pgtypeText(strings.ToLower(identifier.AttributeValueFqn)),
			})
			if err != nil {
				return db.WrapIfKnownInvalidQueryErr(err)
			}
			attributeValueID = av.ID
		default:
			return db.ErrSelectIdentifierInvalid
		}

		createActionAttributeValueParams[i] = createRegisteredResourceActionAttributeValuesParams{
			RegisteredResourceValueID: registeredResourceValueID,
			ActionID:                  actionID,
			AttributeValueID:          attributeValueID,
		}
	}

	count, err := c.queries.createRegisteredResourceActionAttributeValues(ctx, createActionAttributeValueParams)
	if err != nil {
		return db.WrapIfKnownInvalidQueryErr(err)
	}
	if count != int64(len(actionAttrValues)) {
		return fmt.Errorf("failed to create all action attribute values, expected %d, got %d", len(actionAttrValues), count)
	}

	return nil
}
