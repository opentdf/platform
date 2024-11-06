package db

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func (c PolicyDBClient) CreateAttributeValue(ctx context.Context, attributeID string, r *attributes.CreateAttributeValueRequest) (*policy.Value, error) {
	value := strings.ToLower(r.GetValue())

	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	createdID, err := c.Queries.CreateAttributeValue(ctx, CreateAttributeValueParams{
		AttributeDefinitionID: attributeID,
		Value:                 value,
		Metadata:              metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	// Update FQN
	_, err = c.Queries.UpsertAttributeValueFqn(ctx, createdID)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return c.GetAttributeValue(ctx, createdID)
}

func (c PolicyDBClient) GetAttributeValue(ctx context.Context, id string) (*policy.Value, error) {
	av, err := c.Queries.GetAttributeValue(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadata := &common.Metadata{}
	if err := unmarshalMetadata(av.Metadata, metadata); err != nil {
		return nil, err
	}

	var grants []*policy.KeyAccessServer
	if av.Grants != nil {
		grants, err = db.KeyAccessServerProtoJSON(av.Grants)
		if err != nil {
			c.logger.ErrorContext(ctx, "could not unmarshal key access grants", slog.String("error", err.Error()))
			return nil, err
		}
	}

	return &policy.Value{
		Id:       av.ID,
		Value:    av.Value,
		Active:   &wrapperspb.BoolValue{Value: av.Active},
		Grants:   grants,
		Metadata: metadata,
		Attribute: &policy.Attribute{
			Id: av.AttributeDefinitionID,
		},
		Fqn: av.Fqn.String,
	}, nil
}

func (c PolicyDBClient) ListAttributeValues(ctx context.Context, attributeID string, state string) ([]*policy.Value, error) {
	active := pgtype.Bool{
		Valid: false,
	}

	if state != "" && state != StateAny {
		active = pgtypeBool(state == StateActive)
	}

	list, err := c.Queries.ListAttributeValues(ctx, ListAttributeValuesParams{
		AttributeDefinitionID: attributeID,
		Active:                active,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	attributeValues := make([]*policy.Value, len(list))

	for i, av := range list {
		metadata := &common.Metadata{}
		if err := unmarshalMetadata(av.Metadata, metadata); err != nil {
			return nil, err
		}

		attributeValues[i] = &policy.Value{
			Id:       av.ID,
			Value:    av.Value,
			Active:   &wrapperspb.BoolValue{Value: av.Active},
			Metadata: metadata,
			Attribute: &policy.Attribute{
				Id: av.AttributeDefinitionID,
			},
			Fqn: av.Fqn.String,
		}
	}

	return attributeValues, nil
}

func (c PolicyDBClient) ListAllAttributeValues(ctx context.Context) ([]*policy.Value, error) {
	// call ListAttributeValues method with "empty" param values to make the query return all rows
	return c.ListAttributeValues(ctx, "", StateAny)
}

func (c PolicyDBClient) UpdateAttributeValue(ctx context.Context, r *attributes.UpdateAttributeValueRequest) (*policy.Value, error) {
	id := r.GetId()
	metadataJSON, metadata, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		v, err := c.GetAttributeValue(ctx, id)
		if err != nil {
			return nil, err
		}
		return v.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	count, err := c.Queries.UpdateAttributeValue(ctx, UpdateAttributeValueParams{
		ID:       id,
		Metadata: metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Value{
		Id:       id,
		Metadata: metadata,
	}, nil
}

func (c PolicyDBClient) UnsafeUpdateAttributeValue(ctx context.Context, r *unsafe.UnsafeUpdateAttributeValueRequest) (*policy.Value, error) {
	id := r.GetId()
	value := strings.ToLower(r.GetValue())

	count, err := c.Queries.UpdateAttributeValue(ctx, UpdateAttributeValueParams{
		ID:    id,
		Value: pgtypeText(value),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	// Update FQN
	_, err = c.Queries.UpsertAttributeValueFqn(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return c.GetAttributeValue(ctx, id)
}

func (c PolicyDBClient) DeactivateAttributeValue(ctx context.Context, id string) (*policy.Value, error) {
	count, err := c.Queries.UpdateAttributeValue(ctx, UpdateAttributeValueParams{
		ID:     id,
		Active: pgtypeBool(false),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Value{
		Id:     id,
		Active: &wrapperspb.BoolValue{Value: false},
	}, nil
}

func (c PolicyDBClient) UnsafeReactivateAttributeValue(ctx context.Context, id string) (*policy.Value, error) {
	count, err := c.Queries.UpdateAttributeValue(ctx, UpdateAttributeValueParams{
		ID:     id,
		Active: pgtypeBool(true),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Value{
		Id:     id,
		Active: &wrapperspb.BoolValue{Value: true},
	}, nil
}

func (c PolicyDBClient) UnsafeDeleteAttributeValue(ctx context.Context, toDelete *policy.Value, r *unsafe.UnsafeDeleteAttributeValueRequest) (*policy.Value, error) {
	id := r.GetId()
	fqn := r.GetFqn()

	if fqn != toDelete.GetFqn() {
		return nil, fmt.Errorf("fqn mismatch [%s]: %w", fqn, db.ErrNotFound)
	}

	count, err := c.Queries.DeleteAttributeValue(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Value{
		Id: id,
	}, nil
}

func (c PolicyDBClient) AssignKeyAccessServerToValue(ctx context.Context, k *attributes.ValueKeyAccessServer) (*attributes.ValueKeyAccessServer, error) {
	_, err := c.Queries.AssignKeyAccessServerToAttributeValue(ctx, AssignKeyAccessServerToAttributeValueParams{
		AttributeValueID:  k.GetValueId(),
		KeyAccessServerID: k.GetKeyAccessServerId(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return k, nil
}

func (c PolicyDBClient) RemoveKeyAccessServerFromValue(ctx context.Context, k *attributes.ValueKeyAccessServer) (*attributes.ValueKeyAccessServer, error) {
	count, err := c.Queries.RemoveKeyAccessServerFromAttributeValue(ctx, RemoveKeyAccessServerFromAttributeValueParams{
		AttributeValueID:  k.GetValueId(),
		KeyAccessServerID: k.GetKeyAccessServerId(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return k, nil
}
