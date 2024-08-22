package db

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func (c PolicyDBClient) CreateAttributeValue(ctx context.Context, attributeID string, r *attributes.CreateAttributeValueRequest) (*policy.Value, error) {
	metadataJSON, metadata, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	createdAv, err := c.Queries.CreateAttributeValue(ctx, CreateAttributeValueParams{
		AttributeDefinitionID: attributeID,
		Value:                 r.GetValue(),
		Metadata:              metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if err = unmarshalMetadata(createdAv.Metadata, metadata, c.logger); err != nil {
		return nil, err
	}

	// Update FQN
	fqn := c.upsertAttrFqn(ctx, attrFqnUpsertOptions{valueID: createdAv.ID})
	if fqn != "" {
		c.logger.Debug("created new attribute value FQN",
			slog.String("value_id", createdAv.ID),
			slog.String("value", createdAv.Value),
			slog.String("fqn", fqn),
		)
	}

	return &policy.Value{
		Id:        createdAv.ID,
		Attribute: &policy.Attribute{Id: attributeID},
		Value:     createdAv.Value,
		Metadata:  metadata,
		Active:    &wrapperspb.BoolValue{Value: true},
	}, nil
}

func (c PolicyDBClient) GetAttributeValue(ctx context.Context, id string) (*policy.Value, error) {
	av, err := c.Queries.GetAttributeValue(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadata := &common.Metadata{}
	if err := unmarshalMetadata(av.Metadata, metadata, c.logger); err != nil {
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
		active = pgtype.Bool{
			Bool:  state == StateActive,
			Valid: true,
		}
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
		if err := unmarshalMetadata(av.Metadata, metadata, c.logger); err != nil {
			return nil, err
		}

		attributeValues[i] = &policy.Value{
			Id:       av.ID,
			Value:    av.Value,
			Active:   &wrapperspb.BoolValue{Value: av.Active},
			Grants:   []*policy.KeyAccessServer{},
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
	metadataJSON, _, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		v, err := c.GetAttributeValue(ctx, r.GetId())
		if err != nil {
			return nil, err
		}
		return v.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	updatedAttrVal, err := c.Queries.UpdateAttributeValue(ctx, UpdateAttributeValueParams{
		ID:       r.GetId(),
		Metadata: metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &policy.Value{
		Id: updatedAttrVal.ID,
	}, nil
}

func (c PolicyDBClient) UnsafeUpdateAttributeValue(ctx context.Context, r *unsafe.UnsafeUpdateAttributeValueRequest) (*policy.Value, error) {
	value := r.GetValue()

	updatedAttrVal, err := c.Queries.UpdateAttributeValue(ctx, UpdateAttributeValueParams{
		ID: r.GetId(),
		Value: pgtype.Text{
			String: value,
			Valid:  value != "",
		},
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	// Update FQN
	fqn := c.upsertAttrFqn(ctx, attrFqnUpsertOptions{valueID: updatedAttrVal.ID})
	c.logger.Debug("upserted fqn for unsafely updated value",
		slog.String("id", updatedAttrVal.ID),
		slog.String("value", updatedAttrVal.Value),
		slog.String("fqn", fqn),
	)

	return c.GetAttributeValue(ctx, updatedAttrVal.ID)
}

func (c PolicyDBClient) DeactivateAttributeValue(ctx context.Context, id string) (*policy.Value, error) {
	updatedAttrVal, err := c.Queries.UpdateAttributeValue(ctx, UpdateAttributeValueParams{
		ID: id,
		Active: pgtype.Bool{
			Bool:  false,
			Valid: true,
		},
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return c.GetAttributeValue(ctx, updatedAttrVal.ID)
}

func (c PolicyDBClient) UnsafeReactivateAttributeValue(ctx context.Context, id string) (*policy.Value, error) {
	updatedAttrVal, err := c.Queries.UpdateAttributeValue(ctx, UpdateAttributeValueParams{
		ID: id,
		Active: pgtype.Bool{
			Bool:  true,
			Valid: true,
		},
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return c.GetAttributeValue(ctx, updatedAttrVal.ID)
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
