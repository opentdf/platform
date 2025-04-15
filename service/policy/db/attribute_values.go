package db

import (
	"context"
	"errors"
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

func (c PolicyDBClient) GetAttributeValue(ctx context.Context, identifier any) (*policy.Value, error) {
	var (
		av     GetAttributeValueRow
		err    error
		params GetAttributeValueParams
	)

	switch i := identifier.(type) {
	case *attributes.GetAttributeValueRequest_ValueId:
		id := pgtypeUUID(i.ValueId)
		if !id.Valid {
			return nil, db.ErrUUIDInvalid
		}
		params = GetAttributeValueParams{ID: id}
	case *attributes.GetAttributeValueRequest_Fqn:
		fqn := pgtypeText(i.Fqn)
		if !fqn.Valid {
			return nil, db.ErrSelectIdentifierInvalid
		}
		params = GetAttributeValueParams{Fqn: fqn}
	case string:
		id := pgtypeUUID(i)
		if !id.Valid {
			return nil, db.ErrUUIDInvalid
		}
		params = GetAttributeValueParams{ID: pgtypeUUID(i)}
	default:
		// unexpected type
		return nil, errors.Join(db.ErrUnknownSelectIdentifier, fmt.Errorf("type [%T] value [%v]", i, i))
	}

	av, err = c.Queries.GetAttributeValue(ctx, params)
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

	var keys []*policy.AsymmetricKey
	if av.Keys != nil {
		keys, err = db.AsymKeysProtoJSON(av.Keys)
		if err != nil {
			c.logger.ErrorContext(ctx, "could not unmarshal keys", slog.String("error", err.Error()))
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
		Fqn:  av.Fqn.String,
		Keys: keys,
	}, nil
}

func (c PolicyDBClient) ListAttributeValues(ctx context.Context, r *attributes.ListAttributeValuesRequest) (*attributes.ListAttributeValuesResponse, error) {
	state := getDBStateTypeTransformedEnum(r.GetState())
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	active := pgtype.Bool{
		Valid: false,
	}

	if state != stateAny {
		active = pgtypeBool(state == stateActive)
	}

	list, err := c.Queries.ListAttributeValues(ctx, ListAttributeValuesParams{
		AttributeDefinitionID: r.GetAttributeId(),
		Active:                active,
		Limit:                 limit,
		Offset:                offset,
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
	var total int32
	var nextOffset int32
	if len(list) > 0 {
		total = int32(list[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &attributes.ListAttributeValuesResponse{
		Values: attributeValues,
		Pagination: &policy.PageResponse{
			CurrentOffset: offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

// Loads all attribute values into memory by making iterative db roundtrip requests of defaultObjectListAllLimit size
func (c PolicyDBClient) ListAllAttributeValues(ctx context.Context) ([]*policy.Value, error) {
	var nextOffset int32
	valsList := make([]*policy.Value, 0)

	for {
		listed, err := c.ListAttributeValues(ctx, &attributes.ListAttributeValuesRequest{
			State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
			Pagination: &policy.PageRequest{
				Limit:  c.listCfg.limitMax,
				Offset: nextOffset,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list all attributes: %w", err)
		}

		nextOffset = listed.GetPagination().GetNextOffset()
		valsList = append(valsList, listed.GetValues()...)

		// offset becomes zero when list is exhausted
		if nextOffset <= 0 {
			break
		}
	}
	return valsList, nil
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

func (c PolicyDBClient) AssignPublicKeyToValue(ctx context.Context, k *attributes.ValueKey) (*attributes.ValueKey, error) {
	vk, err := c.Queries.assignPublicKeyToAttributeValue(ctx, assignPublicKeyToAttributeValueParams{
		ValueID:              k.GetValueId(),
		KeyAccessServerKeyID: k.GetKeyId(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	return &attributes.ValueKey{
		ValueId: vk.ValueID,
		KeyId:   vk.KeyAccessServerKeyID,
	}, nil
}

func (c PolicyDBClient) RemovePublicKeyFromValue(ctx context.Context, k *attributes.ValueKey) (*attributes.ValueKey, error) {
	count, err := c.Queries.removePublicKeyFromAttributeValue(ctx, removePublicKeyFromAttributeValueParams{
		ValueID:              k.GetValueId(),
		KeyAccessServerKeyID: k.GetKeyId(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &attributes.ValueKey{
		ValueId: k.GetValueId(),
		KeyId:   k.GetKeyId(),
	}, nil
}
