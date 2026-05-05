package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func (c PolicyDBClient) CreateAttributeValue(ctx context.Context, attributeID string, r *attributes.CreateAttributeValueRequest) (*policy.Value, error) {
	if _, ok := c.queries.db.(pgx.Tx); !ok {
		var createdValue *policy.Value
		err := c.RunInTx(ctx, func(txClient *PolicyDBClient) error {
			var err error
			createdValue, err = txClient.CreateAttributeValue(ctx, attributeID, r)
			return err
		})
		if err != nil {
			return nil, err
		}

		return createdValue, nil
	}

	return c.createAttributeValue(ctx, attributeID, r)
}

func (c PolicyDBClient) createAttributeValue(ctx context.Context, attributeID string, r *attributes.CreateAttributeValueRequest) (*policy.Value, error) {
	value := strings.ToLower(r.GetValue())

	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	createdID, err := c.queries.createAttributeValue(ctx, createAttributeValueParams{
		AttributeDefinitionID: attributeID,
		Value:                 value,
		Metadata:              metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	// Update FQN
	_, err = c.queries.upsertAttributeValueFqn(ctx, createdID)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	attributeNamespaceID := ""
	if len(r.GetObligationTriggers()) > 0 {
		attr, err := c.GetAttribute(ctx, attributeID)
		if err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}
		attributeNamespaceID = attr.GetNamespace().GetId()
	}

	for _, trigger := range r.GetObligationTriggers() {
		_, err = c.createObligationTrigger(ctx, &obligations.AddObligationTriggerRequest{
			ObligationValue: trigger.GetObligationValue(),
			Action:          trigger.GetAction(),
			AttributeValue:  &common.IdFqnIdentifier{Id: createdID},
			Context:         trigger.GetContext(),
		}, attributeNamespaceID)
		if err != nil {
			return nil, err
		}
	}

	return c.GetAttributeValue(ctx, createdID)
}

func (c PolicyDBClient) GetAttributeValue(ctx context.Context, identifier any) (*policy.Value, error) {
	var (
		av     getAttributeValueRow
		err    error
		params getAttributeValueParams
	)

	switch i := identifier.(type) {
	case *attributes.GetAttributeValueRequest_ValueId:
		id := pgtypeUUID(i.ValueId)
		if !id.Valid {
			return nil, db.ErrUUIDInvalid
		}
		params = getAttributeValueParams{ID: id}
	case *attributes.GetAttributeValueRequest_Fqn:
		fqn := pgtypeText(i.Fqn)
		if !fqn.Valid {
			return nil, db.ErrSelectIdentifierInvalid
		}
		params = getAttributeValueParams{Fqn: fqn}
	case string:
		id := pgtypeUUID(i)
		if !id.Valid {
			return nil, db.ErrUUIDInvalid
		}
		params = getAttributeValueParams{ID: pgtypeUUID(i)}
	default:
		// unexpected type
		return nil, errors.Join(db.ErrUnknownSelectIdentifier, fmt.Errorf("type [%T] value [%v]", i, i))
	}

	av, err = c.queries.getAttributeValue(ctx, params)
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

	var keys []*policy.SimpleKasKey
	if av.Keys != nil {
		keys, err = db.SimpleKasKeysProtoJSON(av.Keys)
		if err != nil {
			c.logger.ErrorContext(ctx, "could not unmarshal keys", slog.String("error", err.Error()))
			return nil, err
		}
	}

	obligations, err := unmarshalObligations(av.Obligations)
	if err != nil {
		c.logger.ErrorContext(ctx, "could not unmarshal obligations", slog.String("error", err.Error()))
		return nil, err
	}

	return &policy.Value{
		Id:       av.ID,
		Value:    av.Value,
		Active:   &wrapperspb.BoolValue{Value: av.Active},
		Metadata: metadata,
		Attribute: &policy.Attribute{
			Id: av.AttributeDefinitionID,
		},
		Fqn:         av.Fqn.String,
		Grants:      grants,
		KasKeys:     keys,
		Obligations: obligations,
	}, nil
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

	count, err := c.queries.updateAttributeValue(ctx, updateAttributeValueParams{
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

	count, err := c.queries.updateAttributeValue(ctx, updateAttributeValueParams{
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
	_, err = c.queries.upsertAttributeValueFqn(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return c.GetAttributeValue(ctx, id)
}

func (c PolicyDBClient) DeactivateAttributeValue(ctx context.Context, id string) (*policy.Value, error) {
	count, err := c.queries.updateAttributeValue(ctx, updateAttributeValueParams{
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
	count, err := c.queries.updateAttributeValue(ctx, updateAttributeValueParams{
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

	count, err := c.queries.deleteAttributeValue(ctx, id)
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

func (c PolicyDBClient) RemoveKeyAccessServerFromValue(ctx context.Context, k *attributes.ValueKeyAccessServer) (*attributes.ValueKeyAccessServer, error) { //nolint:staticcheck // Compatibility path for deprecated protobuf type.
	count, err := c.queries.removeKeyAccessServerFromAttributeValue(ctx, removeKeyAccessServerFromAttributeValueParams{
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
	if err := c.verifyKeyIsActive(ctx, k.GetKeyId()); err != nil {
		return nil, err
	}

	vk, err := c.queries.assignPublicKeyToAttributeValue(ctx, assignPublicKeyToAttributeValueParams{
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
	count, err := c.queries.removePublicKeyFromAttributeValue(ctx, removePublicKeyFromAttributeValueParams{
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
