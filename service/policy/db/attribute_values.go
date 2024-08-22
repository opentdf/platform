package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type attributeValueSelectOptions struct {
	state               string
	withFqn             bool
	withKeyAccessGrants bool
	// withSubjectMappings  bool
	// withResourceMappings bool

	// withAttribute                bool
	// withAttributeKeyAccessGrants bool
	// withAttributeNamespace       bool
}

func attributeValueHydrateItem(row pgx.Row, opts attributeValueSelectOptions, logger *logger.Logger) (*policy.Value, error) {
	var (
		id           string
		value        string
		active       bool
		metadataJSON []byte
		attributeID  string
		grants       []byte
		fqn          sql.NullString
	)
	fields := []interface{}{
		&id,
		&value,
		&active,
		&metadataJSON,
		&attributeID,
	}

	if opts.withFqn {
		fields = append(fields, &fqn)
	}
	if opts.withKeyAccessGrants {
		fields = append(fields, &grants)
	}
	err := row.Scan(fields...)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	m := &common.Metadata{}
	if metadataJSON != nil {
		if err := protojson.Unmarshal(metadataJSON, m); err != nil {
			return nil, err
		}
	}

	var k []*policy.KeyAccessServer
	if grants != nil {
		k, err = db.KeyAccessServerProtoJSON(grants)
		if err != nil {
			logger.Error("could not unmarshal key access grants", slog.String("error", err.Error()))
			return nil, err
		}
	}

	v := &policy.Value{
		Id:       id,
		Value:    value,
		Active:   &wrapperspb.BoolValue{Value: active},
		Grants:   k,
		Metadata: m,
		Attribute: &policy.Attribute{
			Id: attributeID,
		},
		Fqn: fqn.String,
	}
	return v, nil
}

func attributeValueHydrateItems(rows pgx.Rows, opts attributeValueSelectOptions, logger *logger.Logger) ([]*policy.Value, error) {
	list := make([]*policy.Value, 0)
	for rows.Next() {
		v, err := attributeValueHydrateItem(rows, opts, logger)
		if err != nil {
			return nil, err
		}
		list = append(list, v)
	}
	return list, nil
}

///
/// CRUD
///

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

func getAttributeValueSQL(id string, opts attributeValueSelectOptions) (string, []interface{}, error) {
	t := Tables.AttributeValues
	fqnT := Tables.AttrFqn
	avkagT := Tables.AttributeValueKeyAccessGrants
	kasrT := Tables.KeyAccessServerRegistry

	fields := []string{
		"av.id",
		"av.value",
		"av.active",
		constructMetadata("av", false),
		"av.attribute_definition_id",
	}
	if opts.withFqn {
		fields = append(fields, fqnT.Field("fqn"))
	}
	if opts.withKeyAccessGrants {
		fields = append(fields,
			"JSONB_AGG("+
				"DISTINCT JSONB_BUILD_OBJECT("+
				"'id',"+kasrT.Field("id")+", "+
				"'uri',"+kasrT.Field("uri")+", "+
				"'public_key',"+kasrT.Field("public_key")+
				")) FILTER (WHERE "+avkagT.Field("attribute_value_id")+" IS NOT NULL) AS grants",
		)
	}

	sb := db.NewStatementBuilder().
		Select(fields...).
		From(t.Name() + " av")

	if opts.withFqn {
		sb = sb.LeftJoin(fqnT.Name() + " ON " + fqnT.Field("value_id") + " = av.id")
		sb = sb.GroupBy(fqnT.WithoutSchema().Field("fqn"))
	}
	if opts.withKeyAccessGrants {
		sb = sb.LeftJoin(avkagT.Name() + " ON " + avkagT.WithoutSchema().Name() + ".attribute_value_id = av.id")
		sb = sb.LeftJoin(kasrT.Name() + " ON " + kasrT.Field("id") + " = " + avkagT.Field("key_access_server_id"))
	}

	return sb.Where(sq.Eq{"av.id": id}).GroupBy("av.id").ToSql()
}

func (c PolicyDBClient) GetAttributeValue(ctx context.Context, id string) (*policy.Value, error) {
	opts := attributeValueSelectOptions{withFqn: true, withKeyAccessGrants: true}
	sql, args, err := getAttributeValueSQL(id, opts)
	if err != nil {
		return nil, err
	}

	row, err := c.QueryRow(ctx, sql, args)
	if err != nil {
		c.logger.Error("error getting attribute value", slog.String("id", id), slog.String("sql", sql), slog.String("error", err.Error()))
		return nil, err
	}

	a, err := attributeValueHydrateItem(row, opts, c.logger)
	if err != nil {
		c.logger.Error("error hydrating attribute value", slog.String("id", id), slog.String("sql", sql), slog.String("error", err.Error()))
		return nil, err
	}
	return a, nil
}

func listAttributeValuesSQL(attributeID string, opts attributeValueSelectOptions) (string, []interface{}, error) {
	t := Tables.AttributeValues
	fqnT := Tables.AttrFqn
	fields := []string{
		"av.id",
		"av.value",
		"av.active",
		constructMetadata("av", false),
		"av.attribute_definition_id",
	}
	if opts.withFqn {
		fields = append(fields, fqnT.Field("fqn"))
	}

	sb := db.NewStatementBuilder().
		Select(fields...)

	if opts.withFqn {
		sb = sb.LeftJoin(fqnT.Name() + " ON " + fqnT.Field("value_id") + " = av.id")
		sb = sb.GroupBy(fqnT.WithoutSchema().Field("fqn"))
	}

	sb = sb.GroupBy("av.id")

	where := sq.Eq{}
	if opts.state != "" && opts.state != StateAny {
		where["av.active"] = opts.state == StateActive
	}
	where["av.attribute_definition_id"] = attributeID

	return sb.
		From(t.Name() + " av").
		Where(where).
		ToSql()
}

func (c PolicyDBClient) ListAttributeValues(ctx context.Context, attributeID string, state string) ([]*policy.Value, error) {
	opts := attributeValueSelectOptions{withFqn: true, state: state}

	sql, args, err := listAttributeValuesSQL(attributeID, opts)
	if err != nil {
		return nil, err
	}

	rows, err := c.Query(ctx, sql, args)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return attributeValueHydrateItems(rows, opts, c.logger)
}

func listAllAttributeValuesSQL(opts attributeValueSelectOptions) (string, []interface{}, error) {
	t := Tables.AttributeValues
	fqnT := Tables.AttrFqn
	fields := []string{
		"av.id",
		"av.value",
		"av.active",
		constructMetadata("av", false),
		"av.attribute_definition_id",
	}
	if opts.withFqn {
		fields = append(fields, fqnT.Field("fqn"))
	}
	sb := db.NewStatementBuilder().
		Select(fields...)

	if opts.withFqn {
		sb = sb.LeftJoin(fqnT.Name() + " ON " + fqnT.Field("value_id") + " = av.id")
		sb = sb.GroupBy(fqnT.WithoutSchema().Field("fqn"))
	}

	sb = sb.GroupBy("av.id")

	return sb.
		From(t.Name() + " av").
		ToSql()
}

func (c PolicyDBClient) ListAllAttributeValues(ctx context.Context, state string) ([]*policy.Value, error) {
	opts := attributeValueSelectOptions{withFqn: true, state: state}
	sql, args, err := listAllAttributeValuesSQL(opts)
	if err != nil {
		return nil, err
	}

	rows, err := c.Query(ctx, sql, args)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return attributeValueHydrateItems(rows, opts, c.logger)
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
