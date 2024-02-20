package db

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/sdk/attributes"
	"github.com/opentdf/platform/sdk/common"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var AttributeValueTable = tableName(TableAttributeValues)

func attributeValueHydrateItem(row pgx.Row) (*attributes.Value, error) {
	var (
		id           string
		value        string
		members      []string
		metadataJson []byte
		attributeId  string
		isActive     bool
	)

	if err := row.Scan(&id, &value, &members, &metadataJson, &attributeId, &isActive); err != nil {
		return nil, WrapIfKnownInvalidQueryErr(err)
	}

	m := &common.Metadata{}
	if metadataJson != nil {
		if err := protojson.Unmarshal(metadataJson, m); err != nil {
			return nil, err
		}
	}

	v := &attributes.Value{
		Id:          id,
		Value:       value,
		Members:     members,
		Metadata:    m,
		AttributeId: attributeId,
		Active:      &wrapperspb.BoolValue{Value: isActive},
	}
	return v, nil
}

///
/// CRUD
///

func createAttributeValueSql(
	attribute_id string,
	value string,
	members []string,
	metadata []byte,
) (string, []interface{}, error) {
	return newStatementBuilder().
		Insert(AttributeValueTable).
		Columns(
			"attribute_definition_id",
			"value",
			"members",
			"metadata",
		).
		Values(
			attribute_id,
			value,
			members,
			metadata,
		).
		Suffix("RETURNING id").
		ToSql()
}

func (c Client) CreateAttributeValue(ctx context.Context, attributeId string, v *attributes.ValueCreateUpdate) (*attributes.Value, error) {
	metadataJson, metadata, err := marshalCreateMetadata(v.Metadata)
	if err != nil {
		return nil, err
	}

	sql, args, err := createAttributeValueSql(
		attributeId,
		v.Value,
		v.Members,
		metadataJson,
	)
	if err != nil {
		return nil, err
	}

	var id string
	if r, err := c.queryRow(ctx, sql, args, err); err != nil {
		return nil, err
	} else if err := r.Scan(&id); err != nil {
		return nil, WrapIfKnownInvalidQueryErr(err)
	}

	rV := &attributes.Value{
		Id:          id,
		AttributeId: attributeId,
		Value:       v.Value,
		Members:     v.Members,
		Metadata:    metadata,
		Active:      &wrapperspb.BoolValue{Value: true},
	}
	return rV, nil
}

func getAttributeValueSql(id string) (string, []interface{}, error) {
	return newStatementBuilder().
		Select(
			Tables.AttributeValues.Field("id"),
			Tables.AttributeValues.Field("value"),
			Tables.AttributeValues.Field("members"),
			Tables.AttributeValues.Field("metadata"),
			Tables.AttributeValues.Field("attribute_definition_id"),
			Tables.AttributeValues.Field("active"),
		).
		From(AttributeValueTable).
		Where(sq.Eq{Tables.AttributeValues.Field("id"): id}).
		ToSql()
}

func (c Client) GetAttributeValue(ctx context.Context, id string) (*attributes.Value, error) {
	sql, args, err := getAttributeValueSql(id)
	row, err := c.queryRow(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}

	v, err := attributeValueHydrateItem(row)
	if err != nil {
		return nil, err
	}

	return v, nil
}

func listAttributeValuesSql(attribute_id string, state string) (string, []interface{}, error) {
	sb := newStatementBuilder().
		Select(
			Tables.AttributeValues.Field("id"),
			Tables.AttributeValues.Field("value"),
			Tables.AttributeValues.Field("members"),
			Tables.AttributeValues.Field("metadata"),
			Tables.AttributeValues.Field("attribute_definition_id"),
			Tables.AttributeValues.Field("active"),
		).
		From(AttributeValueTable)

	where := sq.Eq{}
	if state != StateAny {
		where[Tables.AttributeValues.Field("active")] = state == StateActive
	}
	where[Tables.AttributeValues.Field("attribute_definition_id")] = attribute_id
	return sb.Where(where).ToSql()
}

func (c Client) ListAttributeValues(ctx context.Context, attribute_id string, state string) ([]*attributes.Value, error) {
	sql, args, err := listAttributeValuesSql(attribute_id, state)
	rows, err := c.query(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := make([]*attributes.Value, 0)
	for rows.Next() {
		v, err := attributeValueHydrateItem(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, v)
	}

	return list, nil
}

func updateAttributeValueSql(
	id string,
	value string,
	members []string,
	metadata []byte,
) (string, []interface{}, error) {
	sb := newStatementBuilder().
		Update(AttributeValueTable).
		Set("metadata", metadata)

	if value != "" {
		sb = sb.Set("value", value)
	}
	if members != nil {
		sb = sb.Set("members", members)
	}

	return sb.
		Where(sq.Eq{"id": id}).
		ToSql()
}

func (c Client) UpdateAttributeValue(ctx context.Context, id string, v *attributes.ValueCreateUpdate) (*attributes.Value, error) {
	prev, err := c.GetAttributeValue(ctx, id)
	if err != nil {
		return nil, err
	}

	metadataJson, _, err := marshalUpdateMetadata(prev.Metadata, v.Metadata)
	if err != nil {
		return nil, err
	}

	sql, args, err := updateAttributeValueSql(
		id,
		v.Value,
		v.Members,
		metadataJson,
	)
	if err != nil {
		return nil, err
	}

	if err := c.exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	return prev, nil
}

func deactivateAttributeValueSql(id string) (string, []interface{}, error) {
	return newStatementBuilder().
		Update(AttributeValueTable).
		Set("active", false).
		Where(sq.Eq{Tables.AttributeValues.Field("id"): id}).
		ToSql()
}

func (c Client) DeactivateAttributeValue(ctx context.Context, id string) (*attributes.Value, error) {
	sql, args, err := deactivateAttributeValueSql(id)
	if err := c.exec(ctx, sql, args, err); err != nil {
		return nil, err
	}
	return c.GetAttributeValue(ctx, id)
}

func deleteAttributeValueSql(id string) (string, []interface{}, error) {
	return newStatementBuilder().
		Delete(AttributeValueTable).
		Where(sq.Eq{Tables.AttributeValues.Field("id"): id}).
		ToSql()
}

func (c Client) DeleteAttributeValue(ctx context.Context, id string) (*attributes.Value, error) {
	prev, err := c.GetAttributeValue(ctx, id)
	if err != nil {
		return nil, err
	}

	sql, args, err := deleteAttributeValueSql(id)
	if err := c.exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	return prev, nil
}

func assignKeyAccessServerToValueSql(valueID, keyAccessServerID string) (string, []interface{}, error) {
	t := Tables.AttributeValueKeyAccessGrants
	return newStatementBuilder().
		Insert(t.Name()).
		Columns("attribute_value_id", "key_access_server_id").
		Values(valueID, keyAccessServerID).
		ToSql()
}

func (c Client) AssignKeyAccessServerToValue(ctx context.Context, k *attributes.ValueKeyAccessServer) (*attributes.ValueKeyAccessServer, error) {
	sql, args, err := assignKeyAccessServerToValueSql(k.ValueId, k.KeyAccessServerId)
	if err != nil {
		return nil, err
	}

	if err := c.exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	return k, nil
}

func removeKeyAccessServerFromValueSql(valueID, keyAccessServerID string) (string, []interface{}, error) {
	t := Tables.AttributeValueKeyAccessGrants
	return newStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{"attribute_value_id": valueID, "key_access_server_id": keyAccessServerID}).
		Suffix("IS TRUE RETURNING *").
		ToSql()
}

func (c Client) RemoveKeyAccessServerFromValue(ctx context.Context, k *attributes.ValueKeyAccessServer) (*attributes.ValueKeyAccessServer, error) {
	sql, args, err := removeKeyAccessServerFromValueSql(k.ValueId, k.KeyAccessServerId)
	if err != nil {
		return nil, err
	}

	if _, err := c.queryCount(ctx, sql, args); err != nil {
		return nil, WrapIfKnownInvalidQueryErr(err)
	}

	return k, nil
}
