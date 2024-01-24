package db

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/opentdf-v2-poc/sdk/attributes"
	"github.com/opentdf/opentdf-v2-poc/sdk/common"
	"google.golang.org/protobuf/encoding/protojson"
)

var AttributeValueTable = tableName(TableAttributeValues)

func attributeValueHydrateItem(row pgx.Row) (*attributes.Value, error) {
	var (
		id           string
		value        string
		members      []string
		metadataJson []byte
	)
	if err := row.Scan(&id, &value, &members, &metadataJson); err != nil {
		return nil, err
	}

	m := &common.Metadata{}
	if metadataJson != nil {
		if err := protojson.Unmarshal(metadataJson, m); err != nil {
			return nil, err
		}
	}

	v := &attributes.Value{
		Id:       id,
		Value:    value,
		Members:  members,
		Metadata: m,
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
	metadata []byte) (string, []interface{}, error) {
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
func (c Client) CreateAttributeValue(ctx context.Context, v *attributes.ValueCreate) (*attributes.Value, error) {
	metadataJson, metadata, err := marshalCreateMetadata(v.Metadata)
	if err != nil {
		return nil, err
	}

	sql, args, err := createAttributeValueSql(
		v.AttributeId,
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
		return nil, err
	}

	rV := &attributes.Value{
		Id:       id,
		Value:    v.Value,
		Members:  v.Members,
		Metadata: metadata,
	}
	return rV, nil
}

func getAttributeValueSql(id string) (string, []interface{}, error) {
	return newStatementBuilder().
		Select(
			tableField(AttributeValueTable, "id"),
			tableField(AttributeValueTable, "value"),
			tableField(AttributeValueTable, "members"),
			tableField(AttributeValueTable, "metadata"),
		).
		From(AttributeValueTable).
		Where(sq.Eq{tableField(AttributeValueTable, "id"): id}).
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

func listAttributeValuesSql(attribute_id string) (string, []interface{}, error) {
	return newStatementBuilder().
		Select(
			tableField(AttributeValueTable, "id"),
			tableField(AttributeValueTable, "value"),
			tableField(AttributeValueTable, "members"),
			tableField(AttributeValueTable, "metadata"),
		).
		From(AttributeValueTable).
		Where(sq.Eq{tableField(AttributeValueTable, "attribute_definition_id"): attribute_id}).
		ToSql()
}
func (c Client) ListAttributeValues(ctx context.Context, attribute_id string) ([]*attributes.Value, error) {
	sql, args, err := listAttributeValuesSql(attribute_id)
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
	metadata []byte) (string, []interface{}, error) {
	sb := newStatementBuilder().
		Update(AttributeValueTable)

	if value != "" {
		sb = sb.Set("value", value)
	}
	if members != nil {
		sb = sb.Set("members", members)
	}
	sb.Set("metadata", metadata)

	return sb.
		Where(sq.Eq{"id": id}).
		ToSql()
}
func (c Client) UpdateAttributeValue(ctx context.Context, id string, v *attributes.ValueUpdate) (*attributes.Value, error) {
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

func deleteAttributeValueSql(id string) (string, []interface{}, error) {
	return newStatementBuilder().
		Delete(AttributeValueTable).
		Where(sq.Eq{tableField(AttributeValueTable, "id"): id}).
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
