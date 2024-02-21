package db

import (
	"context"
	"database/sql"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/sdk/attributes"
	"github.com/opentdf/platform/sdk/common"
	"golang.org/x/exp/slog"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type attributeValueSelectOptions struct {
	withFqn bool
	state   string
}

func attributeValueHydrateItem(row pgx.Row, opts attributeValueSelectOptions) (*attributes.Value, error) {
	var (
		id           string
		value        string
		active       bool
		members      []string
		metadataJson []byte
		attributeId  string
		fqn          sql.NullString
	)

	fields := []interface{}{
		&id,
		&value,
		&active,
		&members,
		&metadataJson,
		&attributeId,
	}
	if opts.withFqn {
		fields = append(fields, &fqn)
	}

	if err := row.Scan(fields...); err != nil {
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
		Active:      &wrapperspb.BoolValue{Value: active},
		Members:     members,
		Metadata:    m,
		AttributeId: attributeId,
		Fqn:         fqn.String,
	}
	return v, nil
}

func attributeValueHydrateItems(rows pgx.Rows, opts attributeValueSelectOptions) ([]*attributes.Value, error) {
	list := make([]*attributes.Value, 0)
	for rows.Next() {
		v, err := attributeValueHydrateItem(rows, opts)
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

func createAttributeValueSql(
	attribute_id string,
	value string,
	members []string,
	metadata []byte,
) (string, []interface{}, error) {
	t := Tables.AttributeValues
	return newStatementBuilder().
		Insert(t.Name()).
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

	// Update FQN
	c.upsertAttrFqn(ctx, attrFqnUpsertOptions{valueId: id})

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

func getAttributeValueSql(id string, opts attributeValueSelectOptions) (string, []interface{}, error) {
	t := Tables.AttributeValues
	fields := []string{
		t.Field("id"),
		t.Field("value"),
		t.Field("active"),
		t.Field("members"),
		t.Field("metadata"),
		t.Field("attribute_definition_id"),
	}
	if opts.withFqn {
		fields = append(fields, Tables.AttrFqn.Field("fqn"))
	}

	sb := newStatementBuilder().
		Select(fields...).
		From(t.Name())

	if opts.withFqn {
		sb = sb.LeftJoin(Tables.AttrFqn.Name() + " ON " + Tables.AttrFqn.Field("value_id") + " = " + t.Field("id"))
	}

	return sb.Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c Client) GetAttributeValue(ctx context.Context, id string) (*attributes.Value, error) {
	opts := attributeValueSelectOptions{withFqn: true}
	sql, args, err := getAttributeValueSql(id, opts)
	row, err := c.queryRow(ctx, sql, args, err)
	if err != nil {
		slog.Error("error getting attribute value", slog.String("id", id), slog.String("sql", sql), slog.String("error", err.Error()))
		return nil, err
	}

	a, err := attributeValueHydrateItem(row, opts)
	if err != nil {
		slog.Error("error hydrating attribute value", slog.String("id", id), slog.String("sql", sql), slog.String("error", err.Error()))
		return nil, err
	}
	return a, nil
}

func listAttributeValuesSql(attribute_id string, opts attributeValueSelectOptions) (string, []interface{}, error) {
	t := Tables.AttributeValues
	fields := []string{
		t.Field("id"),
		t.Field("value"),
		t.Field("active"),
		t.Field("members"),
		t.Field("metadata"),
		t.Field("attribute_definition_id"),
	}
	if opts.withFqn {
		fields = append(fields, "fqn")
	}

	sb := newStatementBuilder().
		Select(fields...)

	if opts.withFqn {
		sb = sb.LeftJoin(Tables.AttrFqn.Name() + " ON " + Tables.AttrFqn.Field("value_id") + " = " + t.Field("id"))
	}

	where := sq.Eq{}
	if opts.state != "" && opts.state != StateAny {
		where[t.Field("active")] = opts.state == StateActive
	}
	where[t.Field("attribute_definition_id")] = attribute_id

	return sb.
		From(t.Name()).
		Where(where).
		ToSql()
}

func (c Client) ListAttributeValues(ctx context.Context, attribute_id string, state string) ([]*attributes.Value, error) {
	opts := attributeValueSelectOptions{withFqn: true, state: state}

	sql, args, err := listAttributeValuesSql(attribute_id, opts)
	rows, err := c.query(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return attributeValueHydrateItems(rows, opts)
}

func listAllAttributeValuesSql(opts attributeValueSelectOptions) (string, []interface{}, error) {
	t := Tables.AttributeValues
	fields := []string{
		t.Field("id"),
		t.Field("value"),
		t.Field("active"),
		t.Field("members"),
		t.Field("metadata"),
		t.Field("attribute_definition_id"),
	}
	if opts.withFqn {
		fields = append(fields, "fqn")
	}
	sb := newStatementBuilder().
		Select(fields...)

	if opts.withFqn {
		sb = sb.LeftJoin(Tables.AttrFqn.Name() + " ON " + Tables.AttrFqn.Field("value_id") + " = " + t.Field("id"))
	}

	return sb.
		From(t.Name()).
		ToSql()
}

func (c Client) ListAllAttributeValues(ctx context.Context, state string) ([]*attributes.Value, error) {
	opts := attributeValueSelectOptions{withFqn: true, state: state}
	sql, args, err := listAllAttributeValuesSql(opts)
	rows, err := c.query(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return attributeValueHydrateItems(rows, opts)
}

func updateAttributeValueSql(
	id string,
	value string,
	members []string,
	metadata []byte,
) (string, []interface{}, error) {
	t := Tables.AttributeValues
	sb := newStatementBuilder().
		Update(t.Name()).
		Set("metadata", metadata)

	if value != "" {
		sb = sb.Set("value", value)
	}
	if members != nil {
		sb = sb.Set("members", members)
	}

	return sb.
		Where(sq.Eq{t.Field("id"): id}).
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

	// Update FQN
	c.upsertAttrFqn(ctx, attrFqnUpsertOptions{valueId: id})

	return prev, nil
}

func deactivateAttributeValueSql(id string) (string, []interface{}, error) {
	t := Tables.AttributeValues
	return newStatementBuilder().
		Update(t.Name()).
		Set("active", false).
		Where(sq.Eq{t.Field("id"): id}).
		Suffix("RETURNING \"id\"").
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
	t := Tables.AttributeValues
	return newStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
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
		Where(sq.Eq{t.Field("attribute_value_id"): valueID, t.Field("key_access_server_id"): keyAccessServerID}).
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
