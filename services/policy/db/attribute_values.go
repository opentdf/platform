package db

import (
	"context"
	"database/sql"
	"log/slog"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
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
		return nil, db.WrapIfKnownInvalidQueryErr(err)
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
		Active:   &wrapperspb.BoolValue{Value: active},
		Members:  members,
		Metadata: m,
		// TODO: get & hydrate full attribute
		Fqn: fqn.String,
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
	t := db.Tables.AttributeValues
	return db.NewStatementBuilder().
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

func (c PolicyDbClient) CreateAttributeValue(ctx context.Context, attributeId string, v *attributes.CreateAttributeValueRequest) (*attributes.Value, error) {
	metadataJson, metadata, err := db.MarshalCreateMetadata(v.Metadata)
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
	if r, err := c.QueryRow(ctx, sql, args, err); err != nil {
		return nil, err
	} else if err := r.Scan(&id); err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	// Update FQN
	c.upsertAttrFqn(ctx, attrFqnUpsertOptions{valueId: id})

	rV := &attributes.Value{
		Id:        id,
		Attribute: &attributes.Attribute{Id: attributeId},
		Value:     v.Value,
		Members:   v.Members,
		Metadata:  metadata,
		Active:    &wrapperspb.BoolValue{Value: true},
	}
	return rV, nil
}

func getAttributeValueSql(id string, opts attributeValueSelectOptions) (string, []interface{}, error) {
	t := db.Tables.AttributeValues
	fields := []string{
		t.Field("id"),
		t.Field("value"),
		t.Field("active"),
		t.Field("members"),
		t.Field("metadata"),
		t.Field("attribute_definition_id"),
	}
	if opts.withFqn {
		fields = append(fields, db.Tables.AttrFqn.Field("fqn"))
	}

	sb := db.NewStatementBuilder().
		Select(fields...).
		From(t.Name())

	if opts.withFqn {
		fqnT := db.Tables.AttrFqn
		sb = sb.LeftJoin(fqnT.Name() + " ON " + fqnT.Field("value_id") + " = " + t.Field("id"))
	}

	return sb.Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c PolicyDbClient) GetAttributeValue(ctx context.Context, id string) (*attributes.Value, error) {
	opts := attributeValueSelectOptions{withFqn: true}
	sql, args, err := getAttributeValueSql(id, opts)
	row, err := c.QueryRow(ctx, sql, args, err)
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
	t := db.Tables.AttributeValues
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

	sb := db.NewStatementBuilder().
		Select(fields...)

	if opts.withFqn {
		fqnT := db.Tables.AttrFqn
		sb = sb.LeftJoin(fqnT.Name() + " ON " + fqnT.Field("value_id") + " = " + t.Field("id"))
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

func (c PolicyDbClient) ListAttributeValues(ctx context.Context, attribute_id string, state string) ([]*attributes.Value, error) {
	opts := attributeValueSelectOptions{withFqn: true, state: state}

	sql, args, err := listAttributeValuesSql(attribute_id, opts)
	rows, err := c.Query(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return attributeValueHydrateItems(rows, opts)
}

func listAllAttributeValuesSql(opts attributeValueSelectOptions) (string, []interface{}, error) {
	t := db.Tables.AttributeValues
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
	sb := db.NewStatementBuilder().
		Select(fields...)

	if opts.withFqn {
		fqnT := db.Tables.AttrFqn
		sb = sb.LeftJoin(fqnT.Name() + " ON " + fqnT.Field("value_id") + " = " + t.Field("id"))
	}

	return sb.
		From(t.Name()).
		ToSql()
}

func (c PolicyDbClient) ListAllAttributeValues(ctx context.Context, state string) ([]*attributes.Value, error) {
	opts := attributeValueSelectOptions{withFqn: true, state: state}
	sql, args, err := listAllAttributeValuesSql(opts)
	rows, err := c.Query(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return attributeValueHydrateItems(rows, opts)
}

func updateAttributeValueSql(
	id string,
	members []string,
	metadata []byte,
) (string, []interface{}, error) {
	t := db.Tables.AttributeValues
	sb := db.NewStatementBuilder().Update(t.Name())

	if metadata != nil {
		sb = sb.Set("metadata", metadata)
	}

	if members != nil {
		sb = sb.Set("members", members)
	}

	return sb.Where(sq.Eq{t.Field("id"): id}).ToSql()
}

func (c PolicyDbClient) UpdateAttributeValue(ctx context.Context, id string, r *attributes.UpdateAttributeValueRequest) (*attributes.Value, error) {
	metadataJson, _, err := db.MarshalUpdateMetadata(r.Metadata, r.MetadataUpdateBehavior, func() (*common.Metadata, error) {
		v, err := c.GetAttributeValue(ctx, id)
		if err != nil {
			return nil, err
		}
		return v.Metadata, nil
	})
	if err != nil {
		return nil, err
	}

	sql, args, err := updateAttributeValueSql(
		id,
		r.Members,
		metadataJson,
	)
	if db.IsQueryBuilderSetClauseError(err) {
		return &attributes.Value{
			Id: id,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	// Update FQN
	c.upsertAttrFqn(ctx, attrFqnUpsertOptions{valueId: id})

	return &attributes.Value{
		Id: id,
	}, nil
}

func deactivateAttributeValueSql(id string) (string, []interface{}, error) {
	t := db.Tables.AttributeValues
	return db.NewStatementBuilder().
		Update(t.Name()).
		Set("active", false).
		Where(sq.Eq{t.Field("id"): id}).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c PolicyDbClient) DeactivateAttributeValue(ctx context.Context, id string) (*attributes.Value, error) {
	sql, args, err := deactivateAttributeValueSql(id)
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}
	return c.GetAttributeValue(ctx, id)
}

func deleteAttributeValueSql(id string) (string, []interface{}, error) {
	t := db.Tables.AttributeValues
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c PolicyDbClient) DeleteAttributeValue(ctx context.Context, id string) (*attributes.Value, error) {
	prev, err := c.GetAttributeValue(ctx, id)
	if err != nil {
		return nil, err
	}

	sql, args, err := deleteAttributeValueSql(id)
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return prev, nil
}

func assignKeyAccessServerToValueSql(valueID, keyAccessServerID string) (string, []interface{}, error) {
	t := db.Tables.AttributeValueKeyAccessGrants
	return db.NewStatementBuilder().
		Insert(t.Name()).
		Columns("attribute_value_id", "key_access_server_id").
		Values(valueID, keyAccessServerID).
		ToSql()
}

func (c PolicyDbClient) AssignKeyAccessServerToValue(ctx context.Context, k *attributes.ValueKeyAccessServer) (*attributes.ValueKeyAccessServer, error) {
	sql, args, err := assignKeyAccessServerToValueSql(k.ValueId, k.KeyAccessServerId)
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return k, nil
}

func removeKeyAccessServerFromValueSql(valueID, keyAccessServerID string) (string, []interface{}, error) {
	t := db.Tables.AttributeValueKeyAccessGrants
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("attribute_value_id"): valueID, t.Field("key_access_server_id"): keyAccessServerID}).
		Suffix("IS TRUE RETURNING *").
		ToSql()
}

func (c PolicyDbClient) RemoveKeyAccessServerFromValue(ctx context.Context, k *attributes.ValueKeyAccessServer) (*attributes.ValueKeyAccessServer, error) {
	sql, args, err := removeKeyAccessServerFromValueSql(k.ValueId, k.KeyAccessServerId)
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return k, nil
}
