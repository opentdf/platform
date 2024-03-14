package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/internal/set"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type attributeValueSelectOptions struct {
	state   string
	withFqn bool
	// withKeyAccessGrants  bool
	// withSubjectMappings  bool
	// withResourceMappings bool

	// withAttribute                bool
	// withAttributeKeyAccessGrants bool
	// withAttributeNamespace       bool
}

// func getMembersFromStringArray(c PolicyDbClient, members []string) ([]*policy.Value, error) {
// 	// Hydrate members
// 	hydratedMemberIds := map[string]bool{}
// 	var hydratedMembers []*policy.Value

// 	for _, member := range members {
// 		var (
// 			vm_id     string
// 			value_id  string
// 			member_id string
// 		)

// 		// Get member value from db
// 		sql, args, err := getMemberSql(member)
// 		if err != nil {
// 			return nil, err
// 		}
// 		if r, err := c.QueryRow(context.TODO(), sql, args, err); err != nil {
// 			return nil, err
// 		} else if err := r.Scan(&vm_id, &value_id, &member_id); err != nil {
// 			return nil, db.WrapIfKnownInvalidQueryErr(err)
// 		}
// 		attr, err := c.GetAttributeValue(context.TODO(), member_id)
// 		if err != nil {
// 			return nil, err
// 		}

// 		if hydratedMemberIds[member_id] {
// 			slog.Info("attr val member may be duplicated", slog.String("member_id", member_id))
// 			continue
// 		}

// 		hydratedMemberIds[member_id] = true
// 		hydratedMembers = append(hydratedMembers, attr)
// 	}
// 	return hydratedMembers, nil
// }

func attributeValueHydrateItem(row pgx.Row, opts attributeValueSelectOptions) (*policy.Value, error) {
	var (
		id           string
		value        string
		active       bool
		membersJson  []byte
		metadataJson []byte
		attributeId  string
		fqn          sql.NullString
		members      []*policy.Value
	)
	fields := []interface{}{
		&id,
		&value,
		&active,
		&membersJson,
		&metadataJson,
		&attributeId,
	}

	if opts.withFqn {
		fields = append(fields, &fqn)
	}
	if err := row.Scan(fields...); err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	} else {
		if membersJson != nil {
			members, err = attributesValuesProtojson(membersJson)
			if err != nil {
				return nil, err
			}
		}
	}

	m := &common.Metadata{}
	if metadataJson != nil {
		if err := protojson.Unmarshal(metadataJson, m); err != nil {
			return nil, err
		}
	}

	v := &policy.Value{
		Id:       id,
		Value:    value,
		Active:   &wrapperspb.BoolValue{Value: active},
		Members:  members,
		Metadata: m,
		Attribute: &policy.Attribute{
			Id: attributeId,
		},
		Fqn: fqn.String,
	}
	return v, nil
}

func attributeValueHydrateItems(rows pgx.Rows, opts attributeValueSelectOptions) ([]*policy.Value, error) {
	list := make([]*policy.Value, 0)
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

func addMemberSql(value_id string, member_id string) (string, []interface{}, error) {
	t := Tables.ValueMembers
	return db.NewStatementBuilder().
		Insert(t.Name()).
		Columns(
			"value_id",
			"member_id",
		).
		Values(
			value_id,
			member_id,
		).
		Suffix("RETURNING id").
		ToSql()
}

func removeMemberSql(value_id string, member_id string) (string, []interface{}, error) {
	t := Tables.ValueMembers
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{
			t.Field("value_id"):  value_id,
			t.Field("member_id"): member_id,
		}).
		Suffix("RETURNING id").
		ToSql()
}

func createAttributeValueSql(
	attribute_id string,
	value string,
	metadata []byte,
) (string, []interface{}, error) {
	t := Tables.AttributeValues
	return db.NewStatementBuilder().
		Insert(t.Name()).
		Columns(
			"attribute_definition_id",
			"value",
			"metadata",
		).
		Values(
			attribute_id,
			value,
			metadata,
		).
		Suffix("RETURNING id").
		ToSql()
}

func (c PolicyDbClient) CreateAttributeValue(ctx context.Context, attributeId string, v *attributes.CreateAttributeValueRequest) (*policy.Value, error) {
	metadataJson, metadata, err := db.MarshalCreateMetadata(v.Metadata)
	if err != nil {
		return nil, err
	}

	sql, args, err := createAttributeValueSql(
		attributeId,
		v.Value,
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

	var members []*policy.Value

	// Add members
	for _, member := range v.Members {
		var vm_id string
		sql, args, err := addMemberSql(id, member)
		if err != nil {
			return nil, err
		}
		if r, err := c.QueryRow(ctx, sql, args, err); err != nil {
			return nil, err
		} else if err := r.Scan(&vm_id); err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}
		attr, err := c.GetAttributeValue(ctx, member)
		if err != nil {
			return nil, err
		}
		members = append(members, attr)
	}

	// Update FQN
	c.upsertAttrFqn(ctx, attrFqnUpsertOptions{valueId: id})

	rV := &policy.Value{
		Id:        id,
		Attribute: &policy.Attribute{Id: attributeId},
		Value:     v.Value,
		Members:   members,
		Metadata:  metadata,
		Active:    &wrapperspb.BoolValue{Value: true},
	}
	return rV, nil
}

// func getMemberSql(id string) (string, []interface{}, error) {
// 	t := Tables.ValueMembers
// 	fields := []string{
// 		t.Field("id"),
// 		t.Field("value_id"),
// 		t.Field("member_id"),
// 	}

// 	sb := db.NewStatementBuilder().
// 		Select(fields...).
// 		From(t.Name())

// 	return sb.
// 		Where(sq.Eq{t.Field("id"): id}).
// 		ToSql()
// }

func getAttributeValueSql(id string, opts attributeValueSelectOptions) (string, []interface{}, error) {
	t := Tables.AttributeValues
	fqnT := Tables.AttrFqn
	members := "COALESCE(JSON_AGG(JSON_BUILD_OBJECT(" +
		"'id', vmv.id, " +
		"'value', vmv.value, " +
		"'active', vmv.active, " +
		"'members', vmv.members || ARRAY[]::UUID[], " +
		"'metadata', vmv.metadata, " +
		"'attribute', JSON_BUILD_OBJECT(" +
		"'id', vmv.attribute_definition_id )" // TODO: get the rest of the attribute here from the JOIN?
	if opts.withFqn {
		members += ", 'fqn', " + "fqn1.fqn"
	}
	members += ")) FILTER (WHERE vmv.id IS NOT NULL ), '[]') AS members"
	fields := []string{
		"av.id",
		"av.value",
		"av.active",
		members,
		"av.metadata",
		"av.attribute_definition_id",
	}
	if opts.withFqn {
		fields = append(fields, "MAX(fqn2.fqn) AS fqn")
	}

	sb := db.NewStatementBuilder().
		Select(fields...).
		From(t.Name() + " av")

	// join members
	sb = sb.LeftJoin(Tables.ValueMembers.Name() + " vm ON av.id = vm.value_id")

	// join attribute values
	sb = sb.LeftJoin(t.Name() + " vmv ON vm.member_id = vmv.id")

	if opts.withFqn {
		sb = sb.LeftJoin(fqnT.Name() + " AS fqn1 ON " + "fqn1.value_id" + " = " + "vmv.id")
		sb = sb.LeftJoin(fqnT.Name() + " AS fqn2 ON " + "fqn2.value_id" + " = " + "av.id")
	}

	return sb.Where(sq.Eq{
		"av.id": id,
	}).
		GroupBy(
			"av.id",
			// fqnT.Field("fqn"),
		).
		ToSql()
}

func (c PolicyDbClient) GetAttributeValue(ctx context.Context, id string) (*policy.Value, error) {
	opts := attributeValueSelectOptions{withFqn: true}
	sql, args, err := getAttributeValueSql(id, opts)
	fmt.Println("\nsql: ", sql)
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
	t := Tables.AttributeValues
	members := "COALESCE(JSON_AGG(JSON_BUILD_OBJECT(" +
		"'id', vmv.id, " +
		"'value', vmv.value, " +
		"'active', vmv.active, " +
		"'members', vmv.members || ARRAY[]::UUID[], " +
		"'metadata', vmv.metadata, " +
		"'attribute', JSON_BUILD_OBJECT(" +
		"'id', vmv.attribute_definition_id )"
	if opts.withFqn {
		members += ", 'fqn', " + "fqn1.fqn"
	}
	members += ")) FILTER (WHERE vmv.id IS NOT NULL ), '[]') AS members"
	fields := []string{
		"av.id",
		"av.value",
		"av.active",
		members,
		"av.metadata",
		"av.attribute_definition_id",
	}
	if opts.withFqn {
		fields = append(fields, "MAX(fqn2.fqn) AS fqn")
	}

	sb := db.NewStatementBuilder().
		Select(fields...)

	// join members
	sb = sb.LeftJoin(Tables.ValueMembers.Name() + " vm ON av.id = vm.value_id")

	// join attribute values
	sb = sb.LeftJoin(t.Name() + " vmv ON vm.member_id = vmv.id")

	if opts.withFqn {
		fqnT := Tables.AttrFqn
		sb = sb.LeftJoin(fqnT.Name() + " AS fqn1 ON " + "fqn1.value_id" + " = " + "vmv.id")
		sb = sb.LeftJoin(fqnT.Name() + " AS fqn2 ON " + "fqn2.value_id" + " = " + "av.id")
	}

	sb = sb.GroupBy("av.id")

	where := sq.Eq{}
	if opts.state != "" && opts.state != StateAny {
		where["av.active"] = opts.state == StateActive
	}
	where["av.attribute_definition_id"] = attribute_id

	return sb.
		From(t.Name() + " av").
		Where(where).
		ToSql()
}

func (c PolicyDbClient) ListAttributeValues(ctx context.Context, attribute_id string, state string) ([]*policy.Value, error) {
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
	t := Tables.AttributeValues
	members := "COALESCE(JSON_AGG(JSON_BUILD_OBJECT(" +
		"'id', vmv.id, " +
		"'value', vmv.value, " +
		"'active', vmv.active, " +
		"'members', vmv.members || ARRAY[]::UUID[], " +
		"'metadata', vmv.metadata, " +
		"'attribute', JSON_BUILD_OBJECT(" +
		"'id', vmv.attribute_definition_id )"
	if opts.withFqn {
		members += ", 'fqn', " + "fqn1.fqn"
	}
	members += ")) FILTER (WHERE vmv.id IS NOT NULL ), '[]') AS members"
	fields := []string{
		"av.id",
		"av.value",
		"av.active",
		members,
		"av.metadata",
		"av.attribute_definition_id",
	}
	if opts.withFqn {
		fields = append(fields, "MAX(fqn2.fqn) AS fqn")
	}
	sb := db.NewStatementBuilder().
		Select(fields...)

	// join members
	sb = sb.LeftJoin(Tables.ValueMembers.Name() + " vm ON av.id = vm.value_id")

	// join attribute values
	sb = sb.LeftJoin(t.Name() + " vmv ON vm.member_id = vmv.id")

	if opts.withFqn {
		fqnT := Tables.AttrFqn
		sb = sb.LeftJoin(fqnT.Name() + " AS fqn1 ON " + "fqn1.value_id" + " = " + "vmv.id")
		sb = sb.LeftJoin(fqnT.Name() + " AS fqn2 ON " + "fqn2.value_id" + " = " + "av.id")
	}

	sb = sb.GroupBy("av.id")

	return sb.
		From(t.Name() + " av").
		ToSql()
}

func (c PolicyDbClient) ListAllAttributeValues(ctx context.Context, state string) ([]*policy.Value, error) {
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
	metadata []byte,
) (string, []interface{}, error) {
	t := Tables.AttributeValues
	sb := db.NewStatementBuilder().Update(t.Name())

	if metadata != nil {
		sb = sb.Set("metadata", metadata)
	}

	return sb.Where(sq.Eq{t.Field("id"): id}).ToSql()
}

func (c PolicyDbClient) UpdateAttributeValue(ctx context.Context, r *attributes.UpdateAttributeValueRequest) (*policy.Value, error) {
	metadataJson, _, err := db.MarshalUpdateMetadata(r.Metadata, r.MetadataUpdateBehavior, func() (*common.Metadata, error) {
		v, err := c.GetAttributeValue(ctx, r.Id)
		if err != nil {
			return nil, err
		}
		return v.Metadata, nil
	})
	if err != nil {
		return nil, err
	}

	sql, args, err := updateAttributeValueSql(
		r.Id,
		metadataJson,
	)
	if db.IsQueryBuilderSetClauseError(err) {
		return &policy.Value{
			Id: r.Id,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	prev, err := c.GetAttributeValue(ctx, r.Id)
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}
	prevMembersSet := set.NewSet()
	for _, member := range prev.Members {
		prevMembersSet.Add(member.Id)
	}

	membersSet := set.NewSet()
	for _, member := range r.Members {
		membersSet.Add(member)
	}

	toRemove := prevMembersSet.Difference(membersSet).ToSlice()
	toAdd := membersSet.Difference(prevMembersSet).ToSlice()

	// Remove members
	for _, member := range toRemove {
		sql, args, err := removeMemberSql(r.Id, member.(string))
		if err != nil {
			return nil, err
		}
		if err := c.Exec(ctx, sql, args); err != nil {
			return nil, err
		}
	}

	// Add members
	for _, member := range toAdd {
		sql, args, err := addMemberSql(r.Id, member.(string))
		if err != nil {
			return nil, err
		}
		if err := c.Exec(ctx, sql, args); err != nil {
			return nil, err
		}
	}

	// var members []*policy.Value
	// for _, member := range r.Members {
	// 	attr, err := c.GetAttributeValue(ctx, member)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	members = append(members, attr)
	// }

	// Update FQN
	c.upsertAttrFqn(ctx, attrFqnUpsertOptions{valueId: r.Id})

	return &policy.Value{
		Id: r.Id,
	}, nil
}

func deactivateAttributeValueSql(id string) (string, []interface{}, error) {
	t := Tables.AttributeValues
	return db.NewStatementBuilder().
		Update(t.Name()).
		Set("active", false).
		Where(sq.Eq{t.Field("id"): id}).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c PolicyDbClient) DeactivateAttributeValue(ctx context.Context, id string) (*policy.Value, error) {
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
	t := Tables.AttributeValues
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c PolicyDbClient) DeleteAttributeValue(ctx context.Context, id string) (*policy.Value, error) {
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
	t := Tables.AttributeValueKeyAccessGrants
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
	t := Tables.AttributeValueKeyAccessGrants
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
