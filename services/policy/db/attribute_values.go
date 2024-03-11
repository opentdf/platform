package db

import (
	"context"
	"database/sql"
	"log/slog"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/internal/set"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type attributeValueSelectOptions struct {
	withFqn bool
	state   string
}

func getMembersFromStringArray(c PolicyDbClient, members []string) ([]*attributes.Value, error) {
	// Hydrate members
	hydratedMemberIds := set.NewSet()
	var hydratedMembers []*attributes.Value

	for _, member := range members {
		var (
			vm_id     string
			value_id  string
			member_id string
		)

		// Get member value from db
		sql, args, err := getMemberSql(member)
		if err != nil {
			return nil, err
		}
		if r, err := c.QueryRow(context.TODO(), sql, args, err); err != nil {
			return nil, err
		} else if err := r.Scan(&vm_id, &value_id, &member_id); err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}
		attr, err := c.GetAttributeValue(context.TODO(), member_id)
		if err != nil {
			return nil, err
		}

		if hydratedMemberIds.Contains(member_id) {
			slog.Info("attr val member may be duplicated", slog.String("member_id", member_id))
			continue
		}

		hydratedMemberIds.Add(member_id)
		hydratedMembers = append(hydratedMembers, attr)
	}
	return hydratedMembers, nil
}

func attributeValueHydrateItem(c PolicyDbClient, row pgx.Row, opts attributeValueSelectOptions) (*attributes.Value, error) {
	var (
		id           string
		value        string
		active       bool
		membersJson  []byte
		metadataJson []byte
		attributeId  string
		fqn          sql.NullString
		memberUUIDs  []string
		members      []*attributes.Value
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
	println("fqn", fqn.String)
	if err := row.Scan(fields...); err != nil {
		fields := []interface{}{
			&id,
			&value,
			&active,
			&memberUUIDs,
			&metadataJson,
			&attributeId,
		}
		if opts.withFqn {
			fields = append(fields, &fqn)
		}

		if err := row.Scan(fields...); err != nil {
			return nil, db.WrapIfKnownInvalidQueryErr(err)
		}
		members, err = getMembersFromStringArray(c, memberUUIDs)
		if err != nil {
			return nil, err
		}
	} else {
		// for _, memberJson := range membersJson {
		// 	// memberJson = memberJson.(json.RawMessage)
		// 	println("memberJson", string(memberJson))
		// 	// var i interface{}
		// 	// if err := json.Unmarshal(memberJson, &i); err != nil {
		// 	// 	return nil, err
		// 	// }
		// 	// memberattributesValuesProtojson(membersJson)

		// 	member, err := attributesValuesProtojson(c, memberJson)
		// 	if err != nil {
		// 		return nil, err
		// 	}
		// 	// member := &attributes.Value{}
		// 	// if err := protojson.Unmarshal(memberJson, member); err != nil {
		// 	// 	return nil, err
		// 	// }
		// 	members = append(members, member)
		// }
		println("membersJson before", string(membersJson))
		if membersJson != nil {
			members, err = attributesValuesProtojson(c, membersJson)
			println("len(members)", len(members))
			for _, member := range members {
				println("member", member.Id)
			}
			// if len(members) == 0 {
			// 	// log.Fatal("members is empty")
			// 	println("members is empty")
			// }
			// log.Fatal("IsSuE In UnMaRsHaLlInG")
			if err != nil {
				println("IsSuE In UnMaRsHaLlInG")
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
	println("fqn: ", fqn.String)

	// // Hydrate members
	// hydratedMemberIds := set.NewSet()
	// var hydratedMembers []*attributes.Value

	// for _, member := range members {
	// 	var (
	// 		vm_id     string
	// 		value_id  string
	// 		member_id string
	// 	)

	// 	// Get member value from db
	// 	sql, args, err := getMemberSql(member)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	if r, err := c.QueryRow(context.TODO(), sql, args, err); err != nil {
	// 		return nil, err
	// 	} else if err := r.Scan(&vm_id, &value_id, &member_id); err != nil {
	// 		return nil, db.WrapIfKnownInvalidQueryErr(err)
	// 	}
	// 	attr, err := c.GetAttributeValue(context.TODO(), member_id)
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	if hydratedMemberIds.Contains(member_id) {
	// 		slog.Info("attr val member may be duplicated", slog.String("member_id", member_id))
	// 		continue
	// 	}

	// 	hydratedMemberIds.Add(member_id)
	// 	hydratedMembers = append(hydratedMembers, attr)
	// }
	// hydratedMembers, err := getMembersFromStringArray(c, memberUUIDs)
	// if err != nil {
	// 	return nil, err
	// }

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

func attributeValueHydrateItems(c PolicyDbClient, rows pgx.Rows, opts attributeValueSelectOptions) ([]*attributes.Value, error) {
	list := make([]*attributes.Value, 0)
	for rows.Next() {
		v, err := attributeValueHydrateItem(c, rows, opts)
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
	t := db.Tables.ValueMembers
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
	t := db.Tables.ValueMembers
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
	t := db.Tables.AttributeValues
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

func (c PolicyDbClient) CreateAttributeValue(ctx context.Context, attributeId string, v *attributes.ValueCreateUpdate) (*attributes.Value, error) {
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

	var members []*attributes.Value

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

	rV := &attributes.Value{
		Id:          id,
		AttributeId: attributeId,
		Value:       v.Value,
		Members:     members,
		Metadata:    metadata,
		Active:      &wrapperspb.BoolValue{Value: true},
	}
	return rV, nil
}

func getMemberSql(id string) (string, []interface{}, error) {
	t := db.Tables.ValueMembers
	fields := []string{
		t.Field("id"),
		t.Field("value_id"),
		t.Field("member_id"),
	}

	sb := db.NewStatementBuilder().
		Select(fields...).
		From(t.Name())

	return sb.
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func getAttributeValueSql(id string, opts attributeValueSelectOptions) (string, []interface{}, error) {
	t := db.Tables.AttributeValues
	fqnT := db.Tables.AttrFqn
	members := "COALESCE(JSON_AGG(JSON_BUILD_OBJECT(" +
		"'id', vmv.id, " +
		"'value', vmv.value, " +
		"'active', vmv.active, " +
		"'members', vmv.members || ARRAY[]::UUID[], " +
		"'metadata', vmv.metadata ," +
		"'attribute_id', vmv.attribute_definition_id "
	if opts.withFqn {
		members += ", 'fqn', " + fqnT.Field("fqn")
	}
	members += ")) FILTER (WHERE vmv.id IS NOT NULL ), '[]') AS members"
	fields := []string{
		// t.Field("id"),
		// t.Field("value"),
		// t.Field("active"),
		// t.Field("members"),
		// t.Field("metadata"),
		// t.Field("attribute_definition_id"),
		"av.id",
		"av.value",
		"av.active",
		members,
		"av.metadata",
		"av.attribute_definition_id",
	}
	if opts.withFqn {
		// fields = append(fields, "MAX("+fqnT.Field("fqn")+") AS fqn")
		fields = append(fields, db.Tables.AttrFqn.Field("fqn"))
	}

	sb := db.NewStatementBuilder().
		Select(fields...).
		From(t.Name() + " av")
		// add alias

	// join members
	sb = sb.LeftJoin(db.Tables.ValueMembers.Name() + " vm ON av.id = vm.value_id")

	// join attribute values
	sb = sb.JoinClause("FULL OUTER JOIN " + t.Name() + " vmv ON vm.member_id = vmv.id")

	if opts.withFqn {
		sb = sb.LeftJoin(fqnT.Name() + " ON " + fqnT.Field("value_id") + " = " + "vmv.id")
		// sb = sb.LeftJoin(fqnT.Name() + " ON " + fqnT.Field("attribute_id") + " = " + "vmv.attribute_definition_id")
	}

	return sb.Where(sq.Eq{
		"av.id": id}).
		GroupBy(
			"av.id",
			fqnT.Field("fqn"),
		).
		// LeftJoin(t.Name() + " ON " + t.Field("id") + " = " + db.Tables.ValueMembers.Field("member_id")).
		ToSql()
}

func (c PolicyDbClient) GetAttributeValue(ctx context.Context, id string) (*attributes.Value, error) {
	opts := attributeValueSelectOptions{withFqn: true}
	sql, args, err := getAttributeValueSql(id, opts)
	println("sql", sql)
	row, err := c.QueryRow(ctx, sql, args, err)
	if err != nil {
		slog.Error("error getting attribute value", slog.String("id", id), slog.String("sql", sql), slog.String("error", err.Error()))
		return nil, err
	}
	// rows, err := c.Query(ctx, sql, args, err)
	// if err != nil {
	// 	return nil, err
	// }
	// println(rows.FieldDescriptions())
	// for field, description := range rows.FieldDescriptions() {

	// 	fmt.Printf("Field %v: %v\n", field, description.Name)

	// }
	// for rows.Next() {
	// 	columnValues, _ := rows.Values()
	// 	for i, v := range columnValues {
	// 		fmt.Printf("Type of value at %v=%T, value=%v | ", i, v, v)
	// 	}
	// }

	a, err := attributeValueHydrateItem(c, row, opts)
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
	return attributeValueHydrateItems(c, rows, opts)
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
	return attributeValueHydrateItems(c, rows, opts)
}

func updateAttributeValueSql(
	id string,
	value string,
	metadata []byte,
) (string, []interface{}, error) {
	t := db.Tables.AttributeValues
	sb := db.NewStatementBuilder().
		Update(t.Name()).
		Set("metadata", metadata)

	if value != "" {
		sb = sb.Set("value", value)
	}

	return sb.
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c PolicyDbClient) UpdateAttributeValue(ctx context.Context, id string, v *attributes.ValueCreateUpdate) (*attributes.Value, error) {
	prev, err := c.GetAttributeValue(ctx, id)
	if err != nil {
		return nil, err
	}

	metadataJson, _, err := db.MarshalUpdateMetadata(prev.Metadata, v.Metadata)
	if err != nil {
		return nil, err
	}

	sql, args, err := updateAttributeValueSql(
		id,
		v.Value,
		metadataJson,
	)
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args, err); err != nil {
		return nil, err
	}
	prevMembersSet := set.NewSet()
	for _, member := range prev.Members {
		prevMembersSet.Add(member.Id)
	}

	membersSet := set.NewSet()
	for _, member := range v.Members {
		membersSet.Add(member)
	}

	toRemove := prevMembersSet.Difference(membersSet).ToSlice()
	toAdd := membersSet.Difference(prevMembersSet).ToSlice()

	// Remove members
	for _, member := range toRemove {
		sql, args, err := removeMemberSql(id, member.(string))
		if err != nil {
			return nil, err
		}
		if err := c.Exec(ctx, sql, args, err); err != nil {
			return nil, err
		}
	}

	// Add members
	for _, member := range toAdd {
		sql, args, err := addMemberSql(id, member.(string))
		if err != nil {
			return nil, err
		}
		if err := c.Exec(ctx, sql, args, err); err != nil {
			return nil, err
		}
	}

	var members []*attributes.Value
	for _, member := range v.Members {
		attr, err := c.GetAttributeValue(ctx, member)
		if err != nil {
			return nil, err
		}
		members = append(members, attr)
	}

	// Update FQN
	c.upsertAttrFqn(ctx, attrFqnUpsertOptions{valueId: id})

	return prev, nil
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
	if err := c.Exec(ctx, sql, args, err); err != nil {
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
	if err := c.Exec(ctx, sql, args, err); err != nil {
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

	if err := c.Exec(ctx, sql, args, err); err != nil {
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

	if _, err := c.QueryCount(ctx, sql, args); err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return k, nil
}
