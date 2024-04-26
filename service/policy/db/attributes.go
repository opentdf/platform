package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/service/internal/db"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var AttributeRuleTypeEnumPrefix = "ATTRIBUTE_RULE_TYPE_ENUM_"

func attributesRuleTypeEnumTransformIn(value string) string {
	return strings.TrimPrefix(value, AttributeRuleTypeEnumPrefix)
}

func attributesRuleTypeEnumTransformOut(value string) policy.AttributeRuleTypeEnum {
	return policy.AttributeRuleTypeEnum(policy.AttributeRuleTypeEnum_value[AttributeRuleTypeEnumPrefix+value])
}

func attributesValuesProtojson(valuesJSON []byte) ([]*policy.Value, error) {
	var (
		raw    []json.RawMessage
		values []*policy.Value
	)

	if err := json.Unmarshal(valuesJSON, &raw); err != nil {
		return nil, err
	}

	for _, r := range raw {
		value := &policy.Value{}
		err := protojson.Unmarshal(r, value)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling a value: %w", err)
		}
		values = append(values, value)
	}
	return values, nil
}

type attributesSelectOptions struct {
	withAttributeValues bool
	withKeyAccessGrants bool
	// withFqn and withOneValueByFqn are mutually exclusive
	withFqn           bool
	withOneValueByFqn string
	state             string
	namespace         string
}

func attributesSelect(opts attributesSelectOptions) sq.SelectBuilder {
	if opts.withKeyAccessGrants {
		opts.withAttributeValues = true
	}

	t := Tables.Attributes
	nt := Tables.Namespaces
	avt := Tables.AttributeValues
	fqnt := Tables.AttrFqn
	smT := Tables.SubjectMappings
	scsT := Tables.SubjectConditionSet
	// akt := Tables.AttributeKeyAccessGrants
	// avkt := Tables.AttributeKeyAccessGrants
	selectFields := []string{
		t.Field("id"),
		t.Field("name"),
		t.Field("rule"),
		constructMetadata(t.Name(), false),
		t.Field("namespace_id"),
		t.Field("active"),
		nt.Field("name"),
	}
	if opts.withAttributeValues || opts.withOneValueByFqn != "" {
		valueSelect := "JSON_AGG(" +
			"JSON_BUILD_OBJECT(" +
			"'id', avt.id," +
			"'value', avt.value," +
			"'members', avt.members," +
			"'active', avt.active"

		// include the subject mapping / subject condition set for each value
		if opts.withOneValueByFqn != "" {
			valueSelect += ", 'fqn', val_sm_fqn_join.fqn, " +
				"'subject_mappings', sub_maps_arr"
		}
		valueSelect += ")) AS values"
		selectFields = append(selectFields, t.Field("values_order"), valueSelect)
	}
	if opts.withKeyAccessGrants {
		selectFields = append(selectFields, "JSON_AGG("+
			"JSON_BUILD_OBJECT("+
			"'id', "+avt.Field("id")+", "+
			"'value', "+avt.Field("value")+","+
			"'members', "+avt.Field("members")+","+
			"'grants', ("+
			"SELECT JSON_AGG("+
			"JSON_BUILD_OBJECT("+
			"'id', kas.id, "+
			"'uri', kas.uri, "+
			"'public_key', kas.public_key"+
			")"+
			") "+
			"FROM "+Tables.KeyAccessServerRegistry.Name()+" kas "+
			"JOIN "+Tables.AttributeValueKeyAccessGrants.Name()+" avkag ON avkag.key_access_server_id = kas.id "+
			"WHERE avkag.attribute_value_id = "+avt.Field("id")+
			")"+
			")) AS grants")
	}
	if opts.withFqn {
		selectFields = append(selectFields, fqnt.Field("fqn"))
	}

	sb := db.NewStatementBuilder().Select(selectFields...).
		LeftJoin(nt.Name() + " ON " + nt.Field("id") + " = " + t.Field("namespace_id"))

	if opts.withAttributeValues {
		sb = sb.LeftJoin("(SELECT av.id, av.value, av.active, COALESCE(JSON_AGG(JSON_BUILD_OBJECT(" +
			"'id', vmv.id, " +
			"'value', vmv.value, " +
			"'active', vmv.active, " +
			"'members', vmv.members || ARRAY[]::UUID[], " +
			"'attribute', JSON_BUILD_OBJECT(" +
			"'id', vmv.attribute_definition_id ))) FILTER (WHERE vmv.id IS NOT NULL ), '[]') AS members, av.attribute_definition_id FROM " + avt.Name() + " av LEFT JOIN " + Tables.ValueMembers.Name() + " vm ON av.id = vm.value_id LEFT JOIN " + avt.Name() + " vmv ON vm.member_id = vmv.id GROUP BY av.id) avt ON avt.attribute_definition_id = " + t.Field("id"))
	}
	if opts.withKeyAccessGrants {
		sb = sb.LeftJoin(Tables.AttributeKeyAccessGrants.Name() + " ON " + Tables.AttributeKeyAccessGrants.WithoutSchema().Name() + ".attribute_definition_id = " + t.Field("id")).
			LeftJoin(Tables.KeyAccessServerRegistry.Name() + " ON " + Tables.KeyAccessServerRegistry.Field("id") + " = " + Tables.AttributeKeyAccessGrants.WithoutSchema().Name() + ".key_access_server_id")
	}
	if opts.withFqn {
		sb = sb.LeftJoin(fqnt.Name() + " ON " + fqnt.Field("attribute_id") + " = " + t.Field("id") +
			" AND " + fqnt.Field("value_id") + " IS NULL")
	}
	if opts.withOneValueByFqn != "" {
		sb = sb.LeftJoin(fqnt.Name() + " ON " + fqnt.Field("attribute_id") + " = " + t.Field("id")).
			LeftJoin("(SELECT " +
				avt.Field("id") + " AS av_id," +
				"JSON_AGG(JSON_BUILD_OBJECT(" +
				"'id', " + smT.Field("id") + "," +
				"'actions', " + smT.Field("actions") + "," +
				constructMetadata(smT.Name(), true) +
				"'subject_condition_set', JSON_BUILD_OBJECT(" +
				"'id', " + scsT.Field("id") + "," +
				constructMetadata(scsT.Name(), true) +
				"'subject_sets', " + scsT.Field("condition") +
				")" +
				")) AS sub_maps_arr " +
				", inner_fqns.fqn AS fqn " +
				"FROM " + smT.Name() + " " +
				"LEFT JOIN " + avt.Name() + " ON " + smT.Field("attribute_value_id") + " = " + avt.Field("id") + " " +
				"LEFT JOIN " + scsT.Name() + " ON " + smT.Field("subject_condition_set_id") + " = " + scsT.Field("id") + " " +
				"INNER JOIN " + fqnt.Name() + " AS inner_fqns ON " + avt.Field("id") + " = inner_fqns.value_id " +
				"WHERE inner_fqns.fqn = '" + opts.withOneValueByFqn + "' " +
				"GROUP BY " + avt.Field("id") + ", inner_fqns.fqn " +
				") AS val_sm_fqn_join ON " + "avt.id" + " = val_sm_fqn_join.av_id " +
				"AND " + "avt.id" + " = " + fqnt.Field("value_id"),
			)
	}
	g := []string{t.Field("id"), nt.Field("name")}

	if opts.withFqn {
		g = append(g, fqnt.Field("fqn"))
	}

	return sb.GroupBy(g...)
}

func attributesHydrateItem(row pgx.Row, opts attributesSelectOptions) (*policy.Attribute, error) {
	if opts.withKeyAccessGrants {
		opts.withAttributeValues = true
	}

	var (
		id            string
		name          string
		rule          string
		metadataJSON  []byte
		namespaceId   string
		active        bool
		namespaceName string
		valuesJSON    []byte
		valuesOrder   []string
		grants        []byte
		fqn           sql.NullString
	)

	fields := []interface{}{&id, &name, &rule, &metadataJSON, &namespaceId, &active, &namespaceName}
	if opts.withAttributeValues || opts.withOneValueByFqn != "" {
		fields = append(fields, &valuesOrder, &valuesJSON)
	}
	if opts.withKeyAccessGrants {
		fields = append(fields, &grants)
	}
	if opts.withFqn {
		fields = append(fields, &fqn)
	}

	err := row.Scan(fields...)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	m := &common.Metadata{}
	if metadataJSON != nil {
		if err := protojson.Unmarshal(metadataJSON, m); err != nil {
			slog.Error("could not unmarshal metadata", slog.String("error", err.Error()))
			return nil, err
		}
	}
	var v []*policy.Value
	if valuesJSON != nil {
		v, err = attributesValuesProtojson(valuesJSON)
		if err != nil {
			slog.Error("could not unmarshal values", slog.String("error", err.Error()))
			return nil, err
		}
	}
	var k []*policy.KeyAccessServer
	if grants != nil {
		k, err = db.KeyAccessServerProtoJSON(grants)
		if err != nil {
			slog.Error("could not unmarshal key access grants", slog.String("error", err.Error()))
			return nil, err
		}
	}

	attr := &policy.Attribute{
		Id:        id,
		Name:      name,
		Rule:      attributesRuleTypeEnumTransformOut(rule),
		Active:    &wrapperspb.BoolValue{Value: active},
		Metadata:  m,
		Namespace: &policy.Namespace{Id: namespaceId, Name: namespaceName},
		Grants:    k,
		Fqn:       fqn.String,
	}

	// In Go, 0 is not equal to 0, so check if they're not equal and more than 0. If so, then the values_order column
	// on the attribute_definition table does not match the number of values, which is a problem but should not fail the query.
	if len(v) > 0 && len(valuesOrder) > 0 && len(valuesOrder) != len(v) {
		slog.Warn("attribute's values order and number of values do not match - DB is in potentially bad state", slog.String("attribute definition id", id), slog.Any("expected values order", valuesOrder), slog.Any("retrieved values", v))
		attr.Values = v
	} else {
		// sort the values according to the order
		ordered := make([]*policy.Value, len(v))
		for i, order := range valuesOrder {
			for _, value := range v {
				if value.GetId() == order {
					ordered[i] = value
					break
				}
			}
		}
		attr.Values = ordered
	}

	return attr, nil
}

func attributesHydrateList(rows pgx.Rows, opts attributesSelectOptions) ([]*policy.Attribute, error) {
	list := make([]*policy.Attribute, 0)
	for rows.Next() {
		attr, err := attributesHydrateItem(rows, opts)
		if err != nil {
			return nil, err
		}
		list = append(list, attr)
	}
	return list, nil
}

///
// CRUD operations
///

func listAllAttributesSql(opts attributesSelectOptions) (string, []interface{}, error) {
	t := Tables.Attributes
	sb := attributesSelect(opts).
		From(t.Name())

	if opts.state != "" && opts.state != StateAny {
		sb = sb.Where(sq.Eq{t.Field("active"): opts.state == StateActive})
	}

	if opts.namespace != "" {
		_, err := uuid.Parse(opts.namespace)
		if err == nil {
			sb = sb.Where(sq.Eq{t.Field("namespace_id"): opts.namespace})
		} else {
			sb = sb.Where(sq.Eq{Tables.Namespaces.Field("name"): opts.namespace})
		}
	}
	return sb.ToSql()
}

func (c PolicyDBClient) ListAllAttributes(ctx context.Context, state string, namespace string) ([]*policy.Attribute, error) {
	opts := attributesSelectOptions{
		withAttributeValues: true,
		withKeyAccessGrants: false,
		withFqn:             true,
		state:               state,
		namespace:           namespace,
	}

	sql, args, err := listAllAttributesSql(opts)
	if err != nil {
		return nil, err
	}
	slog.Info("list all attributes", slog.String("sql", sql), slog.Any("args", args))

	rows, err := c.Query(ctx, sql, args)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	defer rows.Close()

	list, err := attributesHydrateList(rows, opts)
	if err != nil {
		slog.Error("could not hydrate list", slog.String("error", err.Error()))
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return list, nil
}

func (c PolicyDBClient) ListAllAttributesWithout(ctx context.Context, state string) ([]*policy.Attribute, error) {
	opts := attributesSelectOptions{
		withAttributeValues: false,
		withKeyAccessGrants: false,
		withFqn:             true,
		state:               state,
	}

	sql, args, err := listAllAttributesSql(opts)
	if err != nil {
		return nil, err
	}

	rows, err := c.Query(ctx, sql, args)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	defer rows.Close()

	list, err := attributesHydrateList(rows, opts)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	slog.Info("list", slog.Any("list", list))

	return list, nil
}

func getAttributeSql(id string, opts attributesSelectOptions) (string, []interface{}, error) {
	t := Tables.Attributes
	return attributesSelect(opts).
		Where(sq.Eq{t.Field("id"): id}).
		From(t.Name()).
		ToSql()
}

func (c PolicyDBClient) GetAttribute(ctx context.Context, id string) (*policy.Attribute, error) {
	opts := attributesSelectOptions{
		withFqn:             true,
		withAttributeValues: true,
	}
	sql, args, err := getAttributeSql(id, opts)
	if err != nil {
		return nil, err
	}

	row, err := c.QueryRow(ctx, sql, args)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	attribute, err := attributesHydrateItem(row, opts)
	if err != nil {
		slog.Error("could not hydrate item", slog.String("attributeId", id), slog.String("error", err.Error()))
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return attribute, nil
}

// / Get attribute by fqn
func getAttributeByFqnSql(fqn string, opts attributesSelectOptions) (string, []interface{}, error) {
	return attributesSelect(opts).
		Where(sq.Eq{Tables.AttrFqn.Field("fqn"): fqn}).
		From(Tables.Attributes.Name()).
		ToSql()
}

func (c PolicyDBClient) GetAttributeByFqn(ctx context.Context, fqn string) (*policy.Attribute, error) {
	opts := attributesSelectOptions{
		withAttributeValues: true,
		withKeyAccessGrants: false,
	}
	if strings.Contains(fqn, "/value/") {
		opts.withOneValueByFqn = fqn
	} else {
		opts.withFqn = true
	}
	sql, args, err := getAttributeByFqnSql(fqn, opts)
	if err != nil {
		return nil, err
	}

	row, err := c.QueryRow(ctx, sql, args)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	attribute, err := attributesHydrateItem(row, opts)
	if err != nil {
		slog.Error("could not hydrate item", slog.String("fqn", fqn), slog.String("error", err.Error()))
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	return attribute, nil
}

func getAttributesByNamespaceSql(namespaceId string, opts attributesSelectOptions) (string, []interface{}, error) {
	t := Tables.Attributes
	return attributesSelect(opts).
		Where(sq.Eq{t.Field("namespace_id"): namespaceId}).
		From(t.Name()).
		ToSql()
}

func (c PolicyDBClient) GetAttributesByNamespace(ctx context.Context, namespaceID string) ([]*policy.Attribute, error) {
	opts := attributesSelectOptions{}
	sql, args, err := getAttributesByNamespaceSql(namespaceID, opts)
	if err != nil {
		return nil, err
	}

	rows, err := c.Query(ctx, sql, args)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	defer rows.Close()

	list, err := attributesHydrateList(rows, opts)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return list, nil
}

func createAttributeSql(namespaceId string, name string, rule string, metadata []byte) (string, []interface{}, error) {
	t := Tables.Attributes
	return db.NewStatementBuilder().
		Insert(t.Name()).
		Columns("namespace_id", "name", "rule", "metadata").
		Values(namespaceId, name, rule, metadata).
		Suffix(createSuffix).
		ToSql()
}

func (c PolicyDBClient) CreateAttribute(ctx context.Context, r *attributes.CreateAttributeRequest) (*policy.Attribute, error) {
	metadataJSON, metadata, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	name := strings.ToLower(r.GetName())

	sql, args, err := createAttributeSql(r.GetNamespaceId(), name, attributesRuleTypeEnumTransformIn(r.GetRule().String()), metadataJSON)
	if err != nil {
		return nil, err
	}

	var id string
	if r, err := c.QueryRow(ctx, sql, args); err != nil {
		return nil, err
	} else if err := r.Scan(&id, &metadataJSON); err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if err = unmarshalMetadata(metadataJSON, metadata); err != nil {
		return nil, err
	}

	// Update the FQN
	c.upsertAttrFqn(ctx, attrFqnUpsertOptions{attributeId: id})

	// Add values
	var values []*policy.Value
	for _, v := range r.GetValues() {
		req := &attributes.CreateAttributeValueRequest{AttributeId: id, Value: v}
		value, err := c.CreateAttributeValue(ctx, id, req)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}

	a := &policy.Attribute{
		Id:       id,
		Name:     name,
		Rule:     r.GetRule(),
		Metadata: metadata,
		Namespace: &policy.Namespace{
			Id: r.GetNamespaceId(),
		},
		Active: &wrapperspb.BoolValue{Value: true},
		Values: values,
	}
	return a, nil
}

// TODO: uncomment this and consume when unsafe protos/service is implemented [https://github.com/opentdf/platform/issues/115]
// func unsafeUpdateAttributeSql(id string, updateName string, updateRule string, replaceValuesOrder []string, metadata []byte) (string, []interface{}, error) {
// 	t := Tables.Attributes
// 	sb := db.NewStatementBuilder().Update(t.Name())

// 	if updateName != "" {
// 		sb = sb.Set("name", updateName)
// 	}
// 	if updateRule != "" {
// 		sb = sb.Set("rule", updateRule)
// 	}
// 	// validation should happen before calling that:
// 	// 1) replaceValuesOrder should be the same length as the column's current array length
// 	// 2) replaceValuesOrder should contain all children value id's of this attribute
// 	if len(replaceValuesOrder) > 0 {
// 		sb = sb.Set("values_order", replaceValuesOrder)
// 	}
// 	if metadata != nil {
// 		sb = sb.Set("metadata", metadata)
// 	}

// 	return sb.Where(sq.Eq{t.Field("id"): id}).ToSql()
// }

func safeUpdateAttributeSql(id string, metadata []byte) (string, []interface{}, error) {
	t := Tables.Attributes
	sb := db.NewStatementBuilder().Update(t.Name())

	if metadata != nil {
		sb = sb.Set("metadata", metadata)
	}

	return sb.Where(sq.Eq{t.Field("id"): id}).ToSql()
}

func (c PolicyDBClient) UpdateAttribute(ctx context.Context, id string, r *attributes.UpdateAttributeRequest) (*policy.Attribute, error) {
	// if extend we need to merge the metadata
	metadataJSON, _, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		a, err := c.GetAttribute(ctx, id)
		if err != nil {
			return nil, err
		}
		return a.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	sql, args, err := safeUpdateAttributeSql(id, metadataJSON)
	if db.IsQueryBuilderSetClauseError(err) {
		return &policy.Attribute{
			Id: id,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	// Update the FQN
	c.upsertAttrFqn(ctx, attrFqnUpsertOptions{attributeId: id})

	return &policy.Attribute{
		Id: id,
	}, nil
}

func deactivateAttributeSql(id string) (string, []interface{}, error) {
	t := Tables.Attributes
	return db.NewStatementBuilder().
		Update(t.Name()).
		Set("active", false).
		Where(sq.Eq{t.Field("id"): id}).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c PolicyDBClient) DeactivateAttribute(ctx context.Context, id string) (*policy.Attribute, error) {
	sql, args, err := deactivateAttributeSql(id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}
	return c.GetAttribute(ctx, id)
}

func deleteAttributeSql(id string) (string, []interface{}, error) {
	t := Tables.Attributes
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c PolicyDBClient) DeleteAttribute(ctx context.Context, id string) (*policy.Attribute, error) {
	// get attribute before deleting
	a, err := c.GetAttribute(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	sql, args, err := deleteAttributeSql(id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	// return the attribute before deleting
	return a, nil
}

func assignKeyAccessServerToAttributeSql(attributeID, keyAccessServerID string) (string, []interface{}, error) {
	t := Tables.AttributeKeyAccessGrants
	return db.NewStatementBuilder().
		Insert(t.Name()).
		Columns("attribute_definition_id", "key_access_server_id").
		Values(attributeID, keyAccessServerID).
		ToSql()
}

func (c PolicyDBClient) AssignKeyAccessServerToAttribute(ctx context.Context, k *attributes.AttributeKeyAccessServer) (*attributes.AttributeKeyAccessServer, error) {
	sql, args, err := assignKeyAccessServerToAttributeSql(k.GetAttributeId(), k.GetKeyAccessServerId())
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return k, nil
}

func removeKeyAccessServerFromAttributeSql(attributeID, keyAccessServerID string) (string, []interface{}, error) {
	t := Tables.AttributeKeyAccessGrants
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{"attribute_definition_id": attributeID, "key_access_server_id": keyAccessServerID}).
		Suffix("IS TRUE RETURNING *").
		ToSql()
}

func (c PolicyDBClient) RemoveKeyAccessServerFromAttribute(ctx context.Context, k *attributes.AttributeKeyAccessServer) (*attributes.AttributeKeyAccessServer, error) {
	sql, args, err := removeKeyAccessServerFromAttributeSql(k.GetAttributeId(), k.GetKeyAccessServerId())
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return k, nil
}
