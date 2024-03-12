package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"strings"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	kasrDb "github.com/opentdf/platform/services/kasregistry/db"
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

func attributesValuesProtojson(valuesJson []byte) ([]*policy.Value, error) {
	var (
		raw    []json.RawMessage
		values []*policy.Value
	)
	if err := json.Unmarshal(valuesJson, &raw); err != nil {
		return nil, err
	}

	for _, r := range raw {
		value := policy.Value{}
		if err := protojson.Unmarshal(r, &value); err != nil {
			return nil, err
		}
		values = append(values, &value)
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
		t.Field("metadata"),
		t.Field("namespace_id"),
		t.Field("active"),
		nt.Field("name"),
	}
	if opts.withAttributeValues || opts.withOneValueByFqn != "" {
		valueSelect := "JSON_AGG(" +
			"JSON_BUILD_OBJECT(" +
			"'id', " + avt.Field("id") + ", " +
			"'value', " + avt.Field("value") + "," +
			"'members', " + avt.Field("members") + "," +
			"'active', " + avt.Field("active")

		// include the subject mapping / subject condition set for each value
		if opts.withOneValueByFqn != "" {
			valueSelect += ", 'fqn', val_sm_fqn_join.fqn, " +
				"'subject_mappings', sub_maps_arr"
		}
		valueSelect += ")) AS values"
		selectFields = append(selectFields, valueSelect)
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
			"FROM "+kasrDb.Tables.KeyAccessServerRegistry.Name()+" kas "+
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
		sb = sb.LeftJoin(avt.Name() + " ON " + avt.Field("attribute_definition_id") + " = " + t.Field("id"))
	}
	if opts.withKeyAccessGrants {
		sb = sb.LeftJoin(Tables.AttributeKeyAccessGrants.Name() + " ON " + Tables.AttributeKeyAccessGrants.WithoutSchema().Name() + ".attribute_definition_id = " + t.Field("id")).
			LeftJoin(kasrDb.Tables.KeyAccessServerRegistry.Name() + " ON " + kasrDb.Tables.KeyAccessServerRegistry.Field("id") + " = " + Tables.AttributeKeyAccessGrants.WithoutSchema().Name() + ".key_access_server_id")
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
				"'metadata', " + smT.Field("metadata") + "," +
				"'subject_condition_set', JSON_BUILD_OBJECT(" +
				"'id', " + scsT.Field("id") + "," +
				"'metadata', " + scsT.Field("metadata") + "," +
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
				") AS val_sm_fqn_join ON " + avt.Field("id") + " = val_sm_fqn_join.av_id " +
				"AND " + avt.Field("id") + " = " + fqnt.Field("value_id"),
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
		metadataJson  []byte
		namespaceId   string
		active        bool
		namespaceName string
		valuesJson    []byte
		grants        []byte
		fqn           sql.NullString
	)

	fields := []interface{}{&id, &name, &rule, &metadataJson, &namespaceId, &active, &namespaceName}
	if opts.withAttributeValues || opts.withOneValueByFqn != "" {
		fields = append(fields, &valuesJson)
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
	if metadataJson != nil {
		if err := protojson.Unmarshal(metadataJson, m); err != nil {
			slog.Error("could not unmarshal metadata", slog.String("error", err.Error()))
			return nil, err
		}
	}

	var v []*policy.Value
	if valuesJson != nil {
		v, err = attributesValuesProtojson(valuesJson)
		if err != nil {
			slog.Error("could not unmarshal values", slog.String("error", err.Error()))
			return nil, err
		}
	}
	var k []*kasregistry.KeyAccessServer
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
		Values:    v,
		Namespace: &policy.Namespace{Id: namespaceId, Name: namespaceName},
		Grants:    k,
		Fqn:       fqn.String,
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
	return sb.ToSql()
}

func (c PolicyDbClient) ListAllAttributes(ctx context.Context, state string) ([]*policy.Attribute, error) {
	opts := attributesSelectOptions{
		withAttributeValues: true,
		withKeyAccessGrants: false,
		withFqn:             true,
		state:               state,
	}

	sql, args, err := listAllAttributesSql(opts)
	slog.Info("list all attributes", slog.String("sql", sql), slog.Any("args", args))
	rows, err := c.Query(ctx, sql, args, err)
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

func (c PolicyDbClient) ListAllAttributesWithout(ctx context.Context, state string) ([]*policy.Attribute, error) {
	opts := attributesSelectOptions{
		withAttributeValues: false,
		withKeyAccessGrants: false,
		withFqn:             true,
		state:               state,
	}

	sql, args, err := listAllAttributesSql(opts)
	rows, err := c.Query(ctx, sql, args, err)
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

func (c PolicyDbClient) GetAttribute(ctx context.Context, id string) (*policy.Attribute, error) {
	opts := attributesSelectOptions{
		withFqn: true,
	}
	sql, args, err := getAttributeSql(id, opts)
	row, err := c.QueryRow(ctx, sql, args, err)
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

func (c PolicyDbClient) GetAttributeByFqn(ctx context.Context, fqn string) (*policy.Attribute, error) {
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
	row, err := c.QueryRow(ctx, sql, args, err)
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

func (c PolicyDbClient) GetAttributesByNamespace(ctx context.Context, namespaceId string) ([]*policy.Attribute, error) {
	opts := attributesSelectOptions{}
	sql, args, err := getAttributesByNamespaceSql(namespaceId, opts)

	rows, err := c.Query(ctx, sql, args, err)
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
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c PolicyDbClient) CreateAttribute(ctx context.Context, r *attributes.CreateAttributeRequest) (*policy.Attribute, error) {
	metadataJson, metadata, err := db.MarshalCreateMetadata(r.Metadata)
	if err != nil {
		return nil, err
	}

	sql, args, err := createAttributeSql(r.NamespaceId, r.Name, attributesRuleTypeEnumTransformIn(r.Rule.String()), metadataJson)
	var id string
	if r, err := c.QueryRow(ctx, sql, args, err); err != nil {
		return nil, err
	} else if err := r.Scan(&id); err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	// Update the FQN
	c.upsertAttrFqn(ctx, attrFqnUpsertOptions{attributeId: id})

	a := &policy.Attribute{
		Id:       id,
		Name:     r.Name,
		Rule:     r.Rule,
		Metadata: metadata,
		Namespace: &policy.Namespace{
			Id: r.NamespaceId,
		},
		Active: &wrapperspb.BoolValue{Value: true},
	}
	return a, nil
}

func updateAttributeSql(id string, metadata []byte) (string, []interface{}, error) {
	t := Tables.Attributes
	sb := db.NewStatementBuilder().Update(t.Name())

	if metadata != nil {
		sb = sb.Set("metadata", metadata)
	}

	return sb.Where(sq.Eq{t.Field("id"): id}).ToSql()
}

func (c PolicyDbClient) UpdateAttribute(ctx context.Context, id string, r *attributes.UpdateAttributeRequest) (*policy.Attribute, error) {
	// if extend we need to merge the metadata
	metadataJson, _, err := db.MarshalUpdateMetadata(r.Metadata, r.MetadataUpdateBehavior, func() (*common.Metadata, error) {
		a, err := c.GetAttribute(ctx, id)
		if err != nil {
			return nil, err
		}
		return a.Metadata, nil
	})
	if err != nil {
		return nil, err
	}

	sql, args, err := updateAttributeSql(id, metadataJson)
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

func (c PolicyDbClient) DeactivateAttribute(ctx context.Context, id string) (*policy.Attribute, error) {
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

func (c PolicyDbClient) DeleteAttribute(ctx context.Context, id string) (*policy.Attribute, error) {
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

func (c PolicyDbClient) AssignKeyAccessServerToAttribute(ctx context.Context, k *attributes.AttributeKeyAccessServer) (*attributes.AttributeKeyAccessServer, error) {
	sql, args, err := assignKeyAccessServerToAttributeSql(k.AttributeId, k.KeyAccessServerId)
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

func (c PolicyDbClient) RemoveKeyAccessServerFromAttribute(ctx context.Context, k *attributes.AttributeKeyAccessServer) (*attributes.AttributeKeyAccessServer, error) {
	sql, args, err := removeKeyAccessServerFromAttributeSql(k.AttributeId, k.KeyAccessServerId)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return k, nil
}
