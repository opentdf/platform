package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var AttributeRuleTypeEnumPrefix = "ATTRIBUTE_RULE_TYPE_ENUM_"

func attributesRuleTypeEnumTransformIn(value string) string {
	return strings.TrimPrefix(value, AttributeRuleTypeEnumPrefix)
}

func attributesRuleTypeEnumTransformOut(value string) attributes.AttributeRuleTypeEnum {
	return attributes.AttributeRuleTypeEnum(attributes.AttributeRuleTypeEnum_value[AttributeRuleTypeEnumPrefix+value])
}

func attributesValuesProtojson(valuesJson []byte) ([]*attributes.Value, error) {
	var (
		raw    []json.RawMessage
		values []*attributes.Value
	)
	if err := json.Unmarshal(valuesJson, &raw); err != nil {
		return nil, err
	}

	for _, r := range raw {
		value := attributes.Value{}
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
	withOneValueByFqn bool
	state             string
}

func attributesSelect(opts attributesSelectOptions) sq.SelectBuilder {
	if opts.withKeyAccessGrants {
		opts.withAttributeValues = true
	}

	t := db.Tables.Attributes
	nt := db.Tables.Namespaces
	avt := db.Tables.AttributeValues
	fqnt := db.Tables.AttrFqn
	// akt := db.Tables.AttributeKeyAccessGrants
	// avkt := db.Tables.AttributeKeyAccessGrants
	selectFields := []string{
		t.Field("id"),
		t.Field("name"),
		t.Field("rule"),
		t.Field("metadata"),
		t.Field("namespace_id"),
		t.Field("active"),
		nt.Field("name"),
	}
	if opts.withAttributeValues || opts.withOneValueByFqn {
		selectFields = append(selectFields, "JSON_AGG("+
			"JSON_BUILD_OBJECT("+
			"'id', "+avt.Field("id")+", "+
			"'value', "+avt.Field("value")+","+
			"'members', "+avt.Field("members")+","+
			"'active', "+avt.Field("active")+
			")"+
			") AS values")
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
			"FROM "+db.Tables.KeyAccessServerRegistry.Name()+" kas "+
			"JOIN "+db.Tables.AttributeValueKeyAccessGrants.Name()+" avkag ON avkag.key_access_server_id = kas.id "+
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
		sb = sb.LeftJoin(db.Tables.AttributeKeyAccessGrants.Name() + " ON " + db.Tables.AttributeKeyAccessGrants.WithoutSchema().Name() + ".attribute_definition_id = " + t.Field("id")).
			LeftJoin(db.Tables.KeyAccessServerRegistry.Name() + " ON " + db.Tables.KeyAccessServerRegistry.Name() + ".id = " + db.Tables.AttributeKeyAccessGrants.WithoutSchema().Name() + ".key_access_server_id")
	}
	if opts.withFqn {
		sb = sb.LeftJoin(fqnt.Name() + " ON " + fqnt.Field("attribute_id") + " = " + t.Field("id") +
			" AND " + fqnt.Field("value_id") + " IS NULL")
	}
	if opts.withOneValueByFqn {
		sb = sb.LeftJoin(fqnt.Name() + " ON " + fqnt.Field("attribute_id") + " = " + t.Field("id") +
			" AND " + fqnt.Field("value_id") + " = " + avt.Field("id"))
	}

	g := []string{t.Field("id"), nt.Field("name")}

	if opts.withFqn {
		g = append(g, db.Tables.AttrFqn.Field("fqn"))
	}

	return sb.GroupBy(g...)
}

func attributesHydrateItem(row pgx.Row, opts attributesSelectOptions) (*attributes.Attribute, error) {
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
	if opts.withAttributeValues || opts.withOneValueByFqn {
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

	var v []*attributes.Value
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

	attr := &attributes.Attribute{
		Id:        id,
		Name:      name,
		Rule:      attributesRuleTypeEnumTransformOut(rule),
		Active:    &wrapperspb.BoolValue{Value: active},
		Metadata:  m,
		Values:    v,
		Namespace: &namespaces.Namespace{Id: namespaceId, Name: namespaceName},
		Grants:    k,
		Fqn:       fqn.String,
	}

	return attr, nil
}

func attributesHydrateList(rows pgx.Rows, opts attributesSelectOptions) ([]*attributes.Attribute, error) {
	list := make([]*attributes.Attribute, 0)
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
	t := db.Tables.Attributes
	sb := attributesSelect(opts).
		From(t.Name())

	if opts.state != "" && opts.state != StateAny {
		sb = sb.Where(sq.Eq{t.Field("active"): opts.state == StateActive})
	}
	return sb.ToSql()
}

func (c PolicyDbClient) ListAllAttributes(ctx context.Context, state string) ([]*attributes.Attribute, error) {
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
		return nil, err
	}
	defer rows.Close()

	list, err := attributesHydrateList(rows, opts)
	if err != nil {
		slog.Error("could not hydrate list", slog.String("error", err.Error()))
		return nil, err
	}

	return list, nil
}

func (c PolicyDbClient) ListAllAttributesWithout(ctx context.Context, state string) ([]*attributes.Attribute, error) {
	opts := attributesSelectOptions{
		withAttributeValues: false,
		withKeyAccessGrants: false,
		withFqn:             true,
		state:               state,
	}

	sql, args, err := listAllAttributesSql(opts)
	rows, err := c.Query(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list, err := attributesHydrateList(rows, opts)
	if err != nil {
		return nil, err
	}
	slog.Info("list", slog.Any("list", list))

	return list, nil
}

func getAttributeSql(id string, opts attributesSelectOptions) (string, []interface{}, error) {
	t := db.Tables.Attributes
	return attributesSelect(opts).
		Where(sq.Eq{t.Field("id"): id}).
		From(t.Name()).
		ToSql()
}

func (c PolicyDbClient) GetAttribute(ctx context.Context, id string) (*attributes.Attribute, error) {
	opts := attributesSelectOptions{
		withFqn: true,
	}
	sql, args, err := getAttributeSql(id, opts)
	row, err := c.QueryRow(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}

	attribute, err := attributesHydrateItem(row, opts)
	if err != nil {
		slog.Error("could not hydrate item", slog.String("attributeId", id), slog.String("error", err.Error()))
		return nil, err
	}

	return attribute, nil
}

// / Get attribute by fqn
func getAttributeByFqnSql(fqn string, opts attributesSelectOptions) (string, []interface{}, error) {
	return attributesSelect(opts).
		Where(sq.Eq{db.Tables.AttrFqn.Field("fqn"): fqn}).
		From(db.Tables.Attributes.Name()).
		ToSql()
}

func (c PolicyDbClient) GetAttributeByFqn(ctx context.Context, fqn string) (*attributes.Attribute, error) {
	opts := attributesSelectOptions{
		withAttributeValues: true,
		withKeyAccessGrants: false,
	}
	if strings.Contains(fqn, "/value/") {
		opts.withOneValueByFqn = true
	} else {
		opts.withFqn = true
	}
	sql, args, err := getAttributeByFqnSql(fqn, opts)
	row, err := c.QueryRow(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}

	attribute, err := attributesHydrateItem(row, opts)
	if err != nil {
		slog.Error("could not hydrate item", slog.String("fqn", fqn), slog.String("error", err.Error()))
		return nil, err
	}
	return attribute, nil
}

func getAttributesByNamespaceSql(namespaceId string, opts attributesSelectOptions) (string, []interface{}, error) {
	t := db.Tables.Attributes
	return attributesSelect(opts).
		Where(sq.Eq{t.Field("namespace_id"): namespaceId}).
		From(t.Name()).
		ToSql()
}

func (c PolicyDbClient) GetAttributesByNamespace(ctx context.Context, namespaceId string) ([]*attributes.Attribute, error) {
	opts := attributesSelectOptions{}
	sql, args, err := getAttributesByNamespaceSql(namespaceId, opts)

	rows, err := c.Query(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list, err := attributesHydrateList(rows, opts)
	if err != nil {
		return nil, err
	}

	return list, nil
}

func createAttributeSql(namespaceId string, name string, rule string, metadata []byte) (string, []interface{}, error) {
	t := db.Tables.Attributes
	return db.NewStatementBuilder().
		Insert(t.Name()).
		Columns("namespace_id", "name", "rule", "metadata").
		Values(namespaceId, name, rule, metadata).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c PolicyDbClient) CreateAttribute(ctx context.Context, attr *attributes.AttributeCreateUpdate) (*attributes.Attribute, error) {
	metadataJson, metadata, err := db.MarshalCreateMetadata(attr.Metadata)
	if err != nil {
		return nil, err
	}

	sql, args, err := createAttributeSql(attr.NamespaceId, attr.Name, attributesRuleTypeEnumTransformIn(attr.Rule.String()), metadataJson)
	var id string
	if r, err := c.QueryRow(ctx, sql, args, err); err != nil {
		return nil, err
	} else if err := r.Scan(&id); err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	// Update the FQN
	c.upsertAttrFqn(ctx, attrFqnUpsertOptions{attributeId: id})

	a := &attributes.Attribute{
		Id:       id,
		Name:     attr.Name,
		Rule:     attr.Rule,
		Metadata: metadata,
		Namespace: &namespaces.Namespace{
			Id: attr.NamespaceId,
		},
		Active: &wrapperspb.BoolValue{Value: true},
	}
	return a, nil
}

func updateAttributeSql(id string, name string, rule string, metadata []byte) (string, []interface{}, error) {
	t := db.Tables.Attributes
	sb := db.NewStatementBuilder().
		Update(t.Name())

	if name != "" {
		sb = sb.Set("name", name)
	}
	if rule != "" {
		sb = sb.Set("rule", rule)
	}

	return sb.Set("metadata", metadata).
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c PolicyDbClient) UpdateAttribute(ctx context.Context, id string, attr *attributes.AttributeCreateUpdate) (*attributes.Attribute, error) {
	// get attribute before updating
	a, err := c.GetAttribute(ctx, id)
	if err != nil {
		return nil, err
	}
	if a.Namespace.Id != attr.NamespaceId {
		return nil, errors.Join(db.ErrRestrictViolation, fmt.Errorf("cannot change namespaceId"))
	}

	metadataJson, _, err := db.MarshalUpdateMetadata(a.Metadata, attr.Metadata)
	if err != nil {
		return nil, err
	}

	sql, args, err := updateAttributeSql(id, attr.Name, attributesRuleTypeEnumTransformIn(attr.Rule.String()), metadataJson)
	if err := c.Exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	// Update the FQN
	c.upsertAttrFqn(ctx, attrFqnUpsertOptions{attributeId: id})

	// TODO: see if returning the old is the behavior we should consistently implement throughout services
	// return the attribute before updating
	return a, nil
}

func deactivateAttributeSql(id string) (string, []interface{}, error) {
	t := db.Tables.Attributes
	return db.NewStatementBuilder().
		Update(t.Name()).
		Set("active", false).
		Where(sq.Eq{t.Field("id"): id}).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c PolicyDbClient) DeactivateAttribute(ctx context.Context, id string) (*attributes.Attribute, error) {
	sql, args, err := deactivateAttributeSql(id)

	if err := c.Exec(ctx, sql, args, err); err != nil {
		return nil, err
	}
	return c.GetAttribute(ctx, id)
}

func deleteAttributeSql(id string) (string, []interface{}, error) {
	t := db.Tables.Attributes
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c PolicyDbClient) DeleteAttribute(ctx context.Context, id string) (*attributes.Attribute, error) {
	// get attribute before deleting
	a, err := c.GetAttribute(ctx, id)
	if err != nil {
		return nil, err
	}

	sql, args, err := deleteAttributeSql(id)

	if err := c.Exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	// return the attribute before deleting
	return a, nil
}

func assignKeyAccessServerToAttributeSql(attributeID, keyAccessServerID string) (string, []interface{}, error) {
	t := db.Tables.AttributeKeyAccessGrants
	return db.NewStatementBuilder().
		Insert(t.Name()).
		Columns("attribute_definition_id", "key_access_server_id").
		Values(attributeID, keyAccessServerID).
		ToSql()
}

func (c PolicyDbClient) AssignKeyAccessServerToAttribute(ctx context.Context, k *attributes.AttributeKeyAccessServer) (*attributes.AttributeKeyAccessServer, error) {
	sql, args, err := assignKeyAccessServerToAttributeSql(k.AttributeId, k.KeyAccessServerId)

	if err := c.Exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	return k, nil
}

func removeKeyAccessServerFromAttributeSql(attributeID, keyAccessServerID string) (string, []interface{}, error) {
	t := db.Tables.AttributeKeyAccessGrants
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{"attribute_definition_id": attributeID, "key_access_server_id": keyAccessServerID}).
		Suffix("IS TRUE RETURNING *").
		ToSql()
}

func (c PolicyDbClient) RemoveKeyAccessServerFromAttribute(ctx context.Context, k *attributes.AttributeKeyAccessServer) (*attributes.AttributeKeyAccessServer, error) {
	sql, args, err := removeKeyAccessServerFromAttributeSql(k.AttributeId, k.KeyAccessServerId)
	if err != nil {
		return nil, err
	}

	if _, err := c.QueryCount(ctx, sql, args); err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return k, nil
}
