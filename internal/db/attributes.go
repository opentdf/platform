package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/opentdf-v2-poc/sdk/attributes"
	"github.com/opentdf/opentdf-v2-poc/sdk/common"
	"github.com/opentdf/opentdf-v2-poc/sdk/kasregistry"
	"github.com/opentdf/opentdf-v2-poc/sdk/namespaces"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	AttributeRuleTypeEnumPrefix = "ATTRIBUTE_RULE_TYPE_ENUM_"
)

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
}

func attributesSelect(opts attributesSelectOptions) sq.SelectBuilder {
	t := Tables.Attributes
	nt := Tables.Namespaces
	avt := Tables.AttributeValues
	// akt := Tables.AttributeKeyAccessGrants
	// avkt := Tables.AttributeKeyAccessGrants
	selectFields := []string{
		t.Field("id"),
		t.Field("name"),
		t.Field("rule"),
		t.Field("metadata"),
		t.Field("namespace_id"),
		nt.Field("name"),
	}
	if opts.withAttributeValues {
		selectFields = append(selectFields, "JSON_AGG("+
			"JSON_BUILD_OBJECT("+
			"'id', "+avt.Field("id")+", "+
			"'value', "+avt.Field("value")+","+
			"'members', "+avt.Field("members")+
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
			"FROM "+KeyAccessServerTable+" kas "+
			"JOIN "+Tables.AttributeValueKeyAccessGrants.Name()+" avkag ON avkag.key_access_server_id = kas.id "+
			"WHERE avkag.attribute_value_id = "+avt.Field("id")+
			")"+
			")) AS values")
	}

	b := newStatementBuilder().Select(selectFields...).
		LeftJoin(nt.Name() + " ON " + nt.Field("id") + " = " + t.Field("namespace_id"))

	if opts.withAttributeValues {
		b = b.LeftJoin(avt.Name() + " ON " + avt.Field("attribute_definition_id") + " = " + t.Field("id"))
	}
	if opts.withKeyAccessGrants {
		b = b.LeftJoin(Tables.AttributeKeyAccessGrants.Name() + " ON " + Tables.AttributeKeyAccessGrants.WithoutSchema().Name() + ".attribute_definition_id = " + t.Field("id")).
			LeftJoin(KeyAccessServerTable + " ON " + KeyAccessServerTable + ".id = " + Tables.AttributeKeyAccessGrants.WithoutSchema().Name() + ".key_access_server_id")
	}
	return b.GroupBy(t.Field("id"), nt.Field("name"))
}

func attributesHydrateItem(row pgx.Row, opts attributesSelectOptions) (*attributes.Attribute, error) {
	var (
		id            string
		name          string
		rule          string
		metadataJson  []byte
		namespaceId   string
		namespaceName string
		valuesJson    []byte
		grants        []byte
	)

	fields := []interface{}{&id, &name, &rule, &metadataJson, &namespaceId, &namespaceName}
	if opts.withAttributeValues {
		fields = append(fields, &valuesJson)
	}
	if opts.withKeyAccessGrants {
		fields = append(fields, &grants)
	}

	err := row.Scan(fields...)
	if err != nil {
		return nil, WrapIfKnownInvalidQueryErr(err)
	}

	m := &common.Metadata{}
	if metadataJson != nil {
		if err := protojson.Unmarshal(metadataJson, m); err != nil {
			return nil, err
		}
	}

	var v []*attributes.Value
	if valuesJson != nil {
		v, err = attributesValuesProtojson(valuesJson)
		if err != nil {
			return nil, err
		}
	}
	var k []*kasregistry.KeyAccessServer
	if grants != nil {
		k, err = keyAccessServerProtojson(grants)
		if err != nil {
			return nil, err
		}
	}

	attr := &attributes.Attribute{
		Id:        id,
		Name:      name,
		Rule:      attributesRuleTypeEnumTransformOut(rule),
		Metadata:  m,
		Values:    v,
		Namespace: &namespaces.Namespace{Id: namespaceId, Name: namespaceName},
		Grants:    k,
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
	t := Tables.Attributes
	return attributesSelect(opts).
		From(t.Name()).
		ToSql()
}

func (c Client) ListAllAttributes(ctx context.Context) ([]*attributes.Attribute, error) {
	opts := attributesSelectOptions{
		withAttributeValues: true,
		withKeyAccessGrants: true,
	}
	sql, args, err := listAllAttributesSql(opts)
	rows, err := c.query(ctx, sql, args, err)
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

func (c Client) ListAllAttributesWithout(ctx context.Context) ([]*attributes.Attribute, error) {
	sql, args, err := listAllAttributesSql(attributesSelectOptions{
		withAttributeValues: false,
		withKeyAccessGrants: false,
	})
	rows, err := c.query(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list, err := attributesHydrateList(rows, attributesSelectOptions{})
	if err != nil {
		return nil, err
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

func (c Client) GetAttribute(ctx context.Context, id string) (*attributes.Attribute, error) {
	opts := attributesSelectOptions{}
	sql, args, err := getAttributeSql(id, opts)
	row, err := c.queryRow(ctx, sql, args, err)
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

func getAttributesByNamespaceSql(namespaceId string, opts attributesSelectOptions) (string, []interface{}, error) {
	t := Tables.Attributes
	return attributesSelect(opts).
		Where(sq.Eq{t.Field("namespace_id"): namespaceId}).
		From(t.Name()).
		ToSql()
}

func (c Client) GetAttributesByNamespace(ctx context.Context, namespaceId string) ([]*attributes.Attribute, error) {
	opts := attributesSelectOptions{}
	sql, args, err := getAttributesByNamespaceSql(namespaceId, opts)

	rows, err := c.query(ctx, sql, args, err)
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
	t := Tables.Attributes
	return newStatementBuilder().
		Insert(t.Name()).
		Columns("namespace_id", "name", "rule", "metadata").
		Values(namespaceId, name, rule, metadata).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c Client) CreateAttribute(ctx context.Context, attr *attributes.AttributeCreateUpdate) (*attributes.Attribute, error) {
	metadataJson, metadata, err := marshalCreateMetadata(attr.Metadata)
	if err != nil {
		return nil, err
	}

	sql, args, err := createAttributeSql(attr.NamespaceId, attr.Name, attributesRuleTypeEnumTransformIn(attr.Rule.String()), metadataJson)
	var id string
	if r, err := c.queryRow(ctx, sql, args, err); err != nil {
		return nil, err
	} else if err := r.Scan(&id); err != nil {
		return nil, WrapIfKnownInvalidQueryErr(err)
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
	}
	return a, nil
}

func updateAttributeSql(id string, name string, rule string, metadata []byte) (string, []interface{}, error) {
	t := Tables.Attributes
	sb := newStatementBuilder().
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

func (c Client) UpdateAttribute(ctx context.Context, id string, attr *attributes.AttributeCreateUpdate) (*attributes.Attribute, error) {
	// get attribute before updating
	a, err := c.GetAttribute(ctx, id)
	if err != nil {
		return nil, err
	}
	if a.Namespace.Id != attr.NamespaceId {
		return nil, errors.Join(ErrRestrictViolation, fmt.Errorf("cannot change namespaceId"))
	}

	metadataJson, _, err := marshalUpdateMetadata(a.Metadata, attr.Metadata)
	if err != nil {
		return nil, err
	}

	sql, args, err := updateAttributeSql(id, attr.Name, attributesRuleTypeEnumTransformIn(attr.Rule.String()), metadataJson)
	if err := c.exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	// Update the FQN
	c.upsertAttrFqn(ctx, attrFqnUpsertOptions{attributeId: id})

	// TODO: see if returning the old is the behavior we should consistently implement throughout services
	// return the attribute before updating
	return a, nil
}

func deleteAttributeSql(id string) (string, []interface{}, error) {
	t := Tables.Attributes
	return newStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c Client) DeleteAttribute(ctx context.Context, id string) (*attributes.Attribute, error) {
	// get attribute before deleting
	a, err := c.GetAttribute(ctx, id)
	if err != nil {
		return nil, err
	}

	sql, args, err := deleteAttributeSql(id)

	if err := c.exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	// return the attribute before deleting
	return a, nil
}

func assignKeyAccessServerToAttributeSql(attributeID, keyAccessServerID string) (string, []interface{}, error) {
	t := Tables.AttributeKeyAccessGrants
	return newStatementBuilder().
		Insert(t.Name()).
		Columns("attribute_definition_id", "key_access_server_id").
		Values(attributeID, keyAccessServerID).
		ToSql()
}

func (c Client) AssignKeyAccessServerToAttribute(ctx context.Context, k *attributes.AttributeKeyAccessServer) (*attributes.AttributeKeyAccessServer, error) {
	sql, args, err := assignKeyAccessServerToAttributeSql(k.AttributeId, k.KeyAccessServerId)

	if err := c.exec(ctx, sql, args, err); err != nil {
		return nil, err
	}

	return k, nil
}

func removeKeyAccessServerFromAttributeSql(attributeID, keyAccessServerID string) (string, []interface{}, error) {
	t := Tables.AttributeKeyAccessGrants
	return newStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{"attribute_definition_id": attributeID, "key_access_server_id": keyAccessServerID}).
		Suffix("IS TRUE RETURNING *").
		ToSql()
}

func (c Client) RemoveKeyAccessServerFromAttribute(ctx context.Context, k *attributes.AttributeKeyAccessServer) (*attributes.AttributeKeyAccessServer, error) {
	sql, args, err := removeKeyAccessServerFromAttributeSql(k.AttributeId, k.KeyAccessServerId)
	if err != nil {
		return nil, err
	}

	if _, err := c.queryCount(ctx, sql, args); err != nil {
		return nil, WrapIfKnownInvalidQueryErr(err)
	}

	return k, nil
}
