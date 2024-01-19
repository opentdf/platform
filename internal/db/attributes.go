package db

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/opentdf-v2-poc/sdk/attributes"
)

var AttributeTable = Schema + "." + TableAttributes
var AttributeValueTable = Schema + "." + TableAttributeValues

func tableField(table string, field string) string {
	return table + "." + field
}

func selectAttributeValue() sq.SelectBuilder {
	return newStatementBuilder().Select(
		tableField(AttributeTable, "id"),
		tableField(AttributeTable, "name"),
		tableField(AttributeTable, "rule"),
		tableField(AttributeTable, "metadata"),
		`JSON_AGG(
			JSON_BUILD_OBJECT(
				'id', `+tableField(AttributeValueTable, "id")+`,
				'value', `+tableField(AttributeValueTable, "value")+`,
				'members', `+tableField(AttributeValueTable, "members")+`
			)
		) AS values`,
	).Join(AttributeValueTable + " ON " + AttributeValueTable + ".id = " + AttributeTable + ".id")
}

func listAllAttributesSql() (string, []interface{}, error) {
	return selectAttributeValue().
		From(AttributeTable).
		ToSql()
}
func (c Client) ListAllAttributes(ctx context.Context) (pgx.Rows, error) {
	sql, args, err := listAllAttributesSql()
	return c.query(ctx, sql, args, err)
}

func getAttributeSql(id string) (string, []interface{}, error) {
	return selectAttributeValue().
		Where(sq.Eq{"id": id}).
		From(AttributeValueTable).
		ToSql()
}
func (c Client) GetAttribute(ctx context.Context, id string) (pgx.Row, error) {
	sql, args, err := getAttributeSql(id)
	return c.queryRow(ctx, sql, args, err)
}

func getAttributesByNamespaceSql(namespaceId string) (string, []interface{}, error) {
	return selectAttributeValue().
		Where(sq.Eq{"namespace_id": namespaceId}).
		From(AttributeTable).
		ToSql()
}
func (c Client) GetAttributesByNamespace(ctx context.Context, namespaceId string) (pgx.Rows, error) {
	sql, args, err := getAttributesByNamespaceSql(namespaceId)
	return c.query(ctx, sql, args, err)
}

func createAttributeSql(namespaceId string, name string, rule string, metadata []byte) (string, []interface{}, error) {
	return newStatementBuilder().
		Insert(AttributeValueTable).
		Columns("namespace_id", "name", "rule", "metadata").
		Values(namespaceId, name, rule, metadata).
		ToSql()
}
func (c Client) CreateAttribute(ctx context.Context, attr *attributes.AttributeCreateUpdate) error {
	metadata, err := marshalPolicyMetadata(attr.Metadata)
	if err != nil {
		return err
	}
	sql, args, err := createAttributeSql(attr.NamespaceId, attr.Name, removeProtobufEnumPrefix(attr.Rule.String()), metadata)
	return c.exec(ctx, sql, args, err)
}

func updateAttributeSql(id string, name string, rule string, metadata []byte) (string, []interface{}, error) {
	return newStatementBuilder().
		Update(AttributeTable).
		Set("name", name).
		Set("rule", rule).
		Set("metadata", metadata).
		Where(sq.Eq{"id": id}).
		ToSql()
}
func (c Client) UpdateAttribute(ctx context.Context, id string, attr *attributes.AttributeCreateUpdate) error {
	metadata, err := marshalPolicyMetadata(attr.Metadata)
	if err != nil {
		return err
	}
	sql, args, err := updateAttributeSql(id, attr.Name, removeProtobufEnumPrefix(attr.Rule.String()), metadata)
	return c.exec(ctx, sql, args, err)
}

func deleteAttributeSql(id string) (string, []interface{}, error) {
	return newStatementBuilder().
		Delete(AttributeTable).
		Where(sq.Eq{"id": id}).
		ToSql()
}
func (c Client) DeleteAttribute(ctx context.Context, id string) error {
	sql, args, err := deleteAttributeSql(id)
	return c.exec(ctx, sql, args, err)
}
