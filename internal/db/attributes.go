package db

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/opentdf-v2-poc/sdk/attributes"
)

func listAllAttributesSql() (string, []interface{}, error) {
	return newStatementBuilder().
		Select("*").
		Join("attribute_definitions ON attribute_definitions.id = attribute_values.id").
		From("attribute_values").
		ToSql()
}
func (c Client) ListAllAttributes(ctx context.Context) (pgx.Rows, error) {
	sql, args, err := listAllAttributesSql()
	return c.query(ctx, sql, args, err)
}

func getAttributeByDefinitionSql(id string) (string, []interface{}, error) {
	return newStatementBuilder().
		Select("*").
		Join("attribute_definitions ON attribute_definitions.id = attribute_values.id").
		Where(sq.Eq{"id": id}).
		From("attribute_values").
		ToSql()
}
func (c Client) GetAttribute(ctx context.Context, id string) (pgx.Row, error) {
	sql, args, err := getAttributeByDefinitionSql(id)
	return c.queryRow(ctx, sql, args, err)
}

func getAttributesByNamespaceSql(namespaceId string) (string, []interface{}, error) {
	return newStatementBuilder().
		Select("*").
		Join("attribute_definitions ON attribute_definitions.id = attribute_values.id").
		Where(sq.Eq{"namespace_id": namespaceId}).
		From("attribute_values").
		ToSql()
}
func (c Client) GetAttributesByNamespace(ctx context.Context, namespaceId string) (pgx.Rows, error) {
	sql, args, err := getAttributesByNamespaceSql(namespaceId)
	return c.query(ctx, sql, args, err)
}

func createAttributeSql(namespaceId string, name string, rule string, metadata []byte) (string, []interface{}, error) {
	return newStatementBuilder().
		Insert("attribute_values").
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
