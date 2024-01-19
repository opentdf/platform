package db

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/opentdf-v2-poc/sdk/attributes"
)

func getAttributeByDefinitionSql(definition_id string) (string, []interface{}, error) {
	return newStatementBuilder().
		Select("*").
		Join("attribute_definitions ON attribute_definitions.id = attribute_values.id").
		Where(sq.Eq{"id": definition_id}).
		From("attribute_values").
		ToSql()
}
func (c Client) GetAttribute(ctx context.Context, definition_id string) (pgx.Row, error) {
	sql, args, err := getAttributeByDefinitionSql(definition_id)
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

func createAttributeSql(namespaceId string, name string, rule string) (string, []interface{}, error) {
	return newStatementBuilder().
		Insert("attribute_values").
		Columns("namespace_id", "name", "rule").
		Values(namespaceId, name, rule).
		ToSql()
}
func (c Client) CreateAttribute(ctx context.Context, def *attributes.Definition) error {
	sql, args, err := createAttributeSql(def.NamespaceId, def.Name, removeProtobufEnumPrefix(def.Rule.String()))
	return c.exec(ctx, sql, args, err)
}
