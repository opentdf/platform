package db

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/opentdf-v2-poc/sdk/namespaces"
)

func getNamespaceSql(id string) (string, []interface{}, error) {
	return newStatementBuilder().
		Select("*").
		From("namespaces").
		Where(sq.Eq{"id": id}).
		ToSql()
}

func (c Client) GetNamespace(ctx context.Context, id string) (pgx.Row, error) {
	sql, args, err := getNamespaceSql(id)
	return c.queryRow(ctx, sql, args, err)
}

func listNamespacesSql() (string, []interface{}, error) {
	return newStatementBuilder().
		Select("*").
		From("namespaces").
		ToSql()
}

func (c Client) ListNamespaces(ctx context.Context) (pgx.Rows, error) {
	sql, args, err := listNamespacesSql()
	return c.query(ctx, sql, args, err)
}

func createNamespaceSql(namespace *namespaces.Namespace) (string, []interface{}, error) {
	return newStatementBuilder().
		Insert("namespaces").
		Columns("name").
		Values(namespace.Name).
		ToSql()
}

func (c Client) CreateNamespace(ctx context.Context, namespace *namespaces.Namespace) (pgx.Row, error) {
	sql, args, err := createNamespaceSql(namespace)
	if e := c.exec(ctx, sql, args, err); e != nil {
		return nil, e
	}
	return c.GetNamespace(ctx, namespace.Id)
}

func updateNamespaceSql(namespace *namespaces.Namespace) (string, []interface{}, error) {
	return newStatementBuilder().
		Update("namespaces").
		Set("name", namespace.Name).
		Where(sq.Eq{"id": namespace.Id}).
		ToSql()
}

func (c Client) UpdateNamespace(ctx context.Context, namespace *namespaces.Namespace) (pgx.Row, error) {
	sql, args, err := updateNamespaceSql(namespace)
	if e := c.exec(ctx, sql, args, err); e != nil {
		return nil, e
	}
	return c.GetNamespace(ctx, namespace.Id)
}

func deleteNamespaceSql(id string) (string, []interface{}, error) {
	return newStatementBuilder().
		Delete("namespaces").
		Where(sq.Eq{"id": id}).
		ToSql()
}

func (c Client) DeleteNamespace(ctx context.Context, id string) error {
	sql, args, err := deleteNamespaceSql(id)
	return c.exec(ctx, sql, args, err)
}
