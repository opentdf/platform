package db

import (
	"context"
	"errors"
	"log/slog"

	sq "github.com/Masterminds/squirrel"
	"github.com/opentdf/opentdf-v2-poc/sdk/namespaces"
	"github.com/opentdf/opentdf-v2-poc/services"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var NamespacesTable = tableName(TableNamespaces)

func getNamespaceSql(id string) (string, []interface{}, error) {
	return newStatementBuilder().
		Select("*").
		From(NamespacesTable).
		Where(sq.Eq{tableField(NamespacesTable, "id"): id}).
		ToSql()
}

func (c Client) GetNamespace(ctx context.Context, id string) (*namespaces.Namespace, error) {
	sql, args, err := getNamespaceSql(id)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return nil, err
	}
	row, err := c.queryRow(ctx, sql, args, err)
	if err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return nil, err
	}

	namespace := namespaces.Namespace{Id: "", Name: ""}
	if err := row.Scan(&namespace.Id, &namespace.Name); err != nil {
		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, services.ErrGettingResource)
	}
	return &namespace, nil
}

func listNamespacesSql() (string, []interface{}, error) {
	return newStatementBuilder().
		Select("*").
		From(NamespacesTable).
		ToSql()
}

func (c Client) ListNamespaces(ctx context.Context) ([]*namespaces.Namespace, error) {
	namespacesList := []*namespaces.Namespace{}

	sql, args, err := listNamespacesSql()
	if err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return nil, err
	}
	rows, err := c.query(ctx, sql, args, err)
	if err != nil {
		slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
		return nil, err
	}
	for rows.Next() {
		var namespace namespaces.Namespace
		if err := rows.Scan(&namespace.Id, &namespace.Name); err != nil {
			slog.Error(services.ErrListingResource, slog.String("error", err.Error()))
			return nil, err
		}
		namespacesList = append(namespacesList, &namespace)
	}
	return namespacesList, nil
}

func createNamespaceSql(name string) (string, []interface{}, error) {
	return newStatementBuilder().
		Insert(NamespacesTable).
		Columns("name").
		Values(name).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c Client) CreateNamespace(ctx context.Context, name string) (string, error) {
	sql, args, err := createNamespaceSql(name)
	var id string
	if r, e := c.queryRow(ctx, sql, args, err); e != nil {
		return "", e
	} else if e := r.Scan(&id); e != nil {
		if IsConstraintViolation(e, TableNamespaces, "name") {
			return "", errors.Join(NewUniqueAlreadyExistsError(name), e, ErrUniqueConstraintViolation)
		}
		return "", e
	}
	return id, nil
}

func updateNamespaceSql(id string, name string) (string, []interface{}, error) {
	return newStatementBuilder().
		Update(NamespacesTable).
		Set("name", name).
		Where(sq.Eq{tableField(NamespacesTable, "id"): id}).
		ToSql()
}

func (c Client) UpdateNamespace(ctx context.Context, id string, name string) (*namespaces.Namespace, error) {
	sql, args, err := updateNamespaceSql(id, name)
	if e := c.exec(ctx, sql, args, err); e != nil {
		if IsConstraintViolation(e, TableNamespaces, "name") {
			return nil, errors.Join(NewUniqueAlreadyExistsError(name), e, ErrUniqueConstraintViolation)
		}
		return nil, e
	}
	return c.GetNamespace(ctx, id)
}

func deleteNamespaceSql(id string) (string, []interface{}, error) {
	return newStatementBuilder().
		Delete(NamespacesTable).
		Where(sq.Eq{"id": id}).
		ToSql()
}

func (c Client) DeleteNamespace(ctx context.Context, id string) error {
	sql, args, err := deleteNamespaceSql(id)
	return c.exec(ctx, sql, args, err)
}
