package db

import (
	"context"
	"errors"
	"log/slog"

	sq "github.com/Masterminds/squirrel"
	"github.com/opentdf/opentdf-v2-poc/sdk/namespaces"
	"github.com/opentdf/opentdf-v2-poc/services"
)

func getNamespaceSql(id string) (string, []interface{}, error) {
	t := Tables.Namespaces
	return newStatementBuilder().
		Select("*").
		From(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
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
		if e := WrapIfKnownInvalidQueryErr(err); e != nil {
			slog.Error(services.ErrNotFound, slog.String("error", e.Error()))
			return nil, e
		}

		slog.Error(services.ErrGettingResource, slog.String("error", err.Error()))
		return nil, err
	}

	return &namespace, nil
}

func listNamespacesSql() (string, []interface{}, error) {
	t := Tables.Namespaces
	return newStatementBuilder().
		Select("*").
		From(t.Name()).
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
	t := Tables.Namespaces
	return newStatementBuilder().
		Insert(t.Name()).
		Columns("name").
		Values(name).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c Client) CreateNamespace(ctx context.Context, name string) (string, error) {
	sql, args, err := createNamespaceSql(name)
	var id string

	if r, e := c.queryRow(ctx, sql, args, err); e != nil {
		slog.Error(services.ErrCreatingResource, slog.String("error", e.Error()))
		return "", e
	} else if e := r.Scan(&id); e != nil {
		if IsConstraintViolationForColumnVal(e, TableNamespaces, "name") {
			e = errors.Join(NewUniqueAlreadyExistsError(name), e)
			slog.Error(services.ErrConflict, slog.String("error", e.Error()))
			return "", e
		}

		slog.Error(services.ErrCreatingResource, slog.String("error", e.Error()))
		return "", e
	}
	return id, nil
}

func updateNamespaceSql(id string, name string) (string, []interface{}, error) {
	t := Tables.Namespaces
	return newStatementBuilder().
		Update(t.Name()).
		Set("name", name).
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c Client) UpdateNamespace(ctx context.Context, id string, name string) (*namespaces.Namespace, error) {
	sql, args, err := updateNamespaceSql(id, name)

	if e := c.exec(ctx, sql, args, err); e != nil {
		if IsConstraintViolationForColumnVal(e, TableNamespaces, "name") {
			e = errors.Join(NewUniqueAlreadyExistsError(name), e)
			slog.Error(services.ErrConflict, slog.String("error", e.Error()))
			return nil, e
		}

		if err := WrapIfKnownInvalidQueryErr(e); err != nil {
			if errors.Is(err, ErrNotFound) {
				slog.Error(services.ErrNotFound, slog.String("error", err.Error()))
			}
			return nil, err
		}

		slog.Error(services.ErrUpdatingResource, slog.String("error", e.Error()))
		return nil, e
	}

	return c.GetNamespace(ctx, id)
}

func deleteNamespaceSql(id string) (string, []interface{}, error) {
	t := Tables.Namespaces
	// TODO: handle delete cascade, dangerous deletion via special rpc, or "soft-delete" status change
	return newStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c Client) DeleteNamespace(ctx context.Context, id string) error {
	sql, args, err := deleteNamespaceSql(id)

	e := c.exec(ctx, sql, args, err)
	if e != nil {
		if errors.Is(e, ErrNotFound) {
			slog.Error(services.ErrNotFound, slog.String("error", e.Error()))
		} else if errors.Is(e, ErrForeignKeyViolation) {
			slog.Error(services.ErrConflict, slog.String("error", e.Error()))
		} else {
			slog.Error(services.ErrDeletingResource, slog.String("error", e.Error()))
		}
	}
	return e
}
