package db

import (
	"context"

	sq "github.com/Masterminds/squirrel"
	"github.com/opentdf/platform/sdk/namespaces"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func getNamespaceSql(id string) (string, []interface{}, error) {
	t := Tables.Namespaces
	return newStatementBuilder().
		Select(t.Field("id"), t.Field("name"), t.Field("active")).
		From(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c Client) GetNamespace(ctx context.Context, id string) (*namespaces.Namespace, error) {
	sql, args, err := getNamespaceSql(id)
	if err != nil {
		return nil, err
	}

	row, err := c.queryRow(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}

	var namespace namespaces.Namespace
	var isActive bool
	if err := row.Scan(&namespace.Id, &namespace.Name, &isActive); err != nil {
		return nil, WrapIfKnownInvalidQueryErr(err)
	}
	namespace.Active = &wrapperspb.BoolValue{Value: isActive}

	return &namespace, nil
}

func listNamespacesSql(state string) (string, []interface{}, error) {
	t := Tables.Namespaces
	sb := newStatementBuilder().
		Select(t.Field("id"), t.Field("name"), t.Field("active")).
		From(t.Name())

	if state != StateAny {
		sb = sb.Where(sq.Eq{t.Field("active"): state == StateActive})
	}
	return sb.ToSql()
}

func (c Client) ListNamespaces(ctx context.Context, state string) ([]*namespaces.Namespace, error) {
	namespacesList := []*namespaces.Namespace{}

	sql, args, err := listNamespacesSql(state)
	if err != nil {
		return nil, err
	}

	rows, err := c.query(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var namespace namespaces.Namespace
		var isActive bool
		if err := rows.Scan(&namespace.Id, &namespace.Name, &isActive); err != nil {
			return nil, WrapIfKnownInvalidQueryErr(err)
		}
		namespace.Active = &wrapperspb.BoolValue{Value: isActive}
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
		return "", e
	} else if e := r.Scan(&id); e != nil {
		return "", WrapIfKnownInvalidQueryErr(e)
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
		return nil, e
	}

	return c.GetNamespace(ctx, id)
}

func deactivateNamespaceSql(id string) (string, []interface{}, error) {
	t := Tables.Namespaces
	return newStatementBuilder().
		Update(t.Name()).
		Set("active", false).
		Where(sq.Eq{t.Field("id"): id}).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c Client) DeactivateNamespace(ctx context.Context, id string) (*namespaces.Namespace, error) {
	sql, args, err := deactivateNamespaceSql(id)

	if e := c.exec(ctx, sql, args, err); e != nil {
		return nil, e
	}
	return c.GetNamespace(ctx, id)
}

func deleteNamespaceSql(id string) (string, []interface{}, error) {
	t := Tables.Namespaces
	// TODO: handle delete cascade, dangerous deletion via special rpc [https://github.com/opentdf/platform/issues/115]
	return newStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c Client) DeleteNamespace(ctx context.Context, id string) (*namespaces.Namespace, error) {
	// get a namespace before deleting
	ns, err := c.GetNamespace(ctx, id)
	if err != nil {
		return nil, err
	}
	sql, args, err := deleteNamespaceSql(id)

	if e := c.exec(ctx, sql, args, err); e != nil {
		return nil, WrapIfKnownInvalidQueryErr(e)
	}

	// return the namespace before it was deleted
	return ns, nil
}
