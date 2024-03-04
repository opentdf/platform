package db

import (
	"context"
	"database/sql"
	"log/slog"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type namespaceSelectOptions struct {
	withFqn bool
	state   string
}

func hydrateNamespaceItem(row pgx.Row, opts namespaceSelectOptions) (*namespaces.Namespace, error) {
	var (
		id     string
		name   string
		active bool
		fqn    sql.NullString
	)

	fields := []interface{}{&id, &name, &active}
	if opts.withFqn {
		fields = append(fields, &fqn)
	}

	if err := row.Scan(fields...); err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return &namespaces.Namespace{
		Id:     id,
		Name:   name,
		Active: &wrapperspb.BoolValue{Value: active},
		Fqn:    fqn.String,
	}, nil
}

func hydrateNamespaceItems(rows pgx.Rows, opts namespaceSelectOptions) ([]*namespaces.Namespace, error) {
	var list []*namespaces.Namespace

	for rows.Next() {
		n, err := hydrateNamespaceItem(rows, opts)
		if err != nil {
			return nil, err
		}
		list = append(list, n)
	}

	return list, nil
}

func getNamespaceSql(id string, opts namespaceSelectOptions) (string, []interface{}, error) {
	t := db.Tables.Namespaces
	fqnT := db.Tables.AttrFqn
	fields := []string{
		t.Field("id"),
		t.Field("name"),
		t.Field("active"),
	}

	if opts.withFqn {
		fields = append(fields, fqnT.Field("fqn"))
	}

	sb := db.NewStatementBuilder().
		Select(fields...).
		From(t.Name())

	if opts.withFqn {
		sb = sb.LeftJoin(fqnT.Name() + " ON " + fqnT.Field("namespace_id") + " = " + t.Field("id") +
			" AND " + fqnT.Field("attribute_id") + " IS NULL")
	}

	return sb.
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c PolicyDbClient) GetNamespace(ctx context.Context, id string) (*namespaces.Namespace, error) {
	opts := namespaceSelectOptions{withFqn: true}
	sql, args, err := getNamespaceSql(id, opts)
	if err != nil {
		return nil, err
	}

	row, err := c.QueryRow(ctx, sql, args, err)
	if err != nil {
		return nil, err
	}

	n, err := hydrateNamespaceItem(row, opts)
	if err != nil {
		return nil, err
	}

	return n, nil
}

func listNamespacesSql(opts namespaceSelectOptions) (string, []interface{}, error) {
	t := db.Tables.Namespaces
	fqnT := db.Tables.AttrFqn

	fields := []string{
		t.Field("id"),
		t.Field("name"),
		t.Field("active"),
	}

	if opts.withFqn {
		fields = append(fields, fqnT.Field("fqn"))
	}

	sb := db.NewStatementBuilder().
		Select(fields...).
		From(t.Name())

	if opts.withFqn {
		sb = sb.LeftJoin(fqnT.Name() + " ON " + fqnT.Field("namespace_id") + " = " + t.Field("id") +
			" AND " + fqnT.Field("attribute_id") + " IS NULL")
	}

	if opts.state != "" && opts.state != StateAny {
		sb = sb.Where(sq.Eq{t.Field("active"): opts.state == StateActive})
	}

	return sb.ToSql()
}

func (c PolicyDbClient) ListNamespaces(ctx context.Context, state string) ([]*namespaces.Namespace, error) {
	opts := namespaceSelectOptions{withFqn: true, state: state}

	sql, args, err := listNamespacesSql(opts)
	if err != nil {
		slog.Error("error listing namespaces", slog.String("error", err.Error()))
		return nil, err
	}

	rows, err := c.Query(ctx, sql, args, err)
	if err != nil {
		slog.Error("error listing namespaces", slog.String("sql", sql), slog.String("error", err.Error()))
		return nil, err
	}

	list, err := hydrateNamespaceItems(rows, opts)
	if err != nil {
		slog.Error("error hydrating namespace items", slog.String("sql", sql), slog.String("error", err.Error()))
		return nil, err
	}

	return list, nil
}

func createNamespaceSql(name string) (string, []interface{}, error) {
	t := db.Tables.Namespaces
	return db.NewStatementBuilder().
		Insert(t.Name()).
		Columns("name").
		Values(name).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c PolicyDbClient) CreateNamespace(ctx context.Context, name string) (string, error) {
	sql, args, err := createNamespaceSql(name)
	var id string

	if r, e := c.QueryRow(ctx, sql, args, err); e != nil {
		return "", e
	} else if e := r.Scan(&id); e != nil {
		return "", db.WrapIfKnownInvalidQueryErr(e)
	}

	// Update FQN
	c.upsertAttrFqn(ctx, attrFqnUpsertOptions{namespaceId: id})

	return id, nil
}

func updateNamespaceSql(id string, name string) (string, []interface{}, error) {
	t := db.Tables.Namespaces
	return db.NewStatementBuilder().
		Update(t.Name()).
		Set("name", name).
		Where(sq.Eq{t.Field("id"): id}).
		ToSql()
}

func (c PolicyDbClient) UpdateNamespace(ctx context.Context, id string, name string) (*namespaces.Namespace, error) {
	sql, args, err := updateNamespaceSql(id, name)

	if e := c.Exec(ctx, sql, args, err); e != nil {
		return nil, e
	}

	// Update FQN
	c.upsertAttrFqn(ctx, attrFqnUpsertOptions{namespaceId: id})

	return c.GetNamespace(ctx, id)
}

func deactivateNamespaceSql(id string) (string, []interface{}, error) {
	t := db.Tables.Namespaces
	return db.NewStatementBuilder().
		Update(t.Name()).
		Set("active", false).
		Where(sq.Eq{t.Field("id"): id}).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c PolicyDbClient) DeactivateNamespace(ctx context.Context, id string) (*namespaces.Namespace, error) {
	sql, args, err := deactivateNamespaceSql(id)

	if e := c.Exec(ctx, sql, args, err); e != nil {
		return nil, e
	}
	return c.GetNamespace(ctx, id)
}

func deleteNamespaceSql(id string) (string, []interface{}, error) {
	t := db.Tables.Namespaces
	// TODO: handle delete cascade, dangerous deletion via special rpc [https://github.com/opentdf/platform/issues/115]
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c PolicyDbClient) DeleteNamespace(ctx context.Context, id string) (*namespaces.Namespace, error) {
	// get a namespace before deleting
	ns, err := c.GetNamespace(ctx, id)
	if err != nil {
		return nil, err
	}
	sql, args, err := deleteNamespaceSql(id)

	if e := c.Exec(ctx, sql, args, err); e != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(e)
	}

	// return the namespace before it was deleted
	return ns, nil
}
