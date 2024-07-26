package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type namespaceSelectOptions struct {
	withFqn bool
	state   string
}

func hydrateNamespaceItem(row pgx.Row, opts namespaceSelectOptions, logger *logger.Logger) (*policy.Namespace, error) {
	var (
		id           string
		name         string
		active       bool
		metadataJSON []byte
		fqn          sql.NullString
	)

	fields := []interface{}{&id, &name, &active, &metadataJSON}
	if opts.withFqn {
		fields = append(fields, &fqn)
	}

	if err := row.Scan(fields...); err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	m := &common.Metadata{}
	if metadataJSON != nil {
		if err := protojson.Unmarshal(metadataJSON, m); err != nil {
			logger.Error("could not unmarshal metadata", slog.String("error", err.Error()))
			return nil, err
		}
	}

	return &policy.Namespace{
		Id:       id,
		Name:     name,
		Active:   &wrapperspb.BoolValue{Value: active},
		Metadata: m,
		Fqn:      fqn.String,
	}, nil
}

func hydrateNamespaceItems(rows pgx.Rows, opts namespaceSelectOptions, logger *logger.Logger) ([]*policy.Namespace, error) {
	var list []*policy.Namespace

	for rows.Next() {
		n, err := hydrateNamespaceItem(rows, opts, logger)
		if err != nil {
			return nil, err
		}
		list = append(list, n)
	}

	return list, nil
}

func getNamespaceSQL(id string, opts namespaceSelectOptions) (string, []interface{}, error) {
	t := Tables.Namespaces
	fqnT := Tables.AttrFqn
	fields := []string{
		t.Field("id"),
		t.Field("name"),
		t.Field("active"),
		constructMetadata("", false),
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

func (c PolicyDBClient) GetNamespace(ctx context.Context, id string) (*policy.Namespace, error) {
	opts := namespaceSelectOptions{withFqn: true}
	sql, args, err := getNamespaceSQL(id, opts)
	if err != nil {
		return nil, err
	}

	row, err := c.QueryRow(ctx, sql, args)
	if err != nil {
		return nil, err
	}

	return hydrateNamespaceItem(row, opts, c.logger)
}

func listNamespacesSQL(opts namespaceSelectOptions) (string, []interface{}, error) {
	t := Tables.Namespaces
	fqnT := Tables.AttrFqn

	fields := []string{
		t.Field("id"),
		t.Field("name"),
		t.Field("active"),
		constructMetadata("", false),
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

func (c PolicyDBClient) ListNamespaces(ctx context.Context, state string) ([]*policy.Namespace, error) {
	opts := namespaceSelectOptions{withFqn: true, state: state}

	sql, args, err := listNamespacesSQL(opts)
	if err != nil {
		c.logger.Error("error listing namespaces", slog.String("error", err.Error()))
		return nil, err
	}

	rows, err := c.Query(ctx, sql, args)
	if err != nil {
		c.logger.Error("error listing namespaces", slog.String("sql", sql), slog.String("error", err.Error()))
		return nil, err
	}
	defer rows.Close()

	list, err := hydrateNamespaceItems(rows, opts, c.logger)
	if err != nil {
		c.logger.Error("error hydrating namespace items", slog.String("sql", sql), slog.String("error", err.Error()))
		return nil, err
	}

	return list, nil
}

func createNamespaceSQL(name string, metadata []byte) (string, []interface{}, error) {
	t := Tables.Namespaces
	return db.NewStatementBuilder().
		Insert(t.Name()).
		Columns("name", "metadata").
		Values(name, metadata).
		Suffix(createSuffix).
		ToSql()
}

func (c PolicyDBClient) CreateNamespace(ctx context.Context, r *namespaces.CreateNamespaceRequest) (*policy.Namespace, error) {
	metadataJSON, m, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	name := strings.ToLower(r.GetName())
	sql, args, err := createNamespaceSQL(name, metadataJSON)
	if err != nil {
		return nil, err
	}

	var id string
	if r, e := c.QueryRow(ctx, sql, args); e != nil {
		return nil, e
	} else if e = r.Scan(&id, &metadataJSON); e != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(e)
	}

	if err = unmarshalMetadata(metadataJSON, m, c.logger); err != nil {
		return nil, err
	}

	// Update FQN
	fqn := c.upsertAttrFqn(ctx, attrFqnUpsertOptions{namespaceID: id})
	c.logger.Debug("upserted fqn for created namespace", slog.Any("fqn", fqn))

	return &policy.Namespace{
		Id:       id,
		Name:     name,
		Active:   &wrapperspb.BoolValue{Value: true},
		Metadata: m,
	}, nil
}

func updateNamespaceSQL(id string, metadata []byte) (string, []interface{}, error) {
	t := Tables.Namespaces
	sb := db.NewStatementBuilder().Update(t.Name())

	if metadata != nil {
		sb = sb.Set("metadata", metadata)
	}

	return sb.Where(sq.Eq{t.Field("id"): id}).ToSql()
}

func (c PolicyDBClient) UpdateNamespace(ctx context.Context, id string, r *namespaces.UpdateNamespaceRequest) (*policy.Namespace, error) {
	// if extend we need to merge the metadata
	metadataJSON, _, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		n, err := c.GetNamespace(ctx, id)
		if err != nil {
			return nil, err
		}
		if n.GetMetadata() == nil {
			return nil, nil //nolint:nilnil // no metadata does not mean no error
		}
		return n.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	sql, args, err := updateNamespaceSQL(id, metadataJSON)
	if db.IsQueryBuilderSetClauseError(err) {
		return &policy.Namespace{
			Id: id,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	return &policy.Namespace{
		Id: id,
	}, nil
}

func unsafeUpdateNamespaceSQL(id string, name string) (string, []interface{}, error) {
	t := Tables.Namespaces
	return db.NewStatementBuilder().
		Update(t.Name()).
		Set("name", name).
		Where(sq.Eq{t.Field("id"): id}).
		Suffix("RETURNING \"id\", \"name\", \"active\", " + constructMetadata(TableNamespaces, false)).
		ToSql()
}

func (c PolicyDBClient) UnsafeUpdateNamespace(ctx context.Context, id string, name string) (*policy.Namespace, error) {
	sql, args, err := unsafeUpdateNamespaceSQL(id, strings.ToLower(name))
	if db.IsQueryBuilderSetClauseError(err) {
		return &policy.Namespace{
			Id: id,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	row, err := c.QueryRow(ctx, sql, args)
	if err != nil {
		return nil, err
	}

	// Update all FQNs that may contain the namespace name
	fqn := c.upsertAttrFqn(ctx, attrFqnUpsertOptions{namespaceID: id})
	c.logger.Debug("upserted fqn for unsafely updated namespace", slog.Any("fqn", fqn))

	attrs, err := c.ListAllAttributes(ctx, StateAny, id)
	if err != nil {
		return nil, err
	}
	for _, attr := range attrs {
		fqn = c.upsertAttrFqn(ctx, attrFqnUpsertOptions{namespaceID: id, attributeID: attr.GetId()})
		c.logger.Debug("upserted definition fqn for unsafely updated namespace", slog.Any("fqn", fqn))
		for _, value := range attr.GetValues() {
			fqn = c.upsertAttrFqn(ctx, attrFqnUpsertOptions{namespaceID: id, attributeID: attr.GetId(), valueID: value.GetId()})
			c.logger.Debug("upserted value fqn for unsafely updated namespace", slog.Any("fqn", fqn))
		}
	}

	return hydrateNamespaceItem(row, namespaceSelectOptions{}, c.logger)
}

func setNamespaceActiveStateSQL(id string, isActive bool) (string, []interface{}, error) {
	t := Tables.Namespaces
	return db.NewStatementBuilder().
		Update(t.Name()).
		Set("active", isActive).
		Where(sq.Eq{t.Field("id"): id}).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c PolicyDBClient) DeactivateNamespace(ctx context.Context, id string) (*policy.Namespace, error) {
	attrs, err := c.GetAttributesByNamespace(ctx, id)
	if err != nil {
		return nil, err
	}

	allAttrsDeactivated := true
	for _, attr := range attrs {
		if attr.GetActive().GetValue() {
			allAttrsDeactivated = false
			break
		}
	}

	if !allAttrsDeactivated {
		c.logger.Warn("deactivating the namespace with existed attributes can affect access to related data. Please be aware and proceed accordingly.")
	}

	sql, args, err := setNamespaceActiveStateSQL(id, false)
	if err != nil {
		return nil, err
	}

	if e := c.Exec(ctx, sql, args); e != nil {
		return nil, e
	}
	return c.GetNamespace(ctx, id)
}

func (c PolicyDBClient) UnsafeReactivateNamespace(ctx context.Context, id string) (*policy.Namespace, error) {
	attrs, err := c.GetAttributesByNamespace(ctx, id)
	if err != nil {
		return nil, err
	}

	if len(attrs) > 0 {
		c.logger.Warn("reactivating the namespace with existing attributes can affect access to related data. Please be aware and proceed accordingly.")
	}

	sql, args, err := setNamespaceActiveStateSQL(id, true)
	if err != nil {
		return nil, err
	}

	if e := c.Exec(ctx, sql, args); e != nil {
		return nil, e
	}
	return c.GetNamespace(ctx, id)
}

func deleteNamespaceSQL(id string) (string, []interface{}, error) {
	t := Tables.Namespaces
	return db.NewStatementBuilder().
		Delete(t.Name()).
		Where(sq.Eq{t.Field("id"): id}).
		Suffix("RETURNING \"id\"").
		ToSql()
}

func (c PolicyDBClient) UnsafeDeleteNamespace(ctx context.Context, existing *policy.Namespace, fqn string) (*policy.Namespace, error) {
	if existing == nil {
		return nil, fmt.Errorf("namespace not found: %w", db.ErrNotFound)
	}
	id := existing.GetId()

	if existing.GetFqn() != fqn {
		return nil, fmt.Errorf("fqn mismatch: %w", db.ErrNotFound)
	}
	sql, args, err := deleteNamespaceSQL(id)
	if err != nil {
		return nil, err
	}

	if err := c.Exec(ctx, sql, args); err != nil {
		return nil, err
	}

	// return the namespace id that was deleted
	return &policy.Namespace{
		Id: id,
	}, nil
}
