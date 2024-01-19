package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/opentdf/opentdf-v2-poc/migrations"
	"github.com/opentdf/opentdf-v2-poc/sdk/common"
	"github.com/pressly/goose/v3"
)

// We can rename this but wanted to get mocks working.
type PgxIface interface {
	Acquire(ctx context.Context) (*pgxpool.Conn, error)
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
	Ping(context.Context) error
	Close()
	Config() *pgxpool.Config
}

type Config struct {
	Host          string `yaml:"host" default:"localhost"`
	Port          int    `yaml:"port" default:"5432"`
	Database      string `yaml:"database" default:"opentdf"`
	User          string `yaml:"user" default:"postgres"`
	Password      string `yaml:"password" default:"changeme"`
	RunMigrations bool   `yaml:"runMigrations" default:"true"`
	SSLMode       string `yaml:"sslmode" default:"prefer"`
}

type Client struct {
	PgxIface
	config Config
}

func NewClient(config Config) (*Client, error) {
	pool, err := pgxpool.New(context.Background(), config.buildURL())
	if err != nil {
		return nil, fmt.Errorf("failed to create pgxpool: %w", err)
	}
	return &Client{
		PgxIface: pool,
		config:   config,
	}, nil
}

func (c Config) buildURL() string {
	return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s",
		c.User,
		c.Password,
		net.JoinHostPort(c.Host, fmt.Sprint(c.Port)),
		c.Database,
		c.SSLMode,
	)
}

func (c *Client) RunMigrations() (int, error) {
	var (
		applied int
	)

	if !c.config.RunMigrations {
		slog.Info("skipping migrations",
			slog.String("reason", "runMigrations is false"),
			slog.Bool("runMigrations", c.config.RunMigrations))
		return applied, nil
	}

	pool, ok := c.PgxIface.(*pgxpool.Pool)
	if !ok || pool == nil {
		return applied, fmt.Errorf("failed to cast pgxpool.Pool")
	}

	conn := stdlib.OpenDBFromPool(pool)
	defer conn.Close()

	provider, err := goose.NewProvider(goose.DialectPostgres, conn, migrations.MigrationsFS)
	if err != nil {
		return applied, errors.Join(fmt.Errorf("failed to create goose provider"), err)
	}

	res, err := provider.Up(context.Background())
	if err != nil {
		return applied, errors.Join(fmt.Errorf("failed to run migrations"), err)
	}

	for _, r := range res {
		if r.Error != nil {
			return applied, errors.Join(fmt.Errorf("failed to run migrations"), err)
		}
		if !r.Empty {
			applied++
		}
	}

	return applied, nil
}

func (c Client) CreateResource(ctx context.Context,
	descriptor *common.ResourceDescriptor, resource []byte) error {
	sql, args, err := createResourceSQL(descriptor, resource)
	if err != nil {
		return fmt.Errorf("failed to create resource sql: %w", err)
	}

	slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))

	_, err = c.Exec(ctx, sql, args...)

	return err
}

func createResourceSQL(descriptor *common.ResourceDescriptor,
	resource []byte) (string, []interface{}, error) {
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	builder := psql.Insert("opentdf.resources")

	builder = builder.Columns("name", "namespace", "version", "fqn", "labels", "description", "policytype", "resource")

	builder = builder.Values(
		descriptor.Name,
		descriptor.Namespace,
		descriptor.Version,
		descriptor.Fqn,
		descriptor.Labels,
		descriptor.Description,
		descriptor.Type.String(),
		resource,
	)

	//nolint:wrapcheck // Wrapped error in CreateResource
	return builder.ToSql()
}

func (c Client) ListResources(ctx context.Context,
	policyType string, selectors *common.ResourceSelector) (pgx.Rows, error) {
	sql, args, err := listResourceSQL(policyType, selectors)
	if err != nil {
		return nil, fmt.Errorf("failed to create list resource sql: %w", err)
	}

	slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))

	//nolint:rowserrcheck // Rows error check should not flag this https://github.com/jingyugao/rowserrcheck/issues/32
	return c.Query(ctx, sql, args...)
}

func listResourceSQL(policyType string, selectors *common.ResourceSelector) (string, []interface{}, error) {
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	builder := psql.Select("id", "resource").From("opentdf.resources")

	builder = builder.Where(sq.Eq{"policytype": policyType})

	if selectors != nil {
		// Set the namespace if it is not empty
		if selectors.Namespace != "" {
			builder = builder.Where(sq.Eq{"namespace": selectors.Namespace})
		}

		switch selector := selectors.Selector.(type) {
		case *common.ResourceSelector_Name:
			builder = builder.Where(sq.Eq{"name": selector.Name})
		case *common.ResourceSelector_LabelSelector_:
			bLabels, err := json.Marshal(selector.LabelSelector.Labels)
			if err != nil {
				return "", nil, fmt.Errorf("failed to marshal labels: %w", err)
			}
			builder = builder.Where(sq.Expr("labels @> ?::jsonb", bLabels))
		}
		// Set the version if it is not empty
		if selectors.Version != 0 {
			builder = builder.Where(sq.Eq{"version": selectors.Version})
		}
	}

	//nolint:wrapcheck // Wrapped error in ListResources
	return builder.ToSql()
}

func (c Client) GetResource(ctx context.Context, id int32, policyType string) (pgx.Row, error) {
	sql, args, err := getResourceSQL(id, policyType)
	if err != nil {
		return nil, fmt.Errorf("failed to create get resource sql: %w", err)
	}

	slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))

	return c.QueryRow(ctx, sql, args...), nil
}

func getResourceSQL(id int32, policyType string) (string, []interface{}, error) {
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	builder := psql.Select("id", "resource").From("opentdf.resources")

	builder = builder.Where(sq.Eq{"id": id, "policytype": policyType})

	//nolint:wrapcheck // Wrapped error in GetResource
	return builder.ToSql()
}

func (c Client) UpdateResource(ctx context.Context, descriptor *common.ResourceDescriptor,
	resource []byte, policyType string) error {
	sql, args, err := updateResourceSQL(descriptor, resource, policyType)
	if err != nil {
		return fmt.Errorf("failed to create update resource sql: %w", err)
	}

	slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))

	_, err = c.Exec(ctx, sql, args...)

	return err
}

func updateResourceSQL(descriptor *common.ResourceDescriptor,
	resource []byte, policyType string) (string, []interface{}, error) {
	psql := newStatementBuilder()

	builder := psql.Update("opentdf.resources")

	builder = builder.Set("name", descriptor.Name)
	builder = builder.Set("namespace", descriptor.Namespace)
	builder = builder.Set("version", descriptor.Version)
	builder = builder.Set("description", descriptor.Description)
	builder = builder.Set("fqn", descriptor.Fqn)
	builder = builder.Set("labels", descriptor.Labels)
	builder = builder.Set("policyType", policyType)
	builder = builder.Set("resource", resource)

	builder = builder.Where(sq.Eq{"id": descriptor.Id})

	//nolint:wrapcheck // Wrapped error in UpdateResource
	return builder.ToSql()
}

func (c Client) DeleteResource(ctx context.Context, id int32, policyType string) error {
	sql, args, err := deleteResourceSQL(id, policyType)
	if err != nil {
		return fmt.Errorf("failed to create delete resource sql: %w", err)
	}

	slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))

	_, err = c.Exec(ctx, sql, args...)

	return err
}

func deleteResourceSQL(id int32, policyType string) (string, []interface{}, error) {
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	builder := psql.Delete("opentdf.resources")

	builder = builder.Where(sq.Eq{"id": id, "policytype": policyType})

	//nolint:wrapcheck // Wrapped error in DeleteResource
	return builder.ToSql()
}

// Postgres specific statement builder
func newStatementBuilder() sq.StatementBuilderType {
	return sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
}

// Common function for all queryRow calls
func (c Client) queryRow(ctx context.Context, sql string, args []interface{}, err error) (pgx.Row, error) {
	if err != nil {
		slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))
		return nil, fmt.Errorf("failed to create get resource sql: %w", err)
	}
	slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))
	return c.QueryRow(ctx, sql, args...), nil
}

// Common function for all query calls
func (c Client) query(ctx context.Context, sql string, args []interface{}, err error) (pgx.Rows, error) {
	if err != nil {
		slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))
		return nil, fmt.Errorf("failed to create list resource sql: %w", err)
	}
	slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))
	return c.Query(ctx, sql, args...)
}

// Common function for all exec calls
func (c Client) exec(ctx context.Context, sql string, args []interface{}, err error) error {
	if err != nil {
		slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))
		return fmt.Errorf("failed to create list resource sql: %w", err)
	}
	slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))
	_, err = c.Exec(ctx, sql, args...)
	return err
}
