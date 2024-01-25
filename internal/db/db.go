package db

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	Schema = "opentdf"

	TableAttributes                    = "attribute_definitions"
	TableAttributeValues               = "attribute_values"
	TableNamespaces                    = "attribute_namespaces"
	TableKeyAccessServerRegistry       = "key_access_servers"
	TableAttributeKeyAccessGrants      = "attribute_definition_key_access_grants"
	TableAttributeValueKeyAccessGrants = "attribute_value_key_access_grants"
	TableResourceMappings              = "resource_mappings"
	TableSubjectMappings               = "subject_mappings"
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

// Common function for all queryRow calls
func (c Client) queryRow(ctx context.Context, sql string, args []interface{}, err error) (pgx.Row, error) {
	slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))
	if err != nil {
		return nil, err
	}
	return c.QueryRow(ctx, sql, args...), nil
}

// Common function for all query calls
func (c Client) query(ctx context.Context, sql string, args []interface{}, err error) (pgx.Rows, error) {
	slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))
	if err != nil {
		return nil, err
	}
	r, e := c.Query(ctx, sql, args...)
	return r, WrapIfKnownInvalidQueryErr(e)
}

// Common function for all exec calls
func (c Client) exec(ctx context.Context, sql string, args []interface{}, err error) error {
	slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))
	if err != nil {
		return err
	}
	_, err = c.Exec(ctx, sql, args...)
	return WrapIfKnownInvalidQueryErr(err)
}

//
// Helper functions for building SQL
//

// Postgres uses $1, $2, etc. for placeholders
func newStatementBuilder() sq.StatementBuilderType {
	return sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
}

func tableName(table string) string {
	return Schema + "." + table
}

func tableField(table string, field string) string {
	return table + "." + field
}
