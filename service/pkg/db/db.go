package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"net"
	"net/url"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

type Table struct {
	name       string
	schema     string
	withSchema bool
}

func NewTable(schema string) func(name string) Table {
	s := schema
	return func(name string) Table {
		return Table{
			name:       name,
			schema:     s,
			withSchema: true,
		}
	}
}

func (t Table) WithoutSchema() Table {
	nT := NewTable(t.schema)(t.name)
	nT.withSchema = false
	return nT
}

func (t Table) Name() string {
	if t.withSchema {
		return t.schema + "." + t.name
	}
	return t.name
}

func (t Table) Field(field string) string {
	return t.Name() + "." + field
}

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
	Password      string `yaml:"password" default:"changeme" secret:"true"`
	RunMigrations bool   `yaml:"runMigrations" default:"true"`
	SSLMode       string `yaml:"sslmode" default:"prefer"`
	Schema        string `yaml:"schema" default:"opentdf"`

	VerifyConnection bool `yaml:"verifyConnection" default:"true"`
	MigrationsFS     *embed.FS
}

/*
A wrapper around a pgxpool.Pool and sql.DB reference.

Each service should have a single instance of the Client to share a connection pool,
schema (driven by the service namespace), and an embedded file system for migrations.

The 'search_path' is set to the schema on connection to the database.

If the database config 'runMigrations' is set to true, the client will run migrations on startup,
once per namespace (as there should only be one embedded migrations FS per namespace).

Multiple pools, schemas, or migrations per service are not supported. Multiple databases per
PostgreSQL instance or multiple PostgreSQL servers per platform instance are not supported.
*/
type Client struct {
	Pgx    PgxIface
	config Config

	// This is the stdlib connection that is used for transactions
	SQLDB *sql.DB
}

/*
Connections and pools seems to be pulled in from env vars
We should be able to tell the platform how to run
*/

func New(ctx context.Context, config Config, o ...OptsFunc) (*Client, error) {
	for _, f := range o {
		config = f(config)
	}

	c := Client{
		config: config,
	}

	dbConfig, err := config.buildConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to parse pgx config: %w", err)
	}

	slog.Info("opening new database pool", slog.String("schema", config.Schema))
	pool, err := pgxpool.NewWithConfig(ctx, dbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create pgxpool: %w", err)
	}
	c.Pgx = pool
	// We need to create a stdlib connection for transactions
	c.SQLDB = stdlib.OpenDBFromPool(pool)

	// Connect to the database to verify the connection
	if c.config.VerifyConnection {
		if err := c.Pgx.Ping(ctx); err != nil {
			return nil, fmt.Errorf("failed to connect to database: %w", err)
		}
	}

	// Set the Client search_path to the schema
	q := fmt.Sprintf("SET search_path TO %s", config.Schema)
	if _, err := c.Pgx.Exec(ctx, q); err != nil {
		return nil, fmt.Errorf("failed to SET search_path for db Client schema to [%s]: %w", config.Schema, err)
	}

	slog.Info("successfully set database client search_path", slog.String("schema", config.Schema))
	return &c, nil
}

func (c *Client) Schema() string {
	return c.config.Schema
}

func (c *Client) Close() {
	c.Pgx.Close()
	c.SQLDB.Close()
}

func (c Config) buildConfig() (*pgxpool.Config, error) {
	u := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s",
		c.User,
		url.QueryEscape(c.Password),
		net.JoinHostPort(c.Host, fmt.Sprint(c.Port)),
		c.Database,
		c.SSLMode,
	)
	return pgxpool.ParseConfig(u)
}

// Common function for all queryRow calls
func (c Client) QueryRow(ctx context.Context, sql string, args []interface{}) (pgx.Row, error) {
	slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))
	return c.Pgx.QueryRow(ctx, sql, args...), nil
}

// Common function for all query calls
func (c Client) Query(ctx context.Context, sql string, args []interface{}) (pgx.Rows, error) {
	slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))
	r, e := c.Pgx.Query(ctx, sql, args...)
	if e != nil {
		return nil, WrapIfKnownInvalidQueryErr(e)
	}
	if r.Err() != nil {
		return nil, WrapIfKnownInvalidQueryErr(r.Err())
	}
	return r, nil
}

// Common function for all exec calls
func (c Client) Exec(ctx context.Context, sql string, args []interface{}) error {
	slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))
	tag, err := c.Pgx.Exec(ctx, sql, args...)
	if err != nil {
		return WrapIfKnownInvalidQueryErr(err)
	}

	if tag.RowsAffected() == 0 {
		return WrapIfKnownInvalidQueryErr(pgx.ErrNoRows)
	}

	return nil
}

//
// Helper functions for building SQL
//

// Postgres uses $1, $2, etc. for placeholders
func NewStatementBuilder() sq.StatementBuilderType {
	return sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
}
