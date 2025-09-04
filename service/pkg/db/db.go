package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/opentdf/platform/service/logger"
	"go.opentelemetry.io/otel/trace"
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
	Begin(ctx context.Context) (pgx.Tx, error)
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
	Ping(context.Context) error
	Close()
	Config() *pgxpool.Config
	CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error)
}

// PoolConfig holds all connection pool related configuration
type PoolConfig struct {
	// Maximum amount of connections to keep in the pool.
	MaxConns int32 `mapstructure:"max_connection_count" json:"maxConnectionsCount" default:"4"`

	// Minimum amount of connections to keep in the pool.
	MinConns int32 `mapstructure:"min_connection_count" json:"minConnectionsCount" default:"0"`

	// Minimum amount of idle connections to keep in the pool.
	MinIdleConns int32 `mapstructure:"min_idle_connections_count" json:"minIdleConnectionsCount" default:"0"`

	// Maximum amount of time a connection may be reused, in seconds. Default: 3600 seconds (1 hour).
	MaxConnLifetime int `mapstructure:"max_connection_lifetime_seconds" json:"maxConnectionLifetimeSeconds" default:"3600"`

	// Maximum amount of time a connection may be idle before being closed, in seconds. Default: 1800 seconds (30 minutes).
	MaxConnIdleTime int `mapstructure:"max_connection_idle_seconds" json:"maxConnectionIdleSeconds" default:"1800"`

	// Period at which the pool will check the health of idle connections, in seconds. Default: 60 seconds (1 minute).
	HealthCheckPeriod int `mapstructure:"health_check_period_seconds" json:"healthCheckPeriodSeconds" default:"60"`
}

type Config struct {
	Host           string     `mapstructure:"host" json:"host" default:"localhost"`
	Port           int        `mapstructure:"port" json:"port" default:"5432"`
	Database       string     `mapstructure:"database" json:"database" default:"opentdf"`
	User           string     `mapstructure:"user" json:"user" default:"postgres"`
	Password       string     `mapstructure:"password" json:"password" default:"changeme"`
	SSLMode        string     `mapstructure:"sslmode" json:"sslmode" default:"prefer"`
	Schema         string     `mapstructure:"schema" json:"schema" default:"opentdf"`
	ConnectTimeout int        `mapstructure:"connect_timeout_seconds" json:"connectTimeoutSeconds" default:"15"`
	Pool           PoolConfig `mapstructure:"pool" json:"pool"`

	RunMigrations    bool      `mapstructure:"runMigrations" json:"runMigrations" default:"true"`
	MigrationsFS     *embed.FS `mapstructure:"-"`
	VerifyConnection bool      `mapstructure:"verifyConnection" json:"verifyConnection" default:"true"`
}

func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("host", c.Host),
		slog.Int("port", c.Port),
		slog.String("database", c.Database),
		slog.String("user", c.User),
		slog.String("password", "[REDACTED]"),
		slog.String("sslmode", c.SSLMode),
		slog.String("schema", c.Schema),
		slog.Int("connect_timeout_seconds", c.ConnectTimeout),
		slog.Group("pool",
			slog.Int("max_connection_count", int(c.Pool.MaxConns)),
			slog.Int("min_connection_count", int(c.Pool.MinConns)),
			slog.Int("max_connection_lifetime_seconds", c.Pool.MaxConnLifetime),
			slog.Int("max_connection_idle_seconds", c.Pool.MaxConnIdleTime),
			slog.Int("health_check_period_seconds", c.Pool.HealthCheckPeriod),
		),
		slog.Bool("runMigrations", c.RunMigrations),
		slog.Bool("verifyConnection", c.VerifyConnection),
	)
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
	Pgx           PgxIface
	Logger        *logger.Logger
	config        Config
	ranMigrations bool
	// This is the stdlib connection that is used for transactions
	SQLDB *sql.DB
	trace.Tracer
}

/*
Connections and pools seems to be pulled in from env vars
We should be able to tell the platform how to run
*/
func New(ctx context.Context, config Config, logCfg logger.Config, tracer *trace.Tracer, o ...OptsFunc) (*Client, error) {
	for _, f := range o {
		config = f(config)
	}

	c := Client{
		config: config,
	}

	if tracer != nil {
		c.Tracer = *tracer
	}

	l, err := logger.NewLogger(logger.Config{
		Output: logCfg.Output,
		Type:   logCfg.Type,
		Level:  logCfg.Level,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}
	c.Logger = l.With("schema", config.Schema)

	dbConfig, err := config.buildConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to parse pgx config: %w", err)
	}

	dbConfig.ConnConfig.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
		switch n.Severity {
		case "DEBUG":
			c.Logger.Debug("database notice", slog.String("message", n.Message))
		case "NOTICE":
			c.Logger.Info("database notice", slog.String("message", n.Message))
		case "WARNING":
			c.Logger.Warn("database notice", slog.String("message", n.Message))
		case "ERROR":
			c.Logger.Error("database notice", slog.String("message", n.Message))
		}
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
		net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		c.Database,
		c.SSLMode,
	)
	parsed, err := pgxpool.ParseConfig(u)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pgx config: %w", err)
	}

	// Apply connection and pool configurations
	if c.Pool.MinConns > 0 {
		parsed.MinConns = c.Pool.MinConns
	}
	if c.Pool.MinIdleConns > 0 {
		parsed.MinIdleConns = c.Pool.MinIdleConns
	}
	// Non-zero defaults
	parsed.ConnConfig.ConnectTimeout = time.Duration(c.ConnectTimeout) * time.Second
	parsed.MaxConns = c.Pool.MaxConns
	parsed.MaxConnLifetime = time.Duration(c.Pool.MaxConnLifetime) * time.Second
	parsed.MaxConnIdleTime = time.Duration(c.Pool.MaxConnIdleTime) * time.Second
	parsed.HealthCheckPeriod = time.Duration(c.Pool.HealthCheckPeriod) * time.Second

	// Configure the search_path schema immediately on connection opening
	parsed.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET search_path TO "+pgx.Identifier{c.Schema}.Sanitize())
		if err != nil {
			slog.Error("failed to set database client search_path",
				slog.String("schema", c.Schema),
				slog.Any("error", err),
			)
			return err
		}
		slog.Debug("successfully set database client search_path", slog.String("schema", c.Schema))
		return nil
	}
	return parsed, nil
}

// Common function for all queryRow calls
func (c Client) QueryRow(ctx context.Context, sql string, args []interface{}) (pgx.Row, error) {
	c.Logger.TraceContext(ctx, "sql", slog.String("sql", sql), slog.Any("args", args))
	return c.Pgx.QueryRow(ctx, sql, args...), nil
}

// Common function for all query calls
func (c Client) Query(ctx context.Context, sql string, args []interface{}) (pgx.Rows, error) {
	c.Logger.TraceContext(ctx, "sql", slog.String("sql", sql), slog.Any("args", args))
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
	c.Logger.TraceContext(ctx, "sql", slog.String("sql", sql), slog.Any("args", args))
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
