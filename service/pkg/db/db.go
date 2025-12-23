package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
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
	MaxConns int32 `mapstructure:"max_connection_count" json:"max_connection_count" default:"4"`

	// Minimum amount of connections to keep in the pool.
	MinConns int32 `mapstructure:"min_connection_count" json:"min_connection_count" default:"0"`

	// Minimum amount of idle connections to keep in the pool.
	MinIdleConns int32 `mapstructure:"min_idle_connections_count" json:"min_idle_connections_count" default:"0"`

	// Maximum amount of time a connection may be reused, in seconds. Default: 3600 seconds (1 hour).
	MaxConnLifetime int `mapstructure:"max_connection_lifetime_seconds" json:"max_connection_lifetime_seconds" default:"3600"`

	// Maximum amount of time a connection may be idle before being closed, in seconds. Default: 1800 seconds (30 minutes).
	MaxConnIdleTime int `mapstructure:"max_connection_idle_seconds" json:"max_connection_idle_seconds" default:"1800"`

	// Period at which the pool will check the health of idle connections, in seconds. Default: 60 seconds (1 minute).
	HealthCheckPeriod int `mapstructure:"health_check_period_seconds" json:"health_check_period_seconds" default:"60"`
}

type Config struct {
	// Driver specifies the database driver to use: "postgres" or "sqlite"
	Driver DriverType `mapstructure:"driver" json:"driver" default:"postgres"`

	// PostgreSQL-specific configuration
	Host           string     `mapstructure:"host" json:"host" default:"localhost"`
	Port           int        `mapstructure:"port" json:"port" default:"5432"`
	Database       string     `mapstructure:"database" json:"database" default:"opentdf"`
	User           string     `mapstructure:"user" json:"user" default:"postgres"`
	Password       string     `mapstructure:"password" json:"password" default:"changeme"`
	SSLMode        string     `mapstructure:"sslmode" json:"sslmode" default:"prefer"`
	Schema         string     `mapstructure:"schema" json:"schema" default:"opentdf"`
	ConnectTimeout int        `mapstructure:"connect_timeout_seconds" json:"connect_timeout_seconds" default:"15"`
	Pool           PoolConfig `mapstructure:"pool" json:"pool"`

	// SQLite-specific configuration
	SQLitePath string `mapstructure:"sqlite_path" json:"sqlite_path" default:":memory:"`
	SQLiteMode string `mapstructure:"sqlite_mode" json:"sqlite_mode" default:"rwc"`

	RunMigrations    bool      `mapstructure:"runMigrations" json:"runMigrations" default:"true"`
	MigrationsFS     *embed.FS `mapstructure:"-" json:"-"`
	VerifyConnection bool      `mapstructure:"verifyConnection" json:"verifyConnection" default:"true"`
}

func (c Config) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.String("driver", string(c.Driver)),
		slog.String("schema", c.Schema),
		slog.Bool("runMigrations", c.RunMigrations),
		slog.Bool("verifyConnection", c.VerifyConnection),
	}

	if c.Driver == DriverSQLite {
		attrs = append(attrs,
			slog.String("sqlite_path", c.SQLitePath),
			slog.String("sqlite_mode", c.SQLiteMode),
		)
	} else {
		attrs = append(attrs,
			slog.String("host", c.Host),
			slog.Int("port", c.Port),
			slog.String("database", c.Database),
			slog.String("user", c.User),
			slog.String("password", "[REDACTED]"),
			slog.String("sslmode", c.SSLMode),
			slog.Int("connect_timeout_seconds", c.ConnectTimeout),
			slog.Group("pool",
				slog.Int("max_connection_count", int(c.Pool.MaxConns)),
				slog.Int("min_connection_count", int(c.Pool.MinConns)),
				slog.Int("max_connection_lifetime_seconds", c.Pool.MaxConnLifetime),
				slog.Int("max_connection_idle_seconds", c.Pool.MaxConnIdleTime),
				slog.Int("health_check_period_seconds", c.Pool.HealthCheckPeriod),
			),
		)
	}

	return slog.GroupValue(attrs...)
}

/*
A wrapper around a database connection pool.

Each service should have a single instance of the Client to share a connection pool,
schema (driven by the service namespace), and an embedded file system for migrations.

For PostgreSQL, the 'search_path' is set to the schema on connection to the database.

If the database config 'runMigrations' is set to true, the client will run migrations on startup,
once per namespace (as there should only be one embedded migrations FS per namespace).

Supports both PostgreSQL and SQLite as database backends.
*/
type Client struct {
	// Pgx is the PostgreSQL connection pool (nil for SQLite)
	Pgx PgxIface
	// Driver is the underlying database driver
	driver Driver
	// Logger for database operations
	Logger *logger.Logger
	// config holds the database configuration
	config Config
	// ranMigrations tracks if migrations have been run
	ranMigrations bool
	// SQLDB is the stdlib connection for transactions and compatibility
	SQLDB *sql.DB
	trace.Tracer
}

// DriverType returns the type of database driver being used
func (c *Client) DriverType() DriverType {
	return c.config.Driver
}

// Config returns the database configuration
func (c *Client) Config() Config {
	return c.config
}

/*
New creates a new database client with the specified configuration.

Supports both PostgreSQL and SQLite backends based on the Driver config field.
For PostgreSQL (default), it creates a pgxpool connection.
For SQLite, it creates a sql.DB connection with appropriate pragmas.
*/
func New(ctx context.Context, config Config, logCfg logger.Config, tracer *trace.Tracer, o ...OptsFunc) (*Client, error) {
	for _, f := range o {
		config = f(config)
	}

	// Default to PostgreSQL if not specified
	if config.Driver == "" {
		config.Driver = DriverPostgres
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
	c.Logger = l.With("schema", config.Schema).With("driver", string(config.Driver))

	// Initialize the appropriate driver
	switch config.Driver {
	case DriverSQLite:
		if err := c.initSQLite(ctx, config); err != nil {
			return nil, err
		}
	case DriverPostgres:
		if err := c.initPostgres(ctx, config); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", config.Driver)
	}

	// Verify the connection if requested
	if c.config.VerifyConnection {
		if err := c.driver.Ping(ctx); err != nil {
			return nil, fmt.Errorf("failed to connect to database: %w", err)
		}
	}

	return &c, nil
}

// initPostgres initializes a PostgreSQL connection
func (c *Client) initPostgres(ctx context.Context, config Config) error {
	pgDriver, err := NewPostgresDriver(ctx, config)
	if err != nil {
		return err
	}

	c.driver = pgDriver
	c.Pgx = pgDriver.Pool()
	c.SQLDB = pgDriver.DB()

	return nil
}

// initSQLite initializes a SQLite connection
func (c *Client) initSQLite(ctx context.Context, config Config) error {
	sqliteDriver, err := NewSQLiteDriver(ctx, config)
	if err != nil {
		return err
	}

	c.driver = sqliteDriver
	c.Pgx = nil // No pgx pool for SQLite
	c.SQLDB = sqliteDriver.DB()

	return nil
}

func (c *Client) Schema() string {
	return c.config.Schema
}

func (c *Client) Close() {
	if c.driver != nil {
		c.driver.Close()
	}
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

// NewStatementBuilder returns a statement builder configured for PostgreSQL ($1, $2, etc.)
// For backwards compatibility, this defaults to PostgreSQL placeholder format.
func NewStatementBuilder() sq.StatementBuilderType {
	return sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
}

// NewStatementBuilderForDriver returns a statement builder configured for the specified driver.
// PostgreSQL uses $1, $2, etc. while SQLite uses ?, ?, etc.
func NewStatementBuilderForDriver(driver DriverType) sq.StatementBuilderType {
	switch driver {
	case DriverSQLite:
		return sq.StatementBuilder.PlaceholderFormat(sq.Question)
	default:
		return sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
	}
}
