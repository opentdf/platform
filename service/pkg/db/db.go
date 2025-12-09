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
	"strings"
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

// ReplicaConfig holds configuration for a single read replica
type ReplicaConfig struct {
	Host string `mapstructure:"host" json:"host"`
	Port int    `mapstructure:"port" json:"port"`
}

type Config struct {
	Host           string     `mapstructure:"host" json:"host" default:"localhost"`
	Port           int        `mapstructure:"port" json:"port" default:"5432"`
	Database       string     `mapstructure:"database" json:"database" default:"opentdf"`
	User           string     `mapstructure:"user" json:"user" default:"postgres"`
	Password       string     `mapstructure:"password" json:"password" default:"changeme"`
	SSLMode        string     `mapstructure:"sslmode" json:"sslmode" default:"prefer"`
	Schema         string     `mapstructure:"schema" json:"schema" default:"opentdf"`
	ConnectTimeout int        `mapstructure:"connect_timeout_seconds" json:"connect_timeout_seconds" default:"15"`
	Pool           PoolConfig `mapstructure:"pool" json:"pool"`

	// PrimaryHosts optionally specifies multiple primary database hosts for automatic failover.
	// When configured, pgx will try each host in order using target_session_attrs=primary.
	// If empty, uses Host and Port fields instead.
	PrimaryHosts []ReplicaConfig `mapstructure:"primary_hosts" json:"primary_hosts"`

	// ReadReplicas holds configuration for read replica databases
	// If empty, all reads will go to the primary database
	ReadReplicas []ReplicaConfig `mapstructure:"read_replicas" json:"read_replicas"`

	RunMigrations    bool      `mapstructure:"runMigrations" json:"runMigrations" default:"true"`
	MigrationsFS     *embed.FS `mapstructure:"-" json:"-"`
	VerifyConnection bool      `mapstructure:"verifyConnection" json:"verifyConnection" default:"true"`
}

func (c Config) LogValue() slog.Value {
	attrs := []slog.Attr{
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
	}

	// Add primary hosts information if configured (for failover)
	if len(c.PrimaryHosts) > 0 {
		primaryAttrs := make([]slog.Attr, len(c.PrimaryHosts))
		for i, primary := range c.PrimaryHosts {
			primaryAttrs[i] = slog.String(fmt.Sprintf("primary_%d", i+1), fmt.Sprintf("%s:%d", primary.Host, primary.Port))
		}
		attrs = append(attrs, slog.Group("primary_hosts", slog.Any("hosts", primaryAttrs)))
	}

	// Add read replicas information if configured
	if len(c.ReadReplicas) > 0 {
		replicaAttrs := make([]slog.Attr, len(c.ReadReplicas))
		for i, replica := range c.ReadReplicas {
			replicaAttrs[i] = slog.String(fmt.Sprintf("replica_%d", i+1), fmt.Sprintf("%s:%d", replica.Host, replica.Port))
		}
		attrs = append(attrs, slog.Group("read_replicas", slog.Any("replicas", replicaAttrs)))
	}

	return slog.GroupValue(attrs...)
}

/*
A wrapper around a pgxpool.Pool and sql.DB reference.

Each service should have a single instance of the Client to share a connection pool,
schema (driven by the service namespace), and an embedded file system for migrations.

The 'search_path' is set to the schema on connection to the database.

If the database config 'runMigrations' is set to true, the client will run migrations on startup,
once per namespace (as there should only be one embedded migrations FS per namespace).

The client supports read replicas for horizontal scaling. When configured with read replicas,
write operations (Exec) go to the primary database, while read operations (Query, QueryRow)
are load-balanced across read replicas using a round-robin strategy.
*/
type Client struct {
	// Pgx is the primary database connection pool (used for writes and migrations)
	Pgx PgxIface
	// ReadReplicas holds connection pools to read replica databases
	// If empty, all reads go to the primary (Pgx)
	ReadReplicas  []PgxIface
	replicaCBs    *replicaCircuitBreakers // Circuit breakers for read replicas (using gobreaker)
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
		config:       config,
		ReadReplicas: make([]PgxIface, 0),
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

	// Validate configuration: cannot specify both single host and multi-host primary
	if len(config.PrimaryHosts) > 0 && config.Host != "" {
		return nil, fmt.Errorf("invalid configuration: cannot specify both 'host' and 'primary_hosts' - use one or the other")
	}

	// Build primary database connection
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

	slog.Info("opening primary database pool", slog.String("schema", config.Schema))
	pool, err := pgxpool.NewWithConfig(ctx, dbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create primary pgxpool: %w", err)
	}
	c.Pgx = pool
	// We need to create a stdlib connection for transactions
	c.SQLDB = stdlib.OpenDBFromPool(pool)

	// Connect to the primary database to verify the connection
	if c.config.VerifyConnection {
		if err := c.Pgx.Ping(ctx); err != nil {
			return nil, fmt.Errorf("failed to connect to primary database: %w", err)
		}
	}

	// Set up read replica connections if configured
	if len(config.ReadReplicas) > 0 {
		slog.Info("configuring read replicas", slog.Int("count", len(config.ReadReplicas)))

		for i, replicaCfg := range config.ReadReplicas {
			replicaConfig, err := config.buildReplicaConfig(replicaCfg)
			if err != nil {
				return nil, fmt.Errorf("failed to parse replica %d config: %w", i+1, err)
			}

			// Use the same OnNotice handler for replicas
			replicaConfig.ConnConfig.OnNotice = dbConfig.ConnConfig.OnNotice

			slog.Info("opening read replica pool",
				slog.Int("replica", i+1),
				slog.String("host", replicaCfg.Host),
				slog.Int("port", replicaCfg.Port),
			)

			replicaPool, err := pgxpool.NewWithConfig(ctx, replicaConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to create read replica %d pgxpool: %w", i+1, err)
			}

			// Verify replica connection if configured
			if c.config.VerifyConnection {
				if err := replicaPool.Ping(ctx); err != nil {
					return nil, fmt.Errorf("failed to connect to read replica %d: %w", i+1, err)
				}
			}

			c.ReadReplicas = append(c.ReadReplicas, replicaPool)
		}

		slog.Info("read replicas configured successfully", slog.Int("count", len(c.ReadReplicas)))

		// Initialize circuit breakers for replicas
		c.replicaCBs = newReplicaCircuitBreakers(c.ReadReplicas, c.Logger.Logger)
	}

	return &c, nil
}

func (c *Client) Schema() string {
	return c.config.Schema
}

func (c *Client) Close() {
	c.Pgx.Close()
	c.SQLDB.Close()

	// Close all read replica connections
	for i, replica := range c.ReadReplicas {
		slog.Debug("closing read replica connection", slog.Int("replica", i+1))
		replica.Close()
	}
}

// getReadConnection returns a connection pool and replica index for read operations.
// It implements intelligent routing with circuit breaker protection and context awareness:
// - Checks context for forced primary routing (for read-after-write consistency)
// - Uses circuit breaker-protected round-robin across replicas
// - Falls back to primary if all circuit breakers are open
// This method is concurrency-safe and can be called from multiple goroutines.
func (c *Client) getReadConnection(ctx context.Context) (PgxIface, int) {
	// Check if context forces primary routing (e.g., for read-after-write)
	if ctx != nil && shouldForcePrimary(ctx) {
		return c.Pgx, -1 // -1 indicates primary, not a replica
	}

	// No replicas configured, use primary for reads
	if len(c.ReadReplicas) == 0 {
		return c.Pgx, -1
	}

	// If circuit breakers are enabled, get a healthy replica
	if c.replicaCBs != nil {
		pool, idx := c.replicaCBs.getHealthyReplica()
		if pool != nil {
			return pool, idx
		}

		// All circuit breakers open, fall back to primary
		c.Logger.Warn("all read replica circuit breakers open, falling back to primary")
		return c.Pgx, -1
	}

	// Circuit breakers not enabled (shouldn't happen), use primary
	return c.Pgx, -1
}

func (c Config) buildConfig() (*pgxpool.Config, error) {
	var u string

	// Build connection string with multi-host support for primary failover
	if len(c.PrimaryHosts) > 0 {
		// Use multi-host format with target_session_attrs=primary for automatic failover
		// Format: postgres://user:pass@host1:port1,host2:port2/db?target_session_attrs=primary
		hosts := make([]string, len(c.PrimaryHosts))
		for i, h := range c.PrimaryHosts {
			hosts[i] = net.JoinHostPort(h.Host, strconv.Itoa(h.Port))
		}
		u = fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s&target_session_attrs=primary",
			c.User,
			url.QueryEscape(c.Password),
			strings.Join(hosts, ","),
			c.Database,
			c.SSLMode,
		)
	} else {
		// Single host configuration (backward compatible)
		u = fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s",
			c.User,
			url.QueryEscape(c.Password),
			net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
			c.Database,
			c.SSLMode,
		)
	}

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
		schema := pgx.Identifier{c.Schema}.Sanitize()
		_, err := conn.Exec(ctx, "SET search_path TO "+schema)
		if err != nil {
			slog.Error("failed to set database client search_path",
				slog.String("schema", schema),
				slog.Any("error", err),
			)
			return err
		}
		slog.Debug("successfully set database client search_path", slog.String("schema", schema))
		return nil
	}
	return parsed, nil
}

// buildReplicaConfig builds a pgxpool.Config for a read replica
func (c Config) buildReplicaConfig(replica ReplicaConfig) (*pgxpool.Config, error) {
	u := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s",
		c.User,
		url.QueryEscape(c.Password),
		net.JoinHostPort(replica.Host, strconv.Itoa(replica.Port)),
		c.Database,
		c.SSLMode,
	)
	parsed, err := pgxpool.ParseConfig(u)
	if err != nil {
		return nil, fmt.Errorf("failed to parse replica pgx config: %w", err)
	}

	// Apply the same connection and pool configurations as primary
	if c.Pool.MinConns > 0 {
		parsed.MinConns = c.Pool.MinConns
	}
	if c.Pool.MinIdleConns > 0 {
		parsed.MinIdleConns = c.Pool.MinIdleConns
	}
	parsed.ConnConfig.ConnectTimeout = time.Duration(c.ConnectTimeout) * time.Second
	parsed.MaxConns = c.Pool.MaxConns
	parsed.MaxConnLifetime = time.Duration(c.Pool.MaxConnLifetime) * time.Second
	parsed.MaxConnIdleTime = time.Duration(c.Pool.MaxConnIdleTime) * time.Second
	parsed.HealthCheckPeriod = time.Duration(c.Pool.HealthCheckPeriod) * time.Second

	// Configure the search_path schema immediately on connection opening
	parsed.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET search_path TO "+pgx.Identifier{c.Schema}.Sanitize())
		if err != nil {
			slog.Error("failed to set replica database client search_path",
				slog.String("schema", c.Schema),
				slog.Any("error", err),
			)
			return err
		}
		slog.Debug("successfully set replica database client search_path", slog.String("schema", c.Schema))
		return nil
	}
	return parsed, nil
}

// Common function for all queryRow calls
// Routes read queries to read replicas if configured, with circuit breaker protection and context awareness
func (c *Client) QueryRow(ctx context.Context, sql string, args []interface{}) (pgx.Row, error) {
	c.Logger.TraceContext(ctx, "sql", slog.String("sql", sql), slog.Any("args", args))

	_, replicaIdx := c.getReadConnection(ctx)

	// If using a replica with circuit breaker, execute through circuit breaker
	if replicaIdx >= 0 && c.replicaCBs != nil {
		return c.replicaCBs.executeQueryRow(ctx, replicaIdx, sql, args)
	}

	// Otherwise use primary
	return c.Pgx.QueryRow(ctx, sql, args...), nil
}

// Common function for all query calls
// Routes read queries to read replicas if configured, with circuit breaker protection and context awareness
func (c *Client) Query(ctx context.Context, sql string, args []interface{}) (pgx.Rows, error) {
	c.Logger.TraceContext(ctx, "sql", slog.String("sql", sql), slog.Any("args", args))

	_, replicaIdx := c.getReadConnection(ctx)

	// If using a replica with circuit breaker, execute through circuit breaker
	if replicaIdx >= 0 && c.replicaCBs != nil {
		r, e := c.replicaCBs.executeQuery(ctx, replicaIdx, sql, args)
		if e != nil {
			return nil, WrapIfKnownInvalidQueryErr(e)
		}
		if r.Err() != nil {
			return nil, WrapIfKnownInvalidQueryErr(r.Err())
		}
		return r, nil
	}

	// Otherwise use primary
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
func (c *Client) Exec(ctx context.Context, sql string, args []interface{}) error {
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
