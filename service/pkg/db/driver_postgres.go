package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// PostgresDriver implements the Driver interface for PostgreSQL
type PostgresDriver struct {
	pool  *pgxpool.Pool
	sqlDB *sql.DB
}

// NewPostgresDriver creates a new PostgreSQL driver instance
func NewPostgresDriver(ctx context.Context, config Config) (*PostgresDriver, error) {
	dbConfig, err := buildPostgresConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pgx config: %w", err)
	}

	slog.Info("opening new PostgreSQL database pool", slog.String("schema", config.Schema))
	pool, err := pgxpool.NewWithConfig(ctx, dbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create pgxpool: %w", err)
	}

	// Create stdlib connection for transactions and general SQL compatibility
	sqlDB := stdlib.OpenDBFromPool(pool)

	return &PostgresDriver{
		pool:  pool,
		sqlDB: sqlDB,
	}, nil
}

// Dialect returns the driver type
func (d *PostgresDriver) Dialect() DriverType {
	return DriverPostgres
}

// DB returns the underlying *sql.DB connection
func (d *PostgresDriver) DB() *sql.DB {
	return d.sqlDB
}

// Pool returns the underlying pgxpool.Pool for PostgreSQL-specific operations
// This maintains backward compatibility with existing code that uses pgx directly
func (d *PostgresDriver) Pool() *pgxpool.Pool {
	return d.pool
}

// Close closes the database connection
func (d *PostgresDriver) Close() error {
	d.pool.Close()
	return d.sqlDB.Close()
}

// Ping verifies the database connection is alive
func (d *PostgresDriver) Ping(ctx context.Context) error {
	return d.pool.Ping(ctx)
}

// buildPostgresConfig builds the pgxpool configuration from the Config
func buildPostgresConfig(c Config) (*pgxpool.Config, error) {
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
