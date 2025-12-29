package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// SQLiteDriver implements the Driver interface for SQLite
type SQLiteDriver struct {
	db *sql.DB
}

// NewSQLiteDriver creates a new SQLite driver instance
func NewSQLiteDriver(ctx context.Context, config Config) (*SQLiteDriver, error) {
	dsn := buildSQLiteDSN(config)

	slog.Info("opening SQLite database", slog.String("path", config.SQLitePath))
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// Apply SQLite pragmas for optimal performance and safety
	if err := applySQLitePragmas(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to apply SQLite pragmas: %w", err)
	}

	// SQLite is single-writer, so limit connections appropriately
	// Use 1 for writes, but allow multiple readers with WAL mode
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	return &SQLiteDriver{
		db: db,
	}, nil
}

// Dialect returns the driver type
func (d *SQLiteDriver) Dialect() DriverType {
	return DriverSQLite
}

// DB returns the underlying *sql.DB connection
func (d *SQLiteDriver) DB() *sql.DB {
	return d.db
}

// Close closes the database connection
func (d *SQLiteDriver) Close() error {
	return d.db.Close()
}

// Ping verifies the database connection is alive
func (d *SQLiteDriver) Ping(ctx context.Context) error {
	return d.db.PingContext(ctx)
}

// buildSQLiteDSN constructs the SQLite data source name from config
func buildSQLiteDSN(config Config) string {
	path := config.SQLitePath
	if path == "" {
		path = ":memory:"
	}

	// If path is already a full URI with parameters, use it as-is
	if strings.HasPrefix(path, "file:") && strings.Contains(path, "?") {
		return path
	}

	// Build connection string with mode
	var params []string

	// Set mode (rwc = read-write-create, ro = read-only, rw = read-write)
	mode := config.SQLiteMode
	if mode == "" {
		mode = "rwc"
	}
	params = append(params, "mode="+mode)

	// Enable shared cache for in-memory databases to allow multiple connections
	if path == ":memory:" {
		params = append(params, "cache=shared")
	}

	// Build DSN
	if len(params) > 0 {
		return fmt.Sprintf("file:%s?%s", path, strings.Join(params, "&"))
	}
	return path
}

// applySQLitePragmas applies performance and safety pragmas to the SQLite connection
func applySQLitePragmas(ctx context.Context, db *sql.DB) error {
	pragmas := []string{
		// Write-Ahead Logging for better concurrent read performance
		"PRAGMA journal_mode=WAL",
		// Synchronous NORMAL is a good balance between safety and performance
		"PRAGMA synchronous=NORMAL",
		// Enable foreign key constraints (disabled by default in SQLite)
		"PRAGMA foreign_keys=ON",
		// Set busy timeout to 5 seconds to avoid immediate SQLITE_BUSY errors
		"PRAGMA busy_timeout=5000",
		// Use memory for temp tables (faster)
		"PRAGMA temp_store=MEMORY",
		// Enable memory-mapped I/O for better read performance (64MB)
		"PRAGMA mmap_size=67108864",
		// Cache size in KB (negative = KB, positive = pages)
		"PRAGMA cache_size=-64000",
	}

	for _, pragma := range pragmas {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			slog.Warn("failed to apply SQLite pragma",
				slog.String("pragma", pragma),
				slog.Any("error", err),
			)
			// Don't fail on pragma errors, just log them
			// Some pragmas may not be supported on all SQLite versions
		}
	}

	slog.Debug("applied SQLite pragmas successfully")
	return nil
}
