package fixtures

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	policydb "github.com/opentdf/platform/service/policy/db"
	"github.com/opentdf/platform/service/tracing"
	"go.opentelemetry.io/otel"
)

var (
	// Configured default LIST Limit when working with fixtures
	fixtureLimitDefault int32 = 1000
	fixtureLimitMax     int32 = 5000
)

type DBInterface struct {
	Client       *db.Client
	PolicyClient policydb.PolicyDBClient
	Schema       string
	LimitDefault int32
	LimitMax     int32
}

// IsSQLite returns true if the database is SQLite
func (d *DBInterface) IsSQLite() bool {
	return d.Client.DriverType() == db.DriverSQLite
}

func NewDBInterface(ctx context.Context, cfg config.Config) DBInterface {
	config := cfg.DB
	config.Schema = cfg.DB.Schema
	logCfg := cfg.Logger
	tracer := otel.Tracer(tracing.ServiceName)

	// For SQLite with in-memory database, use unique temp file per schema to enable parallel tests
	if config.Driver == db.DriverSQLite && (config.SQLitePath == ":memory:" || config.SQLitePath == "") && config.Schema != "" {
		tmpDir := os.TempDir()
		dbFileName := fmt.Sprintf("opentdf_test_%s.db", config.Schema)
		config.SQLitePath = filepath.Join(tmpDir, dbFileName)
		slog.Info("using unique SQLite database file for test isolation",
			slog.String("schema", config.Schema),
			slog.String("path", config.SQLitePath))
		// Remove any existing database file to start fresh
		_ = os.Remove(config.SQLitePath)
		_ = os.Remove(config.SQLitePath + "-wal")
		_ = os.Remove(config.SQLitePath + "-shm")
	}

	c, err := db.New(ctx, config, logCfg, &tracer)
	if err != nil {
		slog.Error("issue creating database client", slog.Any("error", err))
		panic(err)
	}

	logger, err := logger.NewLogger(logger.Config{
		Level:  cfg.Logger.Level,
		Output: cfg.Logger.Output,
		Type:   cfg.Logger.Type,
	})
	if err != nil {
		slog.Error("issue creating logger", slog.Any("error", err))
		panic(err)
	}

	return DBInterface{
		Client:       c,
		Schema:       config.Schema,
		PolicyClient: policydb.NewClient(c, logger, fixtureLimitMax, fixtureLimitDefault),
		LimitDefault: fixtureLimitDefault,
		LimitMax:     fixtureLimitMax,
	}
}

// convertToSQLiteArg converts PostgreSQL-specific types to SQLite-compatible types.
// Slices are converted to JSON strings since SQLite doesn't support array types.
// Special case: []byte is treated as already-serialized JSON and converted directly to string.
func convertToSQLiteArg(arg any) any {
	if arg == nil {
		return nil
	}

	// Special case: []byte is typically already-serialized JSON (e.g., from json.Marshal)
	// Convert directly to string to avoid double-encoding (json.Marshal on []byte produces base64)
	if b, ok := arg.([]byte); ok {
		return string(b)
	}

	v := reflect.ValueOf(arg)
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		// Convert slices/arrays to JSON strings for SQLite
		jsonBytes, err := json.Marshal(arg)
		if err != nil {
			slog.Error("failed to marshal slice to JSON for SQLite", slog.Any("error", err))
			return arg
		}
		return string(jsonBytes)
	default:
		return arg
	}
}

// TableName returns a sanitized fully-qualified table name.
func (d *DBInterface) TableName(v string) string {
	if d.IsSQLite() {
		// SQLite doesn't use schemas, just quote the table name
		return `"` + v + `"`
	}
	return pgx.Identifier{d.Schema, v}.Sanitize()
}

// ExecInsert inserts multiple rows into a table using parameterized queries.
// Each row's values are passed as any types, allowing pgx to handle type conversion.
func (d *DBInterface) ExecInsert(ctx context.Context, table string, columns []string, values ...[]any) (int64, error) {
	if len(values) == 0 {
		return 0, nil
	}

	// Build the INSERT statement with placeholders
	numColumns := len(columns)
	var placeholders []string
	var allArgs []any

	// Use different placeholder styles for PostgreSQL vs SQLite
	useDollarPlaceholders := !d.IsSQLite()
	isSQLite := d.IsSQLite()

	placeholderNum := 1
	for _, row := range values {
		if len(row) != numColumns {
			slog.Error("column count mismatch",
				slog.Int("expected", numColumns),
				slog.Int("got", len(row)),
			)
			return 0, fmt.Errorf("column count mismatch: expected %d, got %d", numColumns, len(row))
		}

		var rowPlaceholders []string
		for _, arg := range row {
			if useDollarPlaceholders {
				rowPlaceholders = append(rowPlaceholders, fmt.Sprintf("$%d", placeholderNum))
			} else {
				rowPlaceholders = append(rowPlaceholders, "?")
			}
			placeholderNum++

			// For SQLite, convert slice types to JSON strings
			if isSQLite {
				arg = convertToSQLiteArg(arg)
			}
			allArgs = append(allArgs, arg)
		}
		placeholders = append(placeholders, "("+strings.Join(rowPlaceholders, ",")+")")
	}

	// Get table name based on database type
	tableName := d.TableName(table)

	// Safely sanitize column names
	sanitizedColumns := make([]string, len(columns))
	for i, col := range columns {
		if d.IsSQLite() {
			sanitizedColumns[i] = `"` + col + `"`
		} else {
			sanitizedColumns[i] = pgx.Identifier{col}.Sanitize()
		}
	}

	sql := "INSERT INTO " + tableName +
		" (" + strings.Join(sanitizedColumns, ",") + ")" +
		" VALUES " + strings.Join(placeholders, ",")

	if d.IsSQLite() {
		result, err := d.Client.SQLDB.ExecContext(ctx, sql, allArgs...)
		if err != nil {
			slog.Error("insert error",
				slog.String("stmt", sql),
				slog.Any("err", err),
			)
			return 0, err
		}
		return result.RowsAffected()
	}

	pconn, err := d.Client.Pgx.Exec(ctx, sql, allArgs...)
	if err != nil {
		slog.Error("insert error",
			slog.String("stmt", sql),
			slog.Any("err", err),
		)
		return 0, err
	}
	return pconn.RowsAffected(), err
}

func (d *DBInterface) DropSchema(ctx context.Context) error {
	if d.IsSQLite() {
		// SQLite doesn't have schemas - delete data from all tables except migration-related ones
		// Get list of all tables, excluding system tables and migration tracking
		rows, err := d.Client.SQLDB.QueryContext(ctx, `
			SELECT name FROM sqlite_master
			WHERE type='table'
			AND name NOT LIKE 'sqlite_%'
			AND name != 'goose_db_version'
		`)
		if err != nil {
			slog.Error("failed to query tables", slog.Any("err", err))
			return err
		}
		defer rows.Close()

		var tables []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return err
			}
			tables = append(tables, name)
		}

		// Disable foreign keys temporarily for clean deletion
		if _, err := d.Client.SQLDB.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
			return err
		}

		// Delete all data from tables (preserve schema for next test)
		for _, table := range tables {
			var sql string
			if table == "actions" {
				// Keep standard actions (inserted by migrations), delete only custom actions
				sql = `DELETE FROM "actions" WHERE is_standard = 0`
			} else {
				sql = fmt.Sprintf("DELETE FROM \"%s\"", table)
			}
			if _, err := d.Client.SQLDB.ExecContext(ctx, sql); err != nil {
				slog.Error("delete error", slog.String("table", table), slog.Any("err", err))
				// Continue trying other tables
			}
		}

		// Re-enable foreign keys
		if _, err := d.Client.SQLDB.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
			return err
		}

		return nil
	}

	sql := "DROP SCHEMA IF EXISTS " + pgx.Identifier{d.Schema}.Sanitize() + " CASCADE"
	_, err := d.Client.Pgx.Exec(ctx, sql)
	if err != nil {
		slog.Error("drop error",
			slog.String("stmt", sql),
			slog.Any("err", err),
		)
		return err
	}
	return nil
}
