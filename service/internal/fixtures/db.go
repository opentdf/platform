package fixtures

import (
	"context"
	"fmt"
	"log/slog"
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
		// SQLite doesn't have schemas - drop all tables instead
		// For in-memory databases, this is typically not needed
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
