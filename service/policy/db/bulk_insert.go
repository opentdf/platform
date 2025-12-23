package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/opentdf/platform/service/pkg/db"
)

// BulkInserter provides a unified interface for bulk insert operations
// that works with both PostgreSQL (using COPY protocol) and SQLite (using batched INSERTs).
type BulkInserter interface {
	// BulkInsert inserts multiple rows into the specified table.
	// For PostgreSQL, this uses the efficient COPY protocol.
	// For SQLite, this uses batched INSERT statements within a transaction.
	BulkInsert(ctx context.Context, table string, columns []string, rows [][]any) (int64, error)
}

// PostgresBulkInserter implements BulkInserter for PostgreSQL using pgx CopyFrom.
type PostgresBulkInserter struct {
	pool db.PgxIface
}

// NewPostgresBulkInserter creates a new PostgreSQL bulk inserter.
func NewPostgresBulkInserter(pool db.PgxIface) *PostgresBulkInserter {
	return &PostgresBulkInserter{pool: pool}
}

// BulkInsert uses PostgreSQL's COPY protocol for efficient bulk inserts.
func (p *PostgresBulkInserter) BulkInsert(ctx context.Context, table string, columns []string, rows [][]any) (int64, error) {
	return p.pool.CopyFrom(
		ctx,
		pgx.Identifier{table},
		columns,
		pgx.CopyFromRows(rows),
	)
}

// SQLiteBulkInserter implements BulkInserter for SQLite using batched INSERTs.
type SQLiteBulkInserter struct {
	db *sql.DB
}

// NewSQLiteBulkInserter creates a new SQLite bulk inserter.
func NewSQLiteBulkInserter(db *sql.DB) *SQLiteBulkInserter {
	return &SQLiteBulkInserter{db: db}
}

// BulkInsert uses batched INSERT statements for SQLite.
// SQLite doesn't support COPY, so we use multi-value INSERT statements
// within a transaction for better performance.
func (s *SQLiteBulkInserter) BulkInsert(ctx context.Context, table string, columns []string, rows [][]any) (int64, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	// Start a transaction for the bulk insert
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Build the INSERT statement with placeholders
	// SQLite has a limit on the number of variables (SQLITE_MAX_VARIABLE_NUMBER, default 999)
	// So we batch inserts to stay under this limit
	const maxVarsPerBatch = 900 // Leave some headroom
	varsPerRow := len(columns)
	rowsPerBatch := maxVarsPerBatch / varsPerRow
	if rowsPerBatch < 1 {
		rowsPerBatch = 1
	}

	var totalInserted int64

	for start := 0; start < len(rows); start += rowsPerBatch {
		end := start + rowsPerBatch
		if end > len(rows) {
			end = len(rows)
		}
		batch := rows[start:end]

		// Build placeholders for this batch
		rowPlaceholders := make([]string, len(batch))
		args := make([]any, 0, len(batch)*varsPerRow)

		for i, row := range batch {
			placeholders := make([]string, varsPerRow)
			for j := range placeholders {
				placeholders[j] = "?"
			}
			rowPlaceholders[i] = "(" + strings.Join(placeholders, ", ") + ")"
			args = append(args, row...)
		}

		query := fmt.Sprintf(
			"INSERT INTO %s (%s) VALUES %s",
			table,
			strings.Join(columns, ", "),
			strings.Join(rowPlaceholders, ", "),
		)

		result, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return totalInserted, fmt.Errorf("failed to execute batch insert: %w", err)
		}

		affected, _ := result.RowsAffected()
		totalInserted += affected
	}

	if err := tx.Commit(); err != nil {
		return totalInserted, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return totalInserted, nil
}

// GetBulkInserter returns the appropriate BulkInserter for the given PolicyDBClient.
func (c *PolicyDBClient) GetBulkInserter() BulkInserter {
	if c.IsSQLite() {
		return NewSQLiteBulkInserter(c.SQLDB)
	}
	return NewPostgresBulkInserter(c.Pgx)
}

// BulkInsertRegisteredResourceActionAttributeValues is a helper method that
// provides a unified interface for bulk inserting registered resource action attribute values.
// This replaces the sqlc-generated createRegisteredResourceActionAttributeValues for SQLite.
func (c *PolicyDBClient) BulkInsertRegisteredResourceActionAttributeValues(
	ctx context.Context,
	params []createRegisteredResourceActionAttributeValuesParams,
) (int64, error) {
	if len(params) == 0 {
		return 0, nil
	}

	if c.IsPostgres() {
		// Use the sqlc-generated method for PostgreSQL
		return c.queries.createRegisteredResourceActionAttributeValues(ctx, params)
	}

	// Convert params to generic rows for SQLite
	rows := make([][]any, len(params))
	for i, p := range params {
		rows[i] = []any{p.RegisteredResourceValueID, p.ActionID, p.AttributeValueID}
	}

	inserter := c.GetBulkInserter()
	return inserter.BulkInsert(
		ctx,
		"registered_resource_action_attribute_values",
		[]string{"registered_resource_value_id", "action_id", "attribute_value_id"},
		rows,
	)
}
