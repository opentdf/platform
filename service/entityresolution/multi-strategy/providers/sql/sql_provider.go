package sql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/opentdf/platform/service/entityresolution/multi-strategy/types"
)

var (
	// driverRegMu guards lazy driver registration to prevent duplicate-register panics.
	driverRegMu       sync.Mutex
	registeredDrivers = make(map[string]struct{})
)

// ensureDriverRegistered lazily registers the named database/sql driver the first
// time a SQL provider for that driver is created. This avoids the need for
// consumers to add blank driver imports to their own binaries.
//
// Uses pgx/v5/stdlib for postgres (already a platform dependency). Other drivers
// (mysql, sqlite) are not currently auto-registered and must be imported by the
// consumer. Consumers that have already registered the driver themselves are
// handled gracefully via a sql.Drivers() pre-check.
func ensureDriverRegistered(driver string) {
	driver = normalizeDriverName(driver)

	driverRegMu.Lock()
	defer driverRegMu.Unlock()

	if _, ok := registeredDrivers[driver]; ok {
		return
	}

	// Check whether the driver was already registered externally (e.g. via a
	// blank import in the consumer binary) before attempting to register it.
	// database/sql driver names are case-sensitive, so only an exact canonical
	// match can satisfy sql.Open after the config driver is normalized.
	for _, d := range sql.Drivers() {
		if d == driver {
			registeredDrivers[driver] = struct{}{}
			return
		}
	}

	if driver == defaultPostgreSQLDriver {
		sql.Register(defaultPostgreSQLDriver, stdlib.GetDefaultDriver())
		registeredDrivers[driver] = struct{}{}
	}
	// mysql and sqlite require imports not present in this module's dependencies.
	// Add cases here when those drivers are added to go.mod.
}

func normalizeDriverName(driver string) string {
	driver = strings.ToLower(strings.TrimSpace(driver))
	switch driver {
	case "postgres", "postgresql":
		return defaultPostgreSQLDriver
	default:
		return driver
	}
}

// Provider implements the Provider interface for SQL databases
type Provider struct {
	name   string
	config Config
	db     *sql.DB
	mapper types.Mapper
}

// NewProvider creates a new SQL provider
func NewProvider(ctx context.Context, name string, config Config) (*Provider, error) {
	// Normalize aliases so "postgres" and "postgresql" use the registered pgx
	// database/sql driver name.
	config.Driver = normalizeDriverName(config.Driver)

	// Register the database/sql driver for this provider's configured driver name
	// if it has not already been registered.
	ensureDriverRegistered(config.Driver)

	provider := &Provider{
		name:   name,
		config: config,
		mapper: NewMapper(),
	}

	// Build connection string based on driver
	connStr, err := provider.buildConnectionString()
	if err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeConfiguration,
			"failed to build connection string",
			err,
			map[string]interface{}{
				"provider": name,
				"driver":   config.Driver,
			},
		)
	}

	// Open database connection
	db, err := sql.Open(config.Driver, connStr)
	if err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeProvider,
			"failed to open database connection",
			err,
			map[string]interface{}{
				"provider": name,
				"driver":   config.Driver,
			},
		)
	}

	// Configure connection pool
	db.SetMaxOpenConns(config.MaxOpenConnections)
	db.SetMaxIdleConns(config.MaxIdleConnections)
	db.SetConnMaxLifetime(config.ConnMaxLifetime)
	db.SetConnMaxIdleTime(config.ConnMaxIdleTime)

	provider.db = db

	// Test the connection
	healthCtx, cancel := context.WithTimeout(ctx, config.HealthCheckTime)
	defer cancel()

	if err := provider.HealthCheck(healthCtx); err != nil {
		_ = db.Close()
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeProvider,
			"database connection test failed",
			err,
			map[string]interface{}{
				"provider": name,
				"driver":   config.Driver,
			},
		)
	}

	return provider, nil
}

// Name returns the provider instance name
func (p *Provider) Name() string {
	return p.name
}

// Type returns the provider type
func (p *Provider) Type() string {
	return "sql"
}

// ResolveEntity executes SQL query to resolve entity information
func (p *Provider) ResolveEntity(ctx context.Context, strategy types.MappingStrategy, params map[string]interface{}) (*types.RawResult, error) {
	// Validate that we have a SQL query
	if strategy.Query == "" {
		return nil, types.NewProviderError("no SQL query configured for strategy", map[string]interface{}{
			"provider": p.name,
			"strategy": strategy.Name,
		})
	}

	// Create query context with timeout
	queryCtx, cancel := context.WithTimeout(ctx, p.config.QueryTimeout)
	defer cancel()

	// Execute the query with parameters
	rows, err := p.db.QueryContext(queryCtx, strategy.Query, p.buildQueryArgs(params)...)
	if err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeProvider,
			"SQL query execution failed",
			err,
			map[string]interface{}{
				"provider": p.name,
				"strategy": strategy.Name,
				"query":    strategy.Query,
			},
		)
	}
	defer rows.Close()

	// Check for errors from query execution
	if err := rows.Err(); err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeProvider,
			"SQL query iteration failed",
			err,
			map[string]interface{}{
				"provider": p.name,
				"strategy": strategy.Name,
			},
		)
	}

	// Get column information
	columns, err := rows.Columns()
	if err != nil {
		return nil, types.WrapMultiStrategyError(
			types.ErrorTypeProvider,
			"failed to get column information",
			err,
			map[string]interface{}{
				"provider": p.name,
				"strategy": strategy.Name,
			},
		)
	}

	// Create result structure
	result := &types.RawResult{
		Data:     make(map[string]interface{}),
		Metadata: make(map[string]interface{}),
	}

	// Process results - expect single row for entity resolution
	if rows.Next() {
		// Create slice to hold column values
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		// Scan the row
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, types.WrapMultiStrategyError(
				types.ErrorTypeProvider,
				"failed to scan SQL result row",
				err,
				map[string]interface{}{
					"provider": p.name,
					"strategy": strategy.Name,
				},
			)
		}

		// Map columns to result data
		for i, column := range columns {
			result.Data[column] = p.convertSQLValue(values[i])
		}
	}

	// Add metadata
	result.Metadata["provider_type"] = "sql"
	result.Metadata["provider_name"] = p.name
	result.Metadata["query"] = strategy.Query
	result.Metadata["column_count"] = len(columns)
	result.Metadata["row_found"] = len(result.Data) > 0

	return result, nil
}

// HealthCheck verifies the SQL database is accessible
func (p *Provider) HealthCheck(ctx context.Context) error {
	// Use configured health check query or default
	query := p.config.HealthCheckQuery
	if query == "" {
		query = "SELECT 1"
	}

	// Create context with timeout
	healthCtx, cancel := context.WithTimeout(ctx, p.config.HealthCheckTime)
	defer cancel()

	// Execute health check query
	var result interface{}
	err := p.db.QueryRowContext(healthCtx, query).Scan(&result)
	if err != nil {
		return types.WrapMultiStrategyError(
			types.ErrorTypeHealth,
			"SQL health check query failed",
			err,
			map[string]interface{}{
				"provider": p.name,
				"query":    query,
				"driver":   p.config.Driver,
			},
		)
	}

	return nil
}

// GetMapper returns the provider's mapper implementation
func (p *Provider) GetMapper() types.Mapper {
	return p.mapper
}

// Close closes the database connection
func (p *Provider) Close() error {
	if p.db != nil {
		if err := p.db.Close(); err != nil {
			return types.WrapMultiStrategyError(
				types.ErrorTypeProvider,
				"failed to close database connection",
				err,
				map[string]interface{}{
					"provider": p.name,
					"driver":   p.config.Driver,
				},
			)
		}
	}
	return nil
}

// buildConnectionString creates a connection string based on the driver
func (p *Provider) buildConnectionString() (string, error) {
	switch normalizeDriverName(p.config.Driver) {
	case defaultPostgreSQLDriver:
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			p.config.Host, p.config.Port, p.config.Username, p.config.Password,
			p.config.Database, p.config.SSLMode), nil

	case "mysql":
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
			p.config.Username, p.config.Password, p.config.Host, p.config.Port,
			p.config.Database), nil

	case "sqlite", "sqlite3":
		return p.config.Database, nil

	default:
		return "", fmt.Errorf("unsupported database driver: %s", p.config.Driver)
	}
}

// buildQueryArgs extracts query arguments from parameters in order
func (p *Provider) buildQueryArgs(params map[string]interface{}) []interface{} {
	// For parameterized queries, we need to maintain parameter order
	// This is a simplified implementation - in practice, you might want
	// to parse the query to determine parameter order
	args := make([]interface{}, 0)

	// Add parameters in a consistent order (alphabetical by key)
	// This assumes the SQL query uses positional parameters ($1, $2, etc.)
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}

	// Sort keys for consistent parameter ordering
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}

	for _, key := range keys {
		args = append(args, params[key])
	}

	return args
}

// convertSQLValue converts SQL result values to appropriate Go types
func (p *Provider) convertSQLValue(value interface{}) interface{} {
	// Handle NULL values
	if value == nil {
		return nil
	}

	// Convert byte arrays to strings (common for text fields)
	if bytes, ok := value.([]byte); ok {
		return string(bytes)
	}

	// Return value as-is for other types
	return value
}
