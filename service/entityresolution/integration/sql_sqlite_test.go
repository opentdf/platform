package integration

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/opentdf/platform/service/entityresolution/integration/internal"
	sqlv2 "github.com/opentdf/platform/service/entityresolution/sql/v2"
	"github.com/opentdf/platform/service/logger"
	"go.opentelemetry.io/otel/trace/noop"

	_ "github.com/mattn/go-sqlite3"
)

// TestSQLiteEntityResolutionV2 runs all ERS tests against SQLite implementation using the generic contract test framework
func TestSQLiteEntityResolutionV2(t *testing.T) {
	contractSuite := internal.NewContractTestSuite()
	adapter := NewSQLiteTestAdapter()

	contractSuite.RunContractTestsWithAdapter(t, adapter)
}

// SQLiteTestAdapter implements ERSTestAdapter for SQLite ERS testing
type SQLiteTestAdapter struct {
	service *sqlv2.SQLEntityResolutionServiceV2
	db      *sql.DB
}

// NewSQLiteTestAdapter creates a new SQLite test adapter
func NewSQLiteTestAdapter() *SQLiteTestAdapter {
	return &SQLiteTestAdapter{}
}

// GetScopeName returns the scope name for SQLite ERS
func (a *SQLiteTestAdapter) GetScopeName() string {
	return "SQLite"
}

// SetupTestData injects test data into the SQLite database
func (a *SQLiteTestAdapter) SetupTestData(ctx context.Context, testDataSet *internal.ContractTestDataSet) error {
	// Create a fresh in-memory SQLite database for this service
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return fmt.Errorf("failed to open SQLite database: %w", err)
	}
	a.db = db

	// Create tables and load fixtures in the new database
	if err := a.createSQLiteTables(); err != nil {
		return fmt.Errorf("failed to create test tables: %w", err)
	}

	// Inject test data using the contract test dataset
	if err := a.injectTestData(ctx, testDataSet); err != nil {
		return fmt.Errorf("failed to inject test data: %w", err)
	}

	return nil
}

// CreateERSService creates and returns a configured SQLite ERS service
func (a *SQLiteTestAdapter) CreateERSService(ctx context.Context) (internal.ERSImplementation, error) {
	if a.db == nil {
		return nil, fmt.Errorf("database not initialized - call SetupTestData first")
	}

	sqlConfig := map[string]any{
		"driver": "sqlite3",
		"dsn":    ":memory:",
		"query_mapping": map[string]any{
			"username_query":  "SELECT username, email, display_name FROM users WHERE username = ?",
			"email_query":     "SELECT username, email, display_name FROM users WHERE email = ?",
			"client_id_query": "SELECT client_id, display_name, description FROM clients WHERE client_id = ?",
		},
		"column_mapping": map[string]any{
			"username":     "username",
			"email":        "email",
			"display_name": "display_name",
			"client_id":    "client_id",
		},
		"inferid": map[string]any{
			"from": map[string]any{
				"clientid": true,
				"email":    true,
				"username": true,
			},
		},
	}

	testLogger := logger.CreateTestLogger()
	service, _ := sqlv2.RegisterSQLERS(sqlConfig, testLogger)

	// Set a no-op tracer for testing to prevent nil pointer dereference
	service.Tracer = noop.NewTracerProvider().Tracer("test-sqlite-v2")

	// Replace the service's database with our prepared one
	if service.DB != nil {
		service.Close() // Close the service's default connection
	}
	service.DB = a.db // Use our prepared database

	a.service = service
	return service, nil
}

// TeardownTestData cleans up SQLite test data and resources
func (a *SQLiteTestAdapter) TeardownTestData(ctx context.Context) error {
	if a.service != nil {
		if err := a.service.Close(); err != nil {
			return fmt.Errorf("failed to close service: %w", err)
		}
		a.service = nil
	}
	if a.db != nil {
		if err := a.db.Close(); err != nil {
			return fmt.Errorf("failed to close database: %w", err)
		}
		a.db = nil
	}
	return nil
}

// createSQLiteTables creates test tables in the SQLite database
func (a *SQLiteTestAdapter) createSQLiteTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS clients (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			client_id TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			description TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL,
			description TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS user_groups (
			user_id INTEGER NOT NULL,
			group_id INTEGER NOT NULL,
			PRIMARY KEY (user_id, group_id),
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (group_id) REFERENCES groups(id)
		)`,
	}

	for _, query := range queries {
		if _, err := a.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute table creation query: %w", err)
		}
	}

	return nil
}

// injectTestData injects contract test data into the SQLite database
func (a *SQLiteTestAdapter) injectTestData(ctx context.Context, testDataSet *internal.ContractTestDataSet) error {
	// Insert users
	for _, user := range testDataSet.Users {
		if err := a.insertUser(ctx, user); err != nil {
			return fmt.Errorf("failed to insert user %s: %w", user.Username, err)
		}
	}

	// Insert clients
	for _, client := range testDataSet.Clients {
		if err := a.insertClient(ctx, client); err != nil {
			return fmt.Errorf("failed to insert client %s: %w", client.ClientID, err)
		}
	}

	return nil
}

// insertUser inserts a user into the SQLite database
func (a *SQLiteTestAdapter) insertUser(ctx context.Context, user internal.TestUser) error {
	query := `INSERT OR REPLACE INTO users (username, email, display_name, password_hash) VALUES (?, ?, ?, ?)`
	passwordHash := user.Password
	if passwordHash == "" {
		passwordHash = "test-password-hash"
	}
	_, err := a.db.ExecContext(ctx, query, user.Username, user.Email, user.DisplayName, passwordHash)
	return err
}

// insertClient inserts a client into the SQLite database
func (a *SQLiteTestAdapter) insertClient(ctx context.Context, client internal.TestClient) error {
	query := `INSERT OR REPLACE INTO clients (client_id, display_name, description) VALUES (?, ?, ?)`
	displayName := client.DisplayName
	if displayName == "" {
		displayName = client.ClientID
	}
	_, err := a.db.ExecContext(ctx, query, client.ClientID, displayName, client.Description)
	return err
}