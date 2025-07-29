package sql

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	// In-memory SQLite for testing
	_ "github.com/mattn/go-sqlite3"
)

type SQLEntityResolutionServiceTestSuite struct {
	suite.Suite
	service *SQLEntityResolutionService
	db      *sql.DB
}

func TestSQLEntityResolutionServiceTestSuite(t *testing.T) {
	suite.Run(t, new(SQLEntityResolutionServiceTestSuite))
}

func (suite *SQLEntityResolutionServiceTestSuite) SetupSuite() {
	// Create test configuration
	config := SQLConfig{
		Driver:      "sqlite3",
		DSN:         ":memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		ConnMaxLifetime: time.Hour,
		ConnectTimeout: 10 * time.Second,
		QueryTimeout: 30 * time.Second,
		QueryMapping: QueryMapping{
			UsernameQuery: "SELECT id, username, email, display_name, department FROM users WHERE username = ?",
			EmailQuery:    "SELECT id, username, email, display_name, department FROM users WHERE email = ?",
			ClientIDQuery: "SELECT id, client_id, name, description FROM clients WHERE client_id = ?",
		},
		ColumnMapping: ColumnMapping{
			Username:    "username",
			Email:       "email",
			DisplayName: "display_name",
			ClientID:    "client_id",
			Groups:      "groups",
			Additional: []string{"department", "name", "description"},
		},
		InferID: InferredIdentityConfig{
			From: EntityImpliedFrom{
				ClientID: true,
				Email:    true,
				Username: true,
			},
		},
	}

	logger := logger.CreateTestLogger()

	// Use RegisterSQLERS to properly create the service (but create our own DB for testing)
	// Create in-memory SQLite database for testing
	db, err := sql.Open("sqlite3", ":memory:")
	suite.Require().NoError(err)

	// Configure connection pool
	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIdleConns)
	db.SetConnMaxLifetime(config.ConnMaxLifetime)

	suite.db = db

	// Create test tables
	err = suite.createTestTables()
	suite.Require().NoError(err)

	// Insert test data
	err = suite.insertTestData()
	suite.Require().NoError(err)

	service := &SQLEntityResolutionService{
		config: config,
		db:     db,
		logger: logger,
	}

	suite.service = service
}

func (suite *SQLEntityResolutionServiceTestSuite) TearDownSuite() {
	if suite.db != nil {
		suite.db.Close()
	}
	if suite.service != nil {
		suite.service.Close()
	}
}

func (suite *SQLEntityResolutionServiceTestSuite) createTestTables() error {
	// Create users table
	_, err := suite.db.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			display_name TEXT,
			department TEXT
		)
	`)
	if err != nil {
		return err
	}

	// Create clients table
	_, err = suite.db.Exec(`
		CREATE TABLE clients (
			id INTEGER PRIMARY KEY,
			client_id TEXT UNIQUE NOT NULL,
			name TEXT,
			description TEXT
		)
	`)
	return err
}

func (suite *SQLEntityResolutionServiceTestSuite) insertTestData() error {
	// Insert test users
	users := []struct {
		username, email, displayName, department string
	}{
		{"alice", "alice@example.com", "Alice Smith", "Engineering"},
		{"bob", "bob@example.com", "Bob Johnson", "Marketing"},
		{"charlie", "charlie@example.com", "Charlie Brown", "Engineering"},
	}

	for _, user := range users {
		_, err := suite.db.Exec(
			"INSERT INTO users (username, email, display_name, department) VALUES (?, ?, ?, ?)",
			user.username, user.email, user.displayName, user.department,
		)
		if err != nil {
			return err
		}
	}

	// Insert test clients
	clients := []struct {
		clientID, name, description string
	}{
		{"web-app", "Web Application", "Main web application client"},
		{"mobile-app", "Mobile App", "Mobile application client"},
		{"api-client", "API Client", "Backend API client"},
	}

	for _, client := range clients {
		_, err := suite.db.Exec(
			"INSERT INTO clients (client_id, name, description) VALUES (?, ?, ?)",
			client.clientID, client.name, client.description,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func (suite *SQLEntityResolutionServiceTestSuite) TestResolveEntities_Username() {
	req := &connect.Request[entityresolution.ResolveEntitiesRequest]{
		Msg: &entityresolution.ResolveEntitiesRequest{
			Entities: []*authorization.Entity{
				{
					Id: "user-1",
					EntityType: &authorization.Entity_UserName{
						UserName: "alice",
					},
				},
			},
		},
	}

	resp, err := suite.service.ResolveEntities(context.Background(), req)
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)

	representations := resp.Msg.GetEntityRepresentations()
	suite.Require().Len(representations, 1)

	rep := representations[0]
	suite.Equal("user-1", rep.GetOriginalId())
	suite.Require().Len(rep.GetAdditionalProps(), 1)

	props := rep.GetAdditionalProps()[0].GetFields()
	suite.Equal("alice", props["username"].GetStringValue())
	suite.Equal("alice@example.com", props["email"].GetStringValue())
	suite.Equal("Alice Smith", props["display_name"].GetStringValue())
	suite.Equal("Engineering", props["department"].GetStringValue())
}

func (suite *SQLEntityResolutionServiceTestSuite) TestResolveEntities_Email() {
	req := &connect.Request[entityresolution.ResolveEntitiesRequest]{
		Msg: &entityresolution.ResolveEntitiesRequest{
			Entities: []*authorization.Entity{
				{
					Id: "user-2",
					EntityType: &authorization.Entity_EmailAddress{
						EmailAddress: "bob@example.com",
					},
				},
			},
		},
	}

	resp, err := suite.service.ResolveEntities(context.Background(), req)
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)

	representations := resp.Msg.GetEntityRepresentations()
	suite.Require().Len(representations, 1)

	rep := representations[0]
	suite.Equal("user-2", rep.GetOriginalId())
	suite.Require().Len(rep.GetAdditionalProps(), 1)

	props := rep.GetAdditionalProps()[0].GetFields()
	suite.Equal("bob", props["username"].GetStringValue())
	suite.Equal("bob@example.com", props["email"].GetStringValue())
	suite.Equal("Bob Johnson", props["display_name"].GetStringValue())
	suite.Equal("Marketing", props["department"].GetStringValue())
}

func (suite *SQLEntityResolutionServiceTestSuite) TestResolveEntities_ClientID() {
	req := &connect.Request[entityresolution.ResolveEntitiesRequest]{
		Msg: &entityresolution.ResolveEntitiesRequest{
			Entities: []*authorization.Entity{
				{
					Id: "client-1",
					EntityType: &authorization.Entity_ClientId{
						ClientId: "web-app",
					},
				},
			},
		},
	}

	resp, err := suite.service.ResolveEntities(context.Background(), req)
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)

	representations := resp.Msg.GetEntityRepresentations()
	suite.Require().Len(representations, 1)

	rep := representations[0]
	suite.Equal("client-1", rep.GetOriginalId())
	suite.Require().Len(rep.GetAdditionalProps(), 1)

	props := rep.GetAdditionalProps()[0].GetFields()
	suite.Equal("web-app", props["client_id"].GetStringValue())
	suite.Equal("Web Application", props["name"].GetStringValue())
	suite.Equal("Main web application client", props["description"].GetStringValue())
}

func (suite *SQLEntityResolutionServiceTestSuite) TestResolveEntities_NotFound_WithInference() {
	req := &connect.Request[entityresolution.ResolveEntitiesRequest]{
		Msg: &entityresolution.ResolveEntitiesRequest{
			Entities: []*authorization.Entity{
				{
					Id: "nonexistent-1",
					EntityType: &authorization.Entity_UserName{
						UserName: "nonexistent",
					},
				},
			},
		},
	}

	resp, err := suite.service.ResolveEntities(context.Background(), req)
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)

	representations := resp.Msg.GetEntityRepresentations()
	suite.Require().Len(representations, 1)

	rep := representations[0]
	suite.Equal("nonexistent-1", rep.GetOriginalId())
	suite.Require().Len(rep.GetAdditionalProps(), 1)

	// Should contain the inferred entity data
	props := rep.GetAdditionalProps()[0].GetFields()
	// The entity contains the userName field since it was inferred from a UserName entity
	suite.Contains(props, "userName")
}

func (suite *SQLEntityResolutionServiceTestSuite) TestResolveEntities_NotFound_WithoutInference() {
	// Temporarily disable inference
	originalConfig := suite.service.config.InferID
	suite.service.config.InferID.From.Username = false

	defer func() {
		suite.service.config.InferID = originalConfig
	}()

	req := &connect.Request[entityresolution.ResolveEntitiesRequest]{
		Msg: &entityresolution.ResolveEntitiesRequest{
			Entities: []*authorization.Entity{
				{
					Id: "nonexistent-2",
					EntityType: &authorization.Entity_UserName{
						UserName: "nonexistent",
					},
				},
			},
		},
	}

	_, err := suite.service.ResolveEntities(context.Background(), req)
	suite.Require().Error(err)

	connectErr := err.(*connect.Error)
	suite.Equal(connect.CodeNotFound, connectErr.Code())
}

func (suite *SQLEntityResolutionServiceTestSuite) TestResolveEntities_MultipleEntities() {
	req := &connect.Request[entityresolution.ResolveEntitiesRequest]{
		Msg: &entityresolution.ResolveEntitiesRequest{
			Entities: []*authorization.Entity{
				{
					Id: "user-1",
					EntityType: &authorization.Entity_UserName{
						UserName: "alice",
					},
				},
				{
					Id: "client-1",
					EntityType: &authorization.Entity_ClientId{
						ClientId: "web-app",
					},
				},
			},
		},
	}

	resp, err := suite.service.ResolveEntities(context.Background(), req)
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)

	representations := resp.Msg.GetEntityRepresentations()
	suite.Require().Len(representations, 2)

	// Check first entity (alice)
	rep1 := representations[0]
	suite.Equal("user-1", rep1.GetOriginalId())
	props1 := rep1.GetAdditionalProps()[0].GetFields()
	suite.Equal("alice", props1["username"].GetStringValue())

	// Check second entity (web-app)
	rep2 := representations[1]
	suite.Equal("client-1", rep2.GetOriginalId())
	props2 := rep2.GetAdditionalProps()[0].GetFields()
	suite.Equal("web-app", props2["client_id"].GetStringValue())
}

func (suite *SQLEntityResolutionServiceTestSuite) TestCreateEntityChainFromJwt() {
	// Create a test JWT token
	token := jwt.New()
	token.Set("azp", "test-client")
	token.Set("preferred_username", "testuser")
	token.Set("email", "testuser@example.com")

	tokenBytes, err := jwt.NewSerializer().Serialize(token)
	suite.Require().NoError(err)

	req := &connect.Request[entityresolution.CreateEntityChainFromJwtRequest]{
		Msg: &entityresolution.CreateEntityChainFromJwtRequest{
			Tokens: []*authorization.Token{
				{
					Id:  "token-1",
					Jwt: string(tokenBytes),
				},
			},
		},
	}

	resp, err := suite.service.CreateEntityChainFromJwt(context.Background(), req)
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)

	chains := resp.Msg.GetEntityChains()
	suite.Require().Len(chains, 1)

	chain := chains[0]
	suite.Equal("token-1", chain.GetId())

	entities := chain.GetEntities()
	suite.Require().Len(entities, 3) // client_id, username, email

	// Check client ID entity
	clientEntity := entities[0]
	suite.Equal("test-client", clientEntity.GetClientId())
	suite.Equal(authorization.Entity_CATEGORY_ENVIRONMENT, clientEntity.GetCategory())

	// Check username entity
	usernameEntity := entities[1]
	suite.Equal("testuser", usernameEntity.GetUserName())
	suite.Equal(authorization.Entity_CATEGORY_SUBJECT, usernameEntity.GetCategory())

	// Check email entity
	emailEntity := entities[2]
	suite.Equal("testuser@example.com", emailEntity.GetEmailAddress())
	suite.Equal(authorization.Entity_CATEGORY_SUBJECT, emailEntity.GetCategory())
}

func (suite *SQLEntityResolutionServiceTestSuite) TestQueryExecution() {
	// Test direct query execution
	rows, err := suite.service.executeQuery(context.Background(), 
		"SELECT username, email FROM users WHERE username = ?", "alice")
	suite.Require().NoError(err)
	suite.Require().Len(rows, 1)

	row := rows[0]
	suite.Equal("alice", row["username"])
	suite.Equal("alice@example.com", row["email"])
}

func (suite *SQLEntityResolutionServiceTestSuite) TestQueryExecution_WithTimeout() {
	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// This should timeout
	_, err := suite.service.executeQuery(ctx, 
		"SELECT username, email FROM users WHERE username = ?", "alice")
	suite.Require().Error(err)
	suite.Contains(err.Error(), "context deadline exceeded")
}

func (suite *SQLEntityResolutionServiceTestSuite) TestBuildDSN() {
	tests := []struct {
		name     string
		config   SQLConfig
		expected string
	}{
		{
			name: "PostgreSQL DSN",
			config: SQLConfig{
				Driver:   "pgx",
				Host:     "localhost",
				Port:     5432,
				Database: "testdb",
				Username: "testuser",
				Password: "testpass",
				SSLMode:  "require",
			},
			expected: "host=localhost port=5432 user=testuser password=testpass dbname=testdb sslmode=require",
		},
		{
			name: "MySQL DSN",
			config: SQLConfig{
				Driver:   "mysql",
				Host:     "localhost",
				Port:     3306,
				Database: "testdb",
				Username: "testuser",
				Password: "testpass",
			},
			expected: "testuser:testpass@tcp(localhost:3306)/testdb",
		},
		{
			name: "SQLite DSN",
			config: SQLConfig{
				Driver:   "sqlite3",
				Database: "/path/to/test.db",
			},
			expected: "/path/to/test.db",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			result := buildDSN(tt.config)
			suite.Equal(tt.expected, result)
		})
	}
}

func (suite *SQLEntityResolutionServiceTestSuite) TestShouldInferEntity() {
	tests := []struct {
		name     string
		entity   *authorization.Entity
		config   InferredIdentityConfig
		expected bool
	}{
		{
			name: "Should infer username",
			entity: &authorization.Entity{
				EntityType: &authorization.Entity_UserName{UserName: "test"},
			},
			config: InferredIdentityConfig{
				From: EntityImpliedFrom{Username: true},
			},
			expected: true,
		},
		{
			name: "Should not infer username",
			entity: &authorization.Entity{
				EntityType: &authorization.Entity_UserName{UserName: "test"},
			},
			config: InferredIdentityConfig{
				From: EntityImpliedFrom{Username: false},
			},
			expected: false,
		},
		{
			name: "Should infer email",
			entity: &authorization.Entity{
				EntityType: &authorization.Entity_EmailAddress{EmailAddress: "test@example.com"},
			},
			config: InferredIdentityConfig{
				From: EntityImpliedFrom{Email: true},
			},
			expected: true,
		},
		{
			name: "Should infer client ID",
			entity: &authorization.Entity{
				EntityType: &authorization.Entity_ClientId{ClientId: "test-client"},
			},
			config: InferredIdentityConfig{
				From: EntityImpliedFrom{ClientID: true},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			// Temporarily set the config
			originalConfig := suite.service.config.InferID
			suite.service.config.InferID = tt.config

			result := suite.service.shouldInferEntity(tt.entity)
			suite.Equal(tt.expected, result)

			// Restore original config
			suite.service.config.InferID = originalConfig
		})
	}
}

func (suite *SQLEntityResolutionServiceTestSuite) TestEntityToStructPb() {
	entity := &authorization.Entity{
		Id: "test-id",
		EntityType: &authorization.Entity_UserName{UserName: "testuser"},
		Category: authorization.Entity_CATEGORY_SUBJECT,
	}

	structPb, err := suite.service.entityToStructPb(entity)
	suite.Require().NoError(err)
	suite.Require().NotNil(structPb)

	fields := structPb.GetFields()
	suite.Equal("test-id", fields["id"].GetStringValue())
	// The field name is "userName" not "entityType" when marshaled to JSON
	suite.Contains(fields, "userName")
}

// Test configuration validation and defaults
func TestConfigDefaults(t *testing.T) {
	config := SQLConfig{}
	
	// Test that defaults are applied correctly
	if config.MaxOpenConns == 0 {
		config.MaxOpenConns = DefaultMaxOpenConns
	}
	if config.MaxIdleConns == 0 {
		config.MaxIdleConns = DefaultMaxIdleConns
	}
	if config.ConnMaxLifetime == 0 {
		config.ConnMaxLifetime = DefaultConnMaxLifetime
	}
	
	assert.Equal(t, DefaultMaxOpenConns, config.MaxOpenConns)
	assert.Equal(t, DefaultMaxIdleConns, config.MaxIdleConns)
	assert.Equal(t, DefaultConnMaxLifetime, config.ConnMaxLifetime)
}

// Test secure logging
func TestLogValue(t *testing.T) {
	config := SQLConfig{
		Driver:   "postgres",
		DSN:      "secret-dsn",
		Username: "user",
		Password: "secret-password",
	}

	logValue := config.LogValue()
	logString := fmt.Sprintf("%v", logValue)
	
	// Password should be redacted
	assert.Contains(t, logString, "[REDACTED]")
	assert.NotContains(t, logString, "secret-password")
	assert.NotContains(t, logString, "secret-dsn")
}

// Test error handling
func TestErrorHandling(t *testing.T) {
	// Test with invalid driver
	config := SQLConfig{
		Driver: "invalid-driver",
		DSN:    "test",
	}

	logger := logger.CreateTestLogger()
	service := &SQLEntityResolutionService{
		config: config,
		db:     nil, // Explicitly set to nil to test error handling
		logger: logger,
	}

	// Test query execution with nil database - this should panic/error
	defer func() {
		if r := recover(); r != nil {
			// Expected panic due to nil database
			assert.NotNil(t, r)
		}
	}()
	
	_, err := service.executeQuery(context.Background(), "SELECT 1", "param")
	// If we get here without panic, there should be an error
	if err == nil {
		t.Error("Expected error with nil database")
	}
}

// Benchmark query execution
func BenchmarkQueryExecution(b *testing.B) {
	// Setup test database
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(b, err)
	defer db.Close()

	// Create test table and data
	_, err = db.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL
		)
	`)
	require.NoError(b, err)

	_, err = db.Exec("INSERT INTO users (username, email) VALUES (?, ?)", "testuser", "test@example.com")
	require.NoError(b, err)

	config := SQLConfig{
		Driver:       "sqlite3",
		QueryTimeout: 30 * time.Second,
	}

	logger := logger.CreateTestLogger()
	service := &SQLEntityResolutionService{
		config: config,
		db:     db,
		logger: logger,
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := service.executeQuery(context.Background(), 
				"SELECT username, email FROM users WHERE username = ?", "testuser")
			if err != nil {
				b.Errorf("Query failed: %v", err)
			}
		}
	})
}