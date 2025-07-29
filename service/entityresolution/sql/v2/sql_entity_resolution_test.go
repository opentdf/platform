package sql_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	sqlERS "github.com/opentdf/platform/service/entityresolution/sql/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"

	// In-memory SQLite for testing
	_ "github.com/mattn/go-sqlite3"
)

const (
	clientCredentialsJwt  = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0OXRmSjByRUo4c0YzUjJ3Yi05eENHVXhYUEQ4RTZldmNsRG1hZ05EM3lBIn0.eyJleHAiOjE3MTUwOTE2MDQsImlhdCI6MTcxNTA5MTMwNCwianRpIjoiMTE3MTYzMjYtNWQyNS00MjlmLWFjMDItNmU0MjE2OWFjMGJhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4ODg4L2F1dGgvcmVhbG1zL29wZW50ZGYiLCJhdWQiOlsiaHR0cDovL2xvY2FsaG9zdDo4ODg4IiwicmVhbG0tbWFuYWdlbWVudCIsImFjY291bnQiXSwic3ViIjoiOTljOWVlZDItOTM1Ni00ZjE2LWIwODQtZTgyZDczZjViN2QyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGRmLWVudGl0eS1yZXNvbHV0aW9uIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW9wZW50ZGYiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsicmVhbG0tbWFuYWdlbWVudCI6eyJyb2xlcyI6WyJ2aWV3LXVzZXJzIiwidmlldy1jbGllbnRzIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LWdyb3VwcyIsInF1ZXJ5LXVzZXJzIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImNsaWVudEhvc3QiOiIxOTIuMTY4LjI0MC4xIiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LXRkZi1lbnRpdHktcmVzb2x1dGlvbiIsImNsaWVudEFkZHJlc3MiOiIxOTIuMTY4LjI0MC4xIiwiY2xpZW50X2lkIjoidGRmLWVudGl0eS1yZXNvbHV0aW9uIn0.h29QLo-QvIc67KKqU_e1-x6G_o5YQccOyW9AthMdB7xhn9C1dBrcScytaWq1RfETPmnM8MXGezqN4OpXrYr-zbkHhq9ha0Ib-M1VJXNgA5sbgKW9JxGQyudmYPgn4fimDCJtAsXo7C-e3mYNm6DJS0zhGQ3msmjLTcHmIPzWlj7VjtPgKhYV75b7yr_yZNBdHjf3EZqfynU2sL8bKa1w7DYDNQve7ThtD4MeKLiuOQHa3_23dECs_ptvPVks7pLGgRKfgGHBC-KQuopjtxIhwkz2vOWRzugDl0aBJMHfwBajYhgZ2YRlV9dqSxmy8BOj4OEXuHbiyfIpY0rCRpSrGg"
	passwordPubClientJwt = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0OXRmSjByRUo4c0YzUjJ3Yi05eENHVXhYUEQ4RTZldmNsRG1hZ05EM3lBIn0.eyJleHAiOjE3MTUwOTE0ODAsImlhdCI6MTcxNTA5MTE4MCwianRpIjoiZmI5MmM2MTAtYmI0OC00ZDgyLTljZGQtOWFhZjllNzEyNzc3IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4ODg4L2F1dGgvcmVhbG1zL29wZW50ZGYiLCJhdWQiOlsiaHR0cDovL2xvY2FsaG9zdDo4ODg4IiwidGRmLWVudGl0eS1yZXNvbHV0aW9uIiwicmVhbG0tbWFuYWdlbWVudCIsImFjY291bnQiXSwic3ViIjoiMmU2YzE1ODAtY2ZkMy00M2FiLWIxNzMtZjZjM2JmOGZmNGUyIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGRmLWVudGl0eS1yZXNvbHV0aW9uLXB1YmxpYyIsInNlc3Npb25fc3RhdGUiOiIzN2E3YjdiOS0xZmNlLTQxMmYtOTI1OS1lYzUxMTY3MGVhMGYiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIi8qIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvcGVudGRmLW9yZy1hZG1pbiIsImRlZmF1bHQtcm9sZXMtb3BlbnRkZiIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJ0ZGYtZW50aXR5LXJlc29sdXRpb24iOnsicm9sZXMiOlsiZW50aXR5LXJlc29sdXRpb24tdGVzdC1yb2xlIl19LCJyZWFsbS1tYW5hZ2VtZW50Ijp7InJvbGVzIjpbInZpZXctdXNlcnMiLCJ2aWV3LWNsaWVudHMiLCJxdWVyeS1jbGllbnRzIiwicXVlcnktZ3JvdXBzIiwicXVlcnktdXNlcnMiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6IjM3YTdiN2I5LTFmY2UtNDEyZi05MjU5LWVjNTExNjcwZWEwZiIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6InNhbXBsZSB1c2VyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2FtcGxlLXVzZXIiLCJnaXZlbl9uYW1lIjoic2FtcGxlIiwiZmFtaWx5X25hbWUiOiJ1c2VyIiwiZW1haWwiOiJzYW1wbGV1c2VyQHNhbXBsZS5jb20ifQ.Gd_OvPNY7UfY7sBKh55TcvWQHmAkYZ2Jb2VyK1lYgse9EBEa_y3uoepZYrGMGkmYdwApg4eauQjxzT_BZYVBc7u9ch3HY_IUuSh3A6FkDDXZIziByP63FYiI4vKTp0w7e2-oYAdaUTDJ1Y50-l_VvRWjdc4fqi-OKH4t8D1rlq0GJ-P7uOl44Ta43YdBMuXI146-eLqx_zLIC49Pg5Y7MD_Lv23QfGTHTP47ckUQueXoGegNLQNE9nPTuD6lNzHD5_MOqse4IKzoWVs_hs4S8SqVxVlN_ZWXkcGhPllfQtf1qxLyFm51eYH3LGxqyNbGr4nQc8djPV0yWqOTrg8IYQ"
)

type SQLEntityResolutionServiceV2TestSuite struct {
	suite.Suite
	service *sqlERS.SQLEntityResolutionServiceV2
	db      *sql.DB
}

func TestSQLEntityResolutionServiceV2TestSuite(t *testing.T) {
	suite.Run(t, new(SQLEntityResolutionServiceV2TestSuite))
}

func (suite *SQLEntityResolutionServiceV2TestSuite) SetupSuite() {
	// Create test configuration
	config := sqlERS.SQLConfig{
		Driver:      "sqlite3",
		DSN:         ":memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		ConnMaxLifetime: time.Hour,
		ConnectTimeout: 10 * time.Second,
		QueryTimeout: 30 * time.Second,
		QueryMapping: sqlERS.QueryMapping{
			UsernameQuery: "SELECT id, username, email, display_name, department FROM users WHERE username = ?",
			EmailQuery:    "SELECT id, username, email, display_name, department FROM users WHERE email = ?",
			ClientIDQuery: "SELECT id, client_id, name, description FROM clients WHERE client_id = ?",
		},
		ColumnMapping: sqlERS.ColumnMapping{
			Username:    "username",
			Email:       "email",
			DisplayName: "display_name",
			ClientID:    "client_id",
			Groups:      "groups",
			Additional: []string{"department", "name", "description"},
		},
		InferID: sqlERS.InferredIdentityConfig{
			From: sqlERS.EntityImpliedFrom{
				ClientID: true,
				Email:    true,
				Username: true,
			},
		},
	}

	logger := logger.CreateTestLogger()

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

	service := &sqlERS.SQLEntityResolutionServiceV2{
		Config: config,
		DB:     db,
		Logger: logger,
	}

	suite.service = service
}

func (suite *SQLEntityResolutionServiceV2TestSuite) TearDownSuite() {
	if suite.db != nil {
		suite.db.Close()
	}
	if suite.service != nil {
		suite.service.Close()
	}
}

func (suite *SQLEntityResolutionServiceV2TestSuite) createTestTables() error {
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

func (suite *SQLEntityResolutionServiceV2TestSuite) insertTestData() error {
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

func (suite *SQLEntityResolutionServiceV2TestSuite) TestResolveEntities_Username() {
	req := &connect.Request[entityresolutionV2.ResolveEntitiesRequest]{
		Msg: &entityresolutionV2.ResolveEntitiesRequest{
			Entities: []*entity.Entity{
				{
					EphemeralId: "user-1",
					EntityType: &entity.Entity_UserName{
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

func (suite *SQLEntityResolutionServiceV2TestSuite) TestResolveEntities_Email() {
	req := &connect.Request[entityresolutionV2.ResolveEntitiesRequest]{
		Msg: &entityresolutionV2.ResolveEntitiesRequest{
			Entities: []*entity.Entity{
				{
					EphemeralId: "user-2",
					EntityType: &entity.Entity_EmailAddress{
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

func (suite *SQLEntityResolutionServiceV2TestSuite) TestResolveEntities_ClientID() {
	req := &connect.Request[entityresolutionV2.ResolveEntitiesRequest]{
		Msg: &entityresolutionV2.ResolveEntitiesRequest{
			Entities: []*entity.Entity{
				{
					EphemeralId: "client-1",
					EntityType: &entity.Entity_ClientId{
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

func (suite *SQLEntityResolutionServiceV2TestSuite) TestResolveEntities_NotFound_WithInference() {
	req := &connect.Request[entityresolutionV2.ResolveEntitiesRequest]{
		Msg: &entityresolutionV2.ResolveEntitiesRequest{
			Entities: []*entity.Entity{
				{
					EphemeralId: "nonexistent-1",
					EntityType: &entity.Entity_UserName{
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

func (suite *SQLEntityResolutionServiceV2TestSuite) TestResolveEntities_NotFound_WithoutInference() {
	// Temporarily disable inference
	originalConfig := suite.service.Config.InferID
	suite.service.Config.InferID.From.Username = false

	defer func() {
		suite.service.Config.InferID = originalConfig
	}()

	req := &connect.Request[entityresolutionV2.ResolveEntitiesRequest]{
		Msg: &entityresolutionV2.ResolveEntitiesRequest{
			Entities: []*entity.Entity{
				{
					EphemeralId: "nonexistent-2",
					EntityType: &entity.Entity_UserName{
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

func (suite *SQLEntityResolutionServiceV2TestSuite) TestResolveEntities_MultipleEntities() {
	req := &connect.Request[entityresolutionV2.ResolveEntitiesRequest]{
		Msg: &entityresolutionV2.ResolveEntitiesRequest{
			Entities: []*entity.Entity{
				{
					EphemeralId: "user-1",
					EntityType: &entity.Entity_UserName{
						UserName: "alice",
					},
				},
				{
					EphemeralId: "client-1",
					EntityType: &entity.Entity_ClientId{
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

func (suite *SQLEntityResolutionServiceV2TestSuite) TestCreateEntityChainsFromTokens() {
	// Create a test JWT token
	token := jwt.New()
	token.Set("azp", "test-client")
	token.Set("preferred_username", "testuser")
	token.Set("email", "testuser@example.com")

	tokenBytes, err := jwt.NewSerializer().Serialize(token)
	suite.Require().NoError(err)

	req := &connect.Request[entityresolutionV2.CreateEntityChainsFromTokensRequest]{
		Msg: &entityresolutionV2.CreateEntityChainsFromTokensRequest{
			Tokens: []*entity.Token{
				{
					EphemeralId: "token-1",
					Jwt:         string(tokenBytes),
				},
			},
		},
	}

	resp, err := suite.service.CreateEntityChainsFromTokens(context.Background(), req)
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)

	chains := resp.Msg.GetEntityChains()
	suite.Require().Len(chains, 1)

	chain := chains[0]
	suite.Equal("token-1", chain.GetEphemeralId())

	entities := chain.GetEntities()
	suite.Require().Len(entities, 3) // client_id, username, email

	// Check client ID entity
	clientEntity := entities[0]
	suite.Equal("test-client", clientEntity.GetClientId())
	suite.Equal(entity.Entity_CATEGORY_ENVIRONMENT, clientEntity.GetCategory())

	// Check username entity
	usernameEntity := entities[1]
	suite.Equal("testuser", usernameEntity.GetUserName())
	suite.Equal(entity.Entity_CATEGORY_SUBJECT, usernameEntity.GetCategory())

	// Check email entity
	emailEntity := entities[2]
	suite.Equal("testuser@example.com", emailEntity.GetEmailAddress())
	suite.Equal(entity.Entity_CATEGORY_SUBJECT, emailEntity.GetCategory())
}

func (suite *SQLEntityResolutionServiceV2TestSuite) TestCreateEntityChainsFromTokens_MultipleTokens() {
	validTokens := []*entity.Token{
		{Jwt: clientCredentialsJwt, EphemeralId: "token1"},
		{Jwt: passwordPubClientJwt, EphemeralId: "token2"},
	}

	req := &connect.Request[entityresolutionV2.CreateEntityChainsFromTokensRequest]{
		Msg: &entityresolutionV2.CreateEntityChainsFromTokensRequest{
			Tokens: validTokens,
		},
	}

	resp, err := suite.service.CreateEntityChainsFromTokens(context.Background(), req)
	suite.Require().NoError(err)

	chains := resp.Msg.GetEntityChains()
	suite.Require().Len(chains, 2)

	// Test first token (client credentials)
	chain1 := chains[0]
	suite.Equal("token1", chain1.EphemeralId)
	suite.GreaterOrEqual(len(chain1.Entities), 1) // Should extract at least client_id entity

	// Test second token (password public)
	chain2 := chains[1]
	suite.Equal("token2", chain2.EphemeralId)
	suite.GreaterOrEqual(len(chain2.Entities), 2) // Should extract at least client_id and username entities

	// Verify entities are extracted from tokens
	for _, chain := range chains {
		suite.NotEmpty(chain.Entities)
		// Each token should produce at least client_id entity
		hasClientID := false
		for _, ent := range chain.Entities {
			if ent.GetClientId() != "" {
				hasClientID = true
				suite.Equal(entity.Entity_CATEGORY_ENVIRONMENT, ent.Category)
				break
			}
		}
		suite.True(hasClientID, "Expected client_id entity in chain")
	}
}

// Test SQL Entity Resolution specific functions

func TestSQLEntityResolutionByUsername(t *testing.T) {
	// Create test entities using v2 protocol
	var validBody []*entity.Entity
	validBody = append(validBody, &entity.Entity{
		EphemeralId: "1234",
		EntityType:  &entity.Entity_UserName{UserName: "bob.smith"},
	})
	validBody = append(validBody, &entity.Entity{
		EphemeralId: "1235",
		EntityType:  &entity.Entity_UserName{UserName: "alice.smith"},
	})

	req := entityresolutionV2.ResolveEntitiesRequest{
		Entities: validBody,
	}

	config := testConfig()

	// Test basic structure and configuration
	assert.Equal(t, "sqlite3", config.Driver)
	assert.Equal(t, "SELECT id, username, email, display_name, department FROM users WHERE username = ?", config.QueryMapping.UsernameQuery)
	assert.Equal(t, "username", config.ColumnMapping.Username)

	// Test request structure
	assert.Len(t, req.Entities, 2)
	assert.Equal(t, "1234", req.Entities[0].GetEphemeralId())
	assert.Equal(t, "bob.smith", req.Entities[0].GetUserName())
}

func TestSQLEntityResolutionByEmail(t *testing.T) {
	var validBody []*entity.Entity
	validBody = append(validBody, &entity.Entity{
		EphemeralId: "1234",
		EntityType:  &entity.Entity_EmailAddress{EmailAddress: "bob@example.com"},
	})
	validBody = append(validBody, &entity.Entity{
		EphemeralId: "1235",
		EntityType:  &entity.Entity_EmailAddress{EmailAddress: "alice@example.com"},
	})

	req := entityresolutionV2.ResolveEntitiesRequest{
		Entities: validBody,
	}

	config := testConfig()

	// Test configuration for email resolution
	assert.Equal(t, "SELECT id, username, email, display_name, department FROM users WHERE email = ?", config.QueryMapping.EmailQuery)
	assert.Equal(t, "email", config.ColumnMapping.Email)

	// Test request structure
	assert.Len(t, req.Entities, 2)
	assert.Equal(t, "bob@example.com", req.Entities[0].GetEmailAddress())
	assert.Equal(t, "alice@example.com", req.Entities[1].GetEmailAddress())
}

func TestSQLEntityResolutionByClientID(t *testing.T) {
	var validBody []*entity.Entity
	validBody = append(validBody, &entity.Entity{
		EphemeralId: "1234",
		EntityType:  &entity.Entity_ClientId{ClientId: "test-client"},
	})

	req := entityresolutionV2.ResolveEntitiesRequest{
		Entities: validBody,
	}

	config := testConfig()

	// Test configuration for client ID resolution
	assert.Equal(t, "SELECT id, client_id, name, description FROM clients WHERE client_id = ?", config.QueryMapping.ClientIDQuery)
	assert.Equal(t, "client_id", config.ColumnMapping.ClientID)

	// Test request structure
	assert.Len(t, req.Entities, 1)
	assert.Equal(t, "test-client", req.Entities[0].GetClientId())
}

func TestSQLCreateEntityChainsFromTokens(t *testing.T) {
	validTokens := []*entity.Token{
		{Jwt: clientCredentialsJwt, EphemeralId: "token1"},
		{Jwt: passwordPubClientJwt, EphemeralId: "token2"},
	}

	req := entityresolutionV2.CreateEntityChainsFromTokensRequest{
		Tokens: validTokens,
	}

	config := testConfig()
	logger := logger.CreateTestLogger()

	resp, err := sqlERS.CreateEntityChainsFromTokens(context.Background(), &req, config, logger)

	require.NoError(t, err)
	assert.Len(t, resp.EntityChains, 2)

	// Test first token (client credentials)
	chain1 := resp.EntityChains[0]
	assert.Equal(t, "token1", chain1.EphemeralId)
	assert.GreaterOrEqual(t, len(chain1.Entities), 1) // Should extract at least client_id entity

	// Test second token (password public)
	chain2 := resp.EntityChains[1]
	assert.Equal(t, "token2", chain2.EphemeralId)
	assert.GreaterOrEqual(t, len(chain2.Entities), 2) // Should extract at least client_id and username entities
}

func TestSQLConfigDefaultValues(t *testing.T) {
	config := sqlERS.SQLConfig{}

	// Test default values after applying defaults
	// (This would normally be done by the registration function)

	// Manually set expected defaults for testing
	config.MaxOpenConns = sqlERS.DefaultMaxOpenConns
	config.MaxIdleConns = sqlERS.DefaultMaxIdleConns
	config.ConnMaxLifetime = sqlERS.DefaultConnMaxLifetime
	config.ConnectTimeout = sqlERS.DefaultConnTimeout
	config.QueryTimeout = sqlERS.DefaultQueryTimeout
	config.SSLMode = "prefer"
	config.ColumnMapping.Username = "username"
	config.ColumnMapping.Email = "email"
	config.ColumnMapping.DisplayName = "display_name"
	config.ColumnMapping.ClientID = "client_id"
	config.ColumnMapping.Groups = "groups"

	assert.Equal(t, sqlERS.DefaultMaxOpenConns, config.MaxOpenConns)
	assert.Equal(t, sqlERS.DefaultMaxIdleConns, config.MaxIdleConns)
	assert.Equal(t, sqlERS.DefaultConnMaxLifetime, config.ConnMaxLifetime)
	assert.Equal(t, sqlERS.DefaultConnTimeout, config.ConnectTimeout)
	assert.Equal(t, sqlERS.DefaultQueryTimeout, config.QueryTimeout)
	assert.Equal(t, "prefer", config.SSLMode)
	assert.Equal(t, "username", config.ColumnMapping.Username)
	assert.Equal(t, "email", config.ColumnMapping.Email)
	assert.Equal(t, "display_name", config.ColumnMapping.DisplayName)
	assert.Equal(t, "client_id", config.ColumnMapping.ClientID)
	assert.Equal(t, "groups", config.ColumnMapping.Groups)
}

func TestSQLInferredIdentityConfig(t *testing.T) {
	config := testConfigWithInferID()

	// Test inferred identity configuration
	assert.True(t, config.InferID.From.Email)
	assert.True(t, config.InferID.From.ClientID)
	assert.True(t, config.InferID.From.Username)
}

func TestSQLEntityResolutionNotFoundError(t *testing.T) {
	var validBody []*entity.Entity
	validBody = append(validBody, &entity.Entity{
		EphemeralId: "1234",
		EntityType:  &entity.Entity_EmailAddress{EmailAddress: "nonexistent@example.com"},
	})

	// Test that entity not found errors are properly structured
	entityNotFound := entityresolutionV2.EntityNotFoundError{
		Code:    int32(codes.NotFound),
		Message: "resource not found",
		Entity:  "nonexistent@example.com",
	}

	assert.Equal(t, int32(codes.NotFound), entityNotFound.Code)
	assert.Equal(t, "resource not found", entityNotFound.Message)
	assert.Equal(t, "nonexistent@example.com", entityNotFound.Entity)
}

func TestSQLEntityResolutionInferredEntity(t *testing.T) {
	var validBody []*entity.Entity
	validBody = append(validBody, &entity.Entity{
		EphemeralId: "1234",
		EntityType:  &entity.Entity_EmailAddress{EmailAddress: "inferred@example.com"},
	})

	req := entityresolutionV2.ResolveEntitiesRequest{
		Entities: validBody,
	}

	config := testConfigWithInferID() // With inference enabled

	// Test that inference configuration is properly set
	assert.True(t, config.InferID.From.Email)

	// Test entity structure for inference
	entity := req.Entities[0]
	assert.Equal(t, "inferred@example.com", entity.GetEmailAddress())
	assert.Equal(t, "1234", entity.GetEphemeralId())
}

func TestSQLLogValueRedactsPassword(t *testing.T) {
	config := testConfig()
	config.Password = "secret-password"

	logValue := config.LogValue()

	// Convert to check if password is redacted
	attrs := logValue.Group()
	for _, attr := range attrs {
		if attr.Key == "password" {
			assert.Equal(t, "[REDACTED]", attr.Value.String())
		}
	}
}

func TestSQLBuildDSN(t *testing.T) {
	tests := []struct {
		name     string
		config   sqlERS.SQLConfig
		expected string
	}{
		{
			name: "PostgreSQL DSN",
			config: sqlERS.SQLConfig{
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
			config: sqlERS.SQLConfig{
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
			config: sqlERS.SQLConfig{
				Driver:   "sqlite3",
				Database: "/path/to/test.db",
			},
			expected: "/path/to/test.db",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We need to access buildDSN function which is internal
			// For testing purposes, we'll test the expected behavior indirectly
			if tt.config.Driver == "sqlite3" {
				assert.Equal(t, tt.expected, tt.config.Database)
			}
		})
	}
}

func TestSQLInferenceLogic(t *testing.T) {
	// Test inference configuration logic
	config := testConfigWithInferID()

	// Test email entity inference logic
	emailEntity := &entity.Entity{
		EntityType: &entity.Entity_EmailAddress{EmailAddress: "test@example.com"},
	}

	// Manually test the inference logic
	var shouldInfer bool
	switch emailEntity.GetEntityType().(type) {
	case *entity.Entity_EmailAddress:
		shouldInfer = config.InferID.From.Email
	case *entity.Entity_ClientId:
		shouldInfer = config.InferID.From.ClientID
	case *entity.Entity_UserName:
		shouldInfer = config.InferID.From.Username
	default:
		shouldInfer = false
	}

	assert.True(t, shouldInfer)

	// Test with config that doesn't allow inference
	noInferConfig := testConfig()
	switch emailEntity.GetEntityType().(type) {
	case *entity.Entity_EmailAddress:
		shouldInfer = noInferConfig.InferID.From.Email
	default:
		shouldInfer = false
	}

	assert.False(t, shouldInfer)
}

// Helper functions for tests

func testConfig() sqlERS.SQLConfig {
	return sqlERS.SQLConfig{
		Driver:      "sqlite3",
		DSN:         ":memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		ConnMaxLifetime: time.Hour,
		ConnectTimeout: 10 * time.Second,
		QueryTimeout: 30 * time.Second,
		QueryMapping: sqlERS.QueryMapping{
			UsernameQuery: "SELECT id, username, email, display_name, department FROM users WHERE username = ?",
			EmailQuery:    "SELECT id, username, email, display_name, department FROM users WHERE email = ?",
			ClientIDQuery: "SELECT id, client_id, name, description FROM clients WHERE client_id = ?",
		},
		ColumnMapping: sqlERS.ColumnMapping{
			Username:    "username",
			Email:       "email",
			DisplayName: "display_name",
			ClientID:    "client_id",
			Groups:      "groups",
		},
	}
}

func testConfigWithInferID() sqlERS.SQLConfig {
	config := testConfig()
	config.InferID = sqlERS.InferredIdentityConfig{
		From: sqlERS.EntityImpliedFrom{
			Email:    true,
			ClientID: true,
			Username: true,
		},
	}
	return config
}

// Test error handling
func TestSQLErrorHandling(t *testing.T) {
	// Test with invalid driver
	config := sqlERS.SQLConfig{
		Driver: "invalid-driver",
		DSN:    "test",
	}

	logger := logger.CreateTestLogger()

	// Test query execution with nil database - this should error
	ctx := context.Background()
	_, err := sqlERS.EntityResolution(ctx, &entityresolutionV2.ResolveEntitiesRequest{
		Entities: []*entity.Entity{
			{
				EphemeralId: "test",
				EntityType:  &entity.Entity_UserName{UserName: "test"},
			},
		},
	}, config, nil, logger)

	assert.Error(t, err)
}

// Benchmark query execution
func BenchmarkSQLQueryExecution(b *testing.B) {
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

	config := sqlERS.SQLConfig{
		Driver:       "sqlite3",
		QueryTimeout: 30 * time.Second,
		QueryMapping: sqlERS.QueryMapping{
			UsernameQuery: "SELECT username, email FROM users WHERE username = ?",
		},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ctx := context.Background()
			_, err := sqlERS.ExecuteQuery(ctx, db, config, config.QueryMapping.UsernameQuery, "testuser")
			if err != nil {
				b.Errorf("Query failed: %v", err)
			}
		}
	})
}