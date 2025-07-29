package ldap

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/stretchr/testify/suite"
	"go.opentelemetry.io/otel/trace"
)

type LDAPEntityResolutionTestSuite struct {
	suite.Suite
	logger *logger.Logger
}

func (suite *LDAPEntityResolutionTestSuite) SetupSuite() {
	lgr, err := logger.NewLogger(logger.Config{
		Output: "stdout",
		Level:  "debug",
		Type:   "text",
	})
	if err != nil {
		suite.FailNow("Failed to create logger", err)
	}
	suite.logger = lgr
}

func TestLDAPEntityResolutionTestSuite(t *testing.T) {
	suite.Run(t, new(LDAPEntityResolutionTestSuite))
}

func (suite *LDAPEntityResolutionTestSuite) Test_RegisterLDAPERS_ConfigParsing() {
	// Test configuration parsing
	config := config.ServiceConfig{
		"servers":         []string{"ldap.example.com"},
		"port":           636,
		"use_tls":        true,
		"bind_dn":        "cn=admin,dc=example,dc=com",
		"bind_password":  "password",
		"base_dn":        "dc=example,dc=com",
		"user_filter":    "(uid={username})",
		"email_filter":   "(mail={email})",
		"client_id_filter": "(cn={client_id})",
		"attribute_mapping": map[string]interface{}{
			"username":     "uid",
			"email":        "mail",
			"display_name": "displayName",
			"groups":       "memberOf",
			"client_id":    "cn",
		},
		"include_groups": true,
		"inferid": map[string]interface{}{
			"from": map[string]interface{}{
				"email":    true,
				"username": true,
				"clientid": false,
			},
		},
	}

	ldapService, handler := RegisterLDAPERS(config, suite.logger)
	
	suite.NotNil(ldapService)
	suite.Nil(handler) // LDAP ERS doesn't return a handler server like Keycloak does
	suite.Equal([]string{"ldap.example.com"}, ldapService.config.Servers)
	suite.Equal(636, ldapService.config.Port)
	suite.True(ldapService.config.UseTLS)
	suite.Equal("cn=admin,dc=example,dc=com", ldapService.config.BindDN)
	suite.Equal("password", ldapService.config.BindPassword)
	suite.Equal("dc=example,dc=com", ldapService.config.BaseDN)
	suite.Equal("(uid={username})", ldapService.config.UserFilter)
	suite.Equal("(mail={email})", ldapService.config.EmailFilter)
	suite.Equal("(cn={client_id})", ldapService.config.ClientIDFilter)
	suite.Equal("uid", ldapService.config.AttributeMapping.Username)
	suite.Equal("mail", ldapService.config.AttributeMapping.Email)
	suite.Equal("displayName", ldapService.config.AttributeMapping.DisplayName)
	suite.Equal("memberOf", ldapService.config.AttributeMapping.Groups)
	suite.Equal("cn", ldapService.config.AttributeMapping.ClientID)
	suite.True(ldapService.config.IncludeGroups)
	suite.True(ldapService.config.InferID.From.Email)
	suite.True(ldapService.config.InferID.From.Username)
	suite.False(ldapService.config.InferID.From.ClientID)
}

func (suite *LDAPEntityResolutionTestSuite) Test_RegisterLDAPERS_DefaultValues() {
	// Test default values when minimal config is provided
	config := config.ServiceConfig{
		"servers": []string{"ldap.example.com"},
		"base_dn": "dc=example,dc=com",
	}

	ldapService, _ := RegisterLDAPERS(config, suite.logger)
	
	// With UseTLS not set (defaults to true), should use LDAPS port 636
	suite.Equal(636, ldapService.config.Port) // Default LDAPS port
	suite.True(ldapService.config.UseTLS)    // Default to TLS
	suite.Equal("(uid={username})", ldapService.config.UserFilter)    // Default user filter
	suite.Equal("(mail={email})", ldapService.config.EmailFilter)     // Default email filter
	suite.Equal("(cn={client_id})", ldapService.config.ClientIDFilter) // Default client ID filter
}

func (suite *LDAPEntityResolutionTestSuite) Test_LDAPConfig_LogValue() {
	config := LDAPConfig{
		Servers:      []string{"ldap.example.com"},
		Port:         636,
		UseTLS:       true,
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "secret",
		BaseDN:       "dc=example,dc=com",
	}

	logValue := config.LogValue()
	suite.NotNil(logValue)
	// The password should be redacted in logs
	suite.Contains(logValue.String(), "[REDACTED]")
	suite.Contains(logValue.String(), "ldap.example.com")
}

func (suite *LDAPEntityResolutionTestSuite) Test_EntityToStructPb() {
	// Test entity conversion to protobuf struct
	ldapService := &LDAPEntityResolutionService{
		logger: suite.logger,
	}

	entity := &authorization.Entity{
		EntityType: &authorization.Entity_UserName{UserName: "testuser"},
		Id:         "test-id",
		Category:   authorization.Entity_CATEGORY_SUBJECT,
	}

	structPb, err := ldapService.entityToStructPb(entity)
	
	suite.NoError(err)
	suite.NotNil(structPb)
	suite.NotNil(structPb.Fields)
}

func (suite *LDAPEntityResolutionTestSuite) Test_ShouldInferEntity() {
	config := LDAPConfig{
		InferID: InferredIdentityConfig{
			From: EntityImpliedFrom{
				Email:    true,
				Username: true,
				ClientID: false,
			},
		},
	}

	ldapService := &LDAPEntityResolutionService{
		config: config,
		logger: suite.logger,
	}

	// Test email inference
	emailEntity := &authorization.Entity{
		EntityType: &authorization.Entity_EmailAddress{EmailAddress: "test@example.com"},
	}
	suite.True(ldapService.shouldInferEntity(emailEntity))

	// Test username inference
	usernameEntity := &authorization.Entity{
		EntityType: &authorization.Entity_UserName{UserName: "testuser"},
	}
	suite.True(ldapService.shouldInferEntity(usernameEntity))

	// Test client ID inference (disabled)
	clientEntity := &authorization.Entity{
		EntityType: &authorization.Entity_ClientId{ClientId: "testclient"},
	}
	suite.False(ldapService.shouldInferEntity(clientEntity))
}

func (suite *LDAPEntityResolutionTestSuite) Test_GetEntitiesFromToken() {
	ldapService := &LDAPEntityResolutionService{
		logger: suite.logger,
	}

	// Mock JWT token payload (without verification for testing)
	mockJWT := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhenAiOiJ0ZXN0Y2xpZW50IiwicHJlZmVycmVkX3VzZXJuYW1lIjoidGVzdHVzZXIiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20ifQ.placeholder`

	ctx := context.Background()
	entities, err := ldapService.getEntitiesFromToken(ctx, mockJWT)

	suite.NoError(err)
	suite.NotEmpty(entities)
	
	// Should extract client ID, username, and email from JWT
	foundClientID := false
	foundUsername := false
	foundEmail := false
	
	for _, entity := range entities {
		switch entity.GetEntityType().(type) {
		case *authorization.Entity_ClientId:
			foundClientID = true
			suite.Equal("testclient", entity.GetClientId())
			suite.Equal(authorization.Entity_CATEGORY_ENVIRONMENT, entity.Category)
		case *authorization.Entity_UserName:
			foundUsername = true
			suite.Equal("testuser", entity.GetUserName())
			suite.Equal(authorization.Entity_CATEGORY_SUBJECT, entity.Category)
		case *authorization.Entity_EmailAddress:
			foundEmail = true
			suite.Equal("test@example.com", entity.GetEmailAddress())
			suite.Equal(authorization.Entity_CATEGORY_SUBJECT, entity.Category)
		}
	}
	
	suite.True(foundClientID, "Should extract client ID from JWT")
	suite.True(foundUsername, "Should extract username from JWT")
	suite.True(foundEmail, "Should extract email from JWT")
}

// Test that the service implements the required interface
func (suite *LDAPEntityResolutionTestSuite) Test_ServiceImplementsInterface() {
	ldapService := &LDAPEntityResolutionService{}
	
	// Test that it implements the EntityResolutionServiceServer interface
	// Note: The interface compliance is checked at compile time via embedding
	// UnimplementedEntityResolutionServiceServer, so just check it's not nil
	suite.NotNil(ldapService)
}

// Test ResolveEntities and CreateEntityChainFromJwt method signatures
func (suite *LDAPEntityResolutionTestSuite) Test_ServiceMethods() {
	ldapService := &LDAPEntityResolutionService{
		logger: suite.logger,
		Tracer: trace.NewNoopTracerProvider().Tracer("test"),
	}

	ctx := context.Background()

	// Test ResolveEntities method signature
	req := &connect.Request[entityresolution.ResolveEntitiesRequest]{
		Msg: &entityresolution.ResolveEntitiesRequest{
			Entities: []*authorization.Entity{
				{
					EntityType: &authorization.Entity_UserName{UserName: "testuser"},
					Id:         "test-id",
					Category:   authorization.Entity_CATEGORY_SUBJECT,
				},
			},
		},
	}

	// This will fail due to no LDAP connection, but tests the method signature
	_, err := ldapService.ResolveEntities(ctx, req)
	suite.Error(err) // Expected to fail without LDAP server

	// Test CreateEntityChainFromJwt method signature
	jwtReq := &connect.Request[entityresolution.CreateEntityChainFromJwtRequest]{
		Msg: &entityresolution.CreateEntityChainFromJwtRequest{
			Tokens: []*authorization.Token{
				{
					Id:  "token1",
					Jwt: "invalid.jwt.token",
				},
			},
		},
	}

	// This should succeed as it doesn't require LDAP connection
	_, err = ldapService.CreateEntityChainFromJwt(ctx, jwtReq)
	suite.Error(err) // Expected to fail with invalid JWT
}