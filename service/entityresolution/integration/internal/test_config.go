package internal

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// TestConfig provides environment-aware configuration for integration tests
type TestConfig struct {
	// Service Endpoints
	KeycloakURL    string
	KeycloakPort   int
	PostgresHost   string
	PostgresPort   int
	LDAPHost       string
	LDAPPort       int

	// Authentication
	AdminUser     string
	AdminPassword string
	Realm         string
	ClientID      string
	ClientSecret  string

	// Test Behavior
	ContainerStartupTimeout time.Duration
	ContainerRunTimeout     time.Duration
	TestDataVariation      bool // Enable varied test data generation
	JWTValidityDuration    time.Duration
	
	// Test Data
	EmailDomains   []string
	TestUserCount  int
	TestClientCount int
}

// GetTestConfig returns environment-aware test configuration with sensible defaults
func GetTestConfig() *TestConfig {
	return &TestConfig{
		// Service Endpoints - configurable via environment
		KeycloakURL:    getEnvString("TEST_KEYCLOAK_URL", "http://localhost:8080"),
		KeycloakPort:   getEnvInt("TEST_KEYCLOAK_PORT", 8080),
		PostgresHost:   getEnvString("TEST_POSTGRES_HOST", "localhost"),
		PostgresPort:   getEnvInt("TEST_POSTGRES_PORT", 5432),
		LDAPHost:       getEnvString("TEST_LDAP_HOST", "localhost"),
		LDAPPort:       getEnvInt("TEST_LDAP_PORT", 389),

		// Authentication - configurable for different test environments
		AdminUser:     getEnvString("TEST_ADMIN_USER", "admin"),
		AdminPassword: getEnvString("TEST_ADMIN_PASSWORD", "admin_password"),
		Realm:         getEnvString("TEST_REALM", "test-realm"),
		ClientID:      getEnvString("TEST_CLIENT_ID", "test-client"),
		ClientSecret:  getEnvString("TEST_CLIENT_SECRET", "test-secret"),

		// Test Behavior - tunable for different environments
		ContainerStartupTimeout: getEnvDuration("TEST_CONTAINER_STARTUP_TIMEOUT", 2*time.Minute),
		ContainerRunTimeout:     getEnvDuration("TEST_CONTAINER_RUN_TIMEOUT", 4*time.Minute),
		TestDataVariation:      getEnvBool("TEST_DATA_VARIATION", true),
		JWTValidityDuration:    getEnvDuration("TEST_JWT_VALIDITY", time.Hour),

		// Test Data - configurable scale and variety
		EmailDomains:    getEnvStringSlice("TEST_EMAIL_DOMAINS", []string{"opentdf.test", "example.com", "company.local"}),
		TestUserCount:   getEnvInt("TEST_USER_COUNT", 3),
		TestClientCount: getEnvInt("TEST_CLIENT_COUNT", 3),
	}
}

// Helper functions for environment variable parsing
func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func getEnvStringSlice(key string, defaultValue []string) []string {
	// For simplicity, return default. Could be enhanced to parse comma-separated values
	if value := os.Getenv(key); value != "" {
		// Basic implementation - could be enhanced for CSV parsing
		return []string{value}
	}
	return defaultValue
}

// KeycloakConfig returns Keycloak-specific configuration
func (tc *TestConfig) KeycloakConfig() map[string]interface{} {
	return map[string]interface{}{
		"url":           tc.KeycloakURL,
		"realm":         tc.Realm,
		"clientid":      tc.ClientID,
		"clientsecret":  tc.ClientSecret,
		"admin_user":    tc.AdminUser,
		"admin_pass":    tc.AdminPassword,
	}
}

// PostgresConnectionString returns a connection string for PostgreSQL
func (tc *TestConfig) PostgresConnectionString(dbname, username, password string) string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		tc.PostgresHost, tc.PostgresPort, username, password, dbname)
}