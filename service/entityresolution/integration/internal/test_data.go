package internal

import (
	"context"
)

// TestUser represents a test user entity
type TestUser struct {
	Username    string
	Email       string
	DisplayName string
	Password    string
	Groups      []string
	DN          string
}

// TestClient represents a test client entity
type TestClient struct {
	ClientID    string
	DisplayName string
	Description string
	DN          string
}

// TestGroup represents a test group entity
type TestGroup struct {
	Name        string
	DisplayName string
	Description string
	Members     []string
	DN          string
}

// Test data available to all adapters for consistent contract testing
var (
	// Test users for all ERS implementations
	TestUsers = []TestUser{
		{
			Username:    "alice",
			Email:       "alice@opentdf.test",
			DisplayName: "Alice Smith",
			Password:    "password123",
			Groups:      []string{"users", "admins"},
			DN:          "uid=alice,ou=users,dc=opentdf,dc=test",
		},
		{
			Username:    "bob",
			Email:       "bob@opentdf.test",
			DisplayName: "Bob Johnson",
			Password:    "password456",
			Groups:      []string{"users"},
			DN:          "uid=bob,ou=users,dc=opentdf,dc=test",
		},
		{
			Username:    "charlie",
			Email:       "charlie@opentdf.test",
			DisplayName: "Charlie Brown",
			Password:    "password789",
			Groups:      []string{"users", "managers"},
			DN:          "uid=charlie,ou=users,dc=opentdf,dc=test",
		},
	}

	// Test clients for all ERS implementations
	TestClients = []TestClient{
		{
			ClientID:    "test-client-1",
			DisplayName: "Test Client 1",
			Description: "First test client",
			DN:          "cn=test-client-1,ou=clients,dc=opentdf,dc=test",
		},
		{
			ClientID:    "test-client-2",
			DisplayName: "Test Client 2",
			Description: "Second test client",
			DN:          "cn=test-client-2,ou=clients,dc=opentdf,dc=test",
		},
		{
			ClientID:    "opentdf-sdk",
			DisplayName: "OpenTDF SDK",
			Description: "OpenTDF SDK client",
			DN:          "cn=opentdf-sdk,ou=clients,dc=opentdf,dc=test",
		},
	}

	// Test groups for all ERS implementations
	TestGroups = []TestGroup{
		{
			Name:        "users",
			DisplayName: "All Users",
			Description: "Basic user group",
			Members:     []string{"alice", "bob", "charlie"},
			DN:          "cn=users,ou=groups,dc=opentdf,dc=test",
		},
		{
			Name:        "admins",
			DisplayName: "Administrators",
			Description: "Administrative users",
			Members:     []string{"alice"},
			DN:          "cn=admins,ou=groups,dc=opentdf,dc=test",
		},
		{
			Name:        "managers",
			DisplayName: "Managers",
			Description: "Management users",
			Members:     []string{"charlie"},
			DN:          "cn=managers,ou=groups,dc=opentdf,dc=test",
		},
	}
)

// ContractTestDataSet defines the standard test data that all ERS implementations should support
type ContractTestDataSet struct {
	Users   []TestUser
	Clients []TestClient
}

// NewContractTestDataSet creates the standard test data set for contract testing
func NewContractTestDataSet() *ContractTestDataSet {
	return &ContractTestDataSet{
		Users: []TestUser{
			{
				Username:    "alice",
				Email:       "alice@opentdf.test",
				DisplayName: "Alice Smith",
				Password:    "password123", // Add password for Keycloak
				Groups:      []string{"users", "admins"},
			},
			{
				Username:    "bob",
				Email:       "bob@opentdf.test",
				DisplayName: "Bob Johnson",
				Password:    "password456", // Add password for Keycloak
				Groups:      []string{"users"},
			},
			{
				Username:    "charlie",
				Email:       "charlie@opentdf.test",
				DisplayName: "Charlie Brown",
				Password:    "password789", // Add password for Keycloak
				Groups:      []string{"users", "developers"},
			},
		},
		Clients: []TestClient{
			{
				ClientID:    "test-client-1",
				Description: "First test client",
			},
			{
				ClientID:    "test-client-2",
				Description: "Second test client",
			},
		},
	}
}

// TestDataInjector interface defines methods for injecting test data into different backends
type TestDataInjector interface {
	InjectTestData(ctx context.Context, dataSet *ContractTestDataSet) error
	CleanupTestData(ctx context.Context) error
	ValidateTestData(ctx context.Context, dataSet *ContractTestDataSet) error
}

// MockTestDataInjector provides a no-op implementation for testing
type MockTestDataInjector struct {
	logger any
}

// NewMockTestDataInjector creates a new mock test data injector
func NewMockTestDataInjector(logger any) *MockTestDataInjector {
	return &MockTestDataInjector{
		logger: logger,
	}
}

// InjectTestData is a no-op for the mock injector
func (m *MockTestDataInjector) InjectTestData(ctx context.Context, dataSet *ContractTestDataSet) error {
	return nil
}

// CleanupTestData is a no-op for the mock injector
func (m *MockTestDataInjector) CleanupTestData(ctx context.Context) error {
	return nil
}

// ValidateTestData is a no-op for the mock injector
func (m *MockTestDataInjector) ValidateTestData(ctx context.Context, dataSet *ContractTestDataSet) error {
	return nil
}