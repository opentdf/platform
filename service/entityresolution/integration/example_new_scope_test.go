package integration

import (
	"context"
	"fmt"
	"testing"

	"github.com/opentdf/platform/service/entityresolution/integration/internal"
)

// ExampleNewScopeTestAdapter demonstrates how easy it is to add a new ERS scope
// This shows the pattern that each new scope (Redis, MongoDB, etc.) would follow
type ExampleNewScopeTestAdapter struct {
	// Add fields for your specific implementation
	// e.g., redisClient *redis.Client, mongoClient *mongo.Client, etc.
}

// NewExampleNewScopeTestAdapter creates a new example scope test adapter
func NewExampleNewScopeTestAdapter() *ExampleNewScopeTestAdapter {
	return &ExampleNewScopeTestAdapter{}
}

// GetScopeName returns the scope name for this ERS implementation
func (a *ExampleNewScopeTestAdapter) GetScopeName() string {
	return "ExampleNewScope"
}

// SetupTestData injects test data into the backend data store
func (a *ExampleNewScopeTestAdapter) SetupTestData(ctx context.Context, testDataSet *internal.ContractTestDataSet) error {
	// Step 1: Take the generic testDataSet and transform it for your backend
	// Example for Redis:
	//   - Convert testDataSet.Users to Redis hash entries
	//   - Store user:alice -> {username: alice, email: alice@test.com, ...}
	//   - Set up key patterns for different entity types
	//
	// Example for MongoDB:
	//   - Insert testDataSet.Users into a "users" collection  
	//   - Insert testDataSet.Clients into a "clients" collection
	//   - Create indexes for efficient lookups
	//
	// Example for File-based:
	//   - Write testDataSet to JSON/CSV files
	//   - Set up file paths and formats expected by the ERS
	
	fmt.Printf("Setting up test data for %s with %d users and %d clients\n", 
		a.GetScopeName(), len(testDataSet.Users), len(testDataSet.Clients))
	
	// TODO: Replace with actual data setup for your backend
	return nil
}

// CreateERSService creates and returns a configured ERS service instance
func (a *ExampleNewScopeTestAdapter) CreateERSService(ctx context.Context) (internal.ERSImplementation, error) {
	// Step 2: Create and configure your ERS service implementation
	// This would typically involve:
	//   - Creating connection to your backend (Redis, MongoDB, etc.)
	//   - Configuring query patterns and field mappings
	//   - Setting up any required authentication or connection pooling
	//   - Returning an implementation of internal.ERSImplementation
	
	// For demonstration, we'll return an error since this is just an example
	return nil, fmt.Errorf("ExampleNewScope is a demonstration - implement your actual ERS service here")
}

// TeardownTestData cleans up test data and resources
func (a *ExampleNewScopeTestAdapter) TeardownTestData(ctx context.Context) error {
	// Step 3: Clean up any resources created during testing
	// Examples:
	//   - Delete Redis keys that were created
	//   - Drop MongoDB collections or delete test documents
	//   - Remove temporary files
	//   - Close database connections
	
	fmt.Printf("Cleaning up test data for %s\n", a.GetScopeName())
	
	// TODO: Replace with actual cleanup for your backend
	return nil
}

// TestExampleNewScopeContractCompliance demonstrates running contract tests against the new scope
// This test is skipped by default since it's just an example
func TestExampleNewScopeContractCompliance(t *testing.T) {
	t.Skip("This is an example demonstrating the pattern - implement your actual ERS first")
	
	// Once you implement the actual ERS service, running contract tests is this simple:
	contractSuite := internal.NewContractTestSuite()
	adapter := NewExampleNewScopeTestAdapter()
	
	contractSuite.RunContractTestsWithAdapter(t, adapter)
	
	// That's it! The adapter handles:
	// 1. Setting up test data in your specific backend format
	// 2. Creating your ERS service instance
	// 3. Running all standard contract tests
	// 4. Cleaning up resources when done
	//
	// This ensures every ERS implementation meets the same behavioral contracts
	// regardless of the underlying data store technology.
}

/*
Adding a new ERS scope is now a 3-step process:

1. **Implement the ERSTestAdapter interface** (this file):
   - SetupTestData: Transform generic test data for your backend
   - CreateERSService: Create and configure your ERS implementation  
   - TeardownTestData: Clean up test resources

2. **Implement your actual ERS service** (separate file):
   - Create your service that implements internal.ERSImplementation
   - Handle ResolveEntities and CreateEntityChainsFromTokens methods
   - Connect to your backend (Redis, MongoDB, file system, etc.)

3. **Add contract test** (one line):
   - contractSuite.RunContractTestsWithAdapter(t, yourAdapter)

The contract testing framework automatically validates that your implementation:
- ✅ Resolves entities correctly by username, email, and client ID
- ✅ Handles multiple entity resolution in a single request  
- ✅ Supports entity inference when data is not found
- ✅ Processes mixed entity types consistently
- ✅ Returns properly formatted entity representations
- ✅ Handles JWT token parsing for entity chain creation

Benefits of this pattern:
- 🚀 **Easy to add new scopes** - just implement the 4 interface methods
- 🔄 **Consistent testing** - all implementations tested against same contracts
- 🧪 **Isolated test data** - each test gets fresh, isolated data
- 🛠️ **Flexible backends** - works with any data store technology
- 📊 **Contract compliance** - ensures behavioral consistency across all ERS implementations
*/