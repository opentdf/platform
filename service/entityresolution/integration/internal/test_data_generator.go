package internal

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/opentdf/platform/protocol/go/entity"
)

// TestDataGenerator provides flexible test data generation
type TestDataGenerator struct {
	config *TestConfig
	rand   *rand.Rand
}

// NewTestDataGenerator creates a new test data generator
func NewTestDataGenerator(config *TestConfig) *TestDataGenerator {
	return &TestDataGenerator{
		config: config,
		rand:   rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// TestDataScenario defines a test scenario with specific characteristics
type TestDataScenario struct {
	Name         string
	UserCount    int
	ClientCount  int
	EmailDomains []string
	
	// JWT claim variations
	IncludeClientID   bool
	IncludeEmail      bool 
	IncludeUsername   bool
	IncludeEmptyUsers bool // Test edge case with missing claims
	
	// Strategy testing
	StrategyTypes []string // Which strategies should be triggered
}

// GetStandardScenarios returns common test scenarios
func (g *TestDataGenerator) GetStandardScenarios() []TestDataScenario {
	return []TestDataScenario{
		{
			Name:            "Basic Multi-User",
			UserCount:       3,
			ClientCount:     2,
			EmailDomains:    g.config.EmailDomains,
			IncludeClientID: true,
			IncludeEmail:    true,
			IncludeUsername: true,
			StrategyTypes:   []string{"jwt_claims", "client_jwt", "azp_jwt"},
		},
		{
			Name:            "Edge Cases",
			UserCount:       2,
			ClientCount:     1,
			EmailDomains:    []string{"opentdf.test"},
			IncludeClientID:   false, // Test missing client_id
			IncludeEmail:      true,
			IncludeUsername:   true,
			IncludeEmptyUsers: true, // Test fallback strategies
			StrategyTypes:     []string{"fallback_jwt"},
		},
		{
			Name:            "Email Variations",
			UserCount:       4,
			ClientCount:     3,
			EmailDomains:    []string{"company.com", "partner.org", "external.net"},
			IncludeClientID: true,
			IncludeEmail:    true,
			IncludeUsername: true,
			StrategyTypes:   []string{"jwt_claims", "client_jwt"},
		},
		{
			Name:            "Client Focus",
			UserCount:       1,
			ClientCount:     5,
			EmailDomains:    []string{"opentdf.test"},
			IncludeClientID: true,
			IncludeEmail:    false, // Test client-only scenarios
			IncludeUsername: false,
			StrategyTypes:   []string{"client_jwt", "azp_jwt"},
		},
	}
}

// GenerateTestUsers creates varied test users based on scenario
func (g *TestDataGenerator) GenerateTestUsers(scenario TestDataScenario) []TestUser {
	users := make([]TestUser, 0, scenario.UserCount)
	
	baseUsers := []string{"alice", "bob", "charlie", "diana", "eve", "frank", "grace", "henry"}
	
	for i := 0; i < scenario.UserCount; i++ {
		var username string
		if i < len(baseUsers) {
			username = baseUsers[i]
		} else {
			username = fmt.Sprintf("user%d", i+1)
		}
		
		// Add variation when enabled
		if g.config.TestDataVariation && i > 0 {
			username = fmt.Sprintf("%s_%d", username, g.rand.Intn(100))
		}
		
		// Select domain
		domainIndex := i % len(scenario.EmailDomains)
		email := fmt.Sprintf("%s@%s", username, scenario.EmailDomains[domainIndex])
		
		// Handle empty user case for edge testing
		if scenario.IncludeEmptyUsers && i == scenario.UserCount-1 {
			username = ""
			email = ""
		}
		
		users = append(users, TestUser{
			Username:    username,
			Email:       email,
			DisplayName: formatDisplayName(username),
			Password:    generateTestPassword(username, i),
			Groups:      generateGroups(username, i),
			DN:          generateDN(username, "users"),
		})
	}
	
	return users
}

// GenerateTestClients creates varied test clients based on scenario
func (g *TestDataGenerator) GenerateTestClients(scenario TestDataScenario) []TestClient {
	clients := make([]TestClient, 0, scenario.ClientCount)
	
	baseClients := []string{"web-app", "mobile-app", "api-client", "admin-client", "external-client"}
	
	for i := 0; i < scenario.ClientCount; i++ {
		var clientID string
		if i < len(baseClients) {
			clientID = baseClients[i]
		} else {
			clientID = fmt.Sprintf("client-%d", i+1)
		}
		
		// Add variation when enabled
		if g.config.TestDataVariation && i > 0 {
			clientID = fmt.Sprintf("%s-%d", clientID, g.rand.Intn(1000))
		}
		
		clients = append(clients, TestClient{
			ClientID:    clientID,
			DisplayName: formatDisplayName(clientID),
			Description: fmt.Sprintf("Test client %s for scenario %s", clientID, scenario.Name),
			DN:          generateDN(clientID, "clients"),
		})
	}
	
	return clients
}

// GenerateTestTokens creates tokens that will trigger specific strategies
func (g *TestDataGenerator) GenerateTestTokens(scenario TestDataScenario, users []TestUser, clients []TestClient) []*entity.Token {
	tokens := make([]*entity.Token, 0)
	
	// Create user tokens
	for i, user := range users {
		if user.Username == "" && user.Email == "" {
			continue // Skip empty users for token generation
		}
		
		clientID := ""
		if scenario.IncludeClientID && len(clients) > 0 {
			clientID = clients[i%len(clients)].ClientID
		}
		
		username := user.Username
		if !scenario.IncludeUsername {
			username = ""
		}
		
		email := user.Email
		if !scenario.IncludeEmail {
			email = ""
		}
		
		ephemeralID := fmt.Sprintf("token-%s-%d", scenario.Name, i)
		token := CreateTestToken(ephemeralID, clientID, username, email)
		tokens = append(tokens, token)
	}
	
	// Create client-only tokens if scenario focuses on clients
	if len(scenario.StrategyTypes) > 0 {
		for _, strategyType := range scenario.StrategyTypes {
			if strategyType == "client_jwt" || strategyType == "azp_jwt" {
				for i, client := range clients {
					ephemeralID := fmt.Sprintf("client-token-%s-%d", scenario.Name, i)
					token := CreateTestToken(ephemeralID, client.ClientID, "", "")
					tokens = append(tokens, token)
				}
				break // Only add once
			}
		}
	}
	
	return tokens
}

// Helper functions
func formatDisplayName(identifier string) string {
	if identifier == "" {
		return "Anonymous User"
	}
	// Convert "alice" to "Alice" or "web-app" to "Web App"
	if len(identifier) == 0 {
		return identifier
	}
	
	result := ""
	capitalize := true
	for _, char := range identifier {
		if char == '-' || char == '_' {
			result += " "
			capitalize = true
		} else if capitalize {
			result += string(char - 32) // Simple uppercase
			capitalize = false
		} else {
			result += string(char)
		}
	}
	return result
}

func generateTestPassword(username string, index int) string {
	if username == "" {
		return ""
	}
	return fmt.Sprintf("%s_password_%d", username, index+1)
}

func generateGroups(username string, index int) []string {
	if username == "" {
		return []string{}
	}
	
	groups := []string{"users"}
	
	// Add role-based groups based on index
	switch index % 3 {
	case 0:
		groups = append(groups, "admins")
	case 1:
		groups = append(groups, "managers")
	case 2:
		groups = append(groups, "developers")
	}
	
	return groups
}

func generateDN(identifier, ouType string) string {
	if identifier == "" {
		return ""
	}
	return fmt.Sprintf("cn=%s,ou=%s,dc=opentdf,dc=test", identifier, ouType)
}

// CreateVariedTestDataSet creates a test data set based on scenario
func (g *TestDataGenerator) CreateVariedTestDataSet(scenario TestDataScenario) *ContractTestDataSet {
	users := g.GenerateTestUsers(scenario)
	clients := g.GenerateTestClients(scenario)
	
	return &ContractTestDataSet{
		Users:   users,
		Clients: clients,
	}
}

// Scenario-specific helpers
func (g *TestDataGenerator) CreateBasicScenario() *ContractTestDataSet {
	scenario := TestDataScenario{
		Name:            "Basic",
		UserCount:       3,
		ClientCount:     2,
		EmailDomains:    g.config.EmailDomains,
		IncludeClientID: true,
		IncludeEmail:    true,
		IncludeUsername: true,
	}
	return g.CreateVariedTestDataSet(scenario)
}

func (g *TestDataGenerator) CreateEdgeCaseScenario() *ContractTestDataSet {
	scenario := TestDataScenario{
		Name:              "EdgeCase",
		UserCount:         2,
		ClientCount:       1,
		EmailDomains:      []string{"opentdf.test"},
		IncludeClientID:   false,
		IncludeEmail:      true,
		IncludeUsername:   true,
		IncludeEmptyUsers: true,
	}
	return g.CreateVariedTestDataSet(scenario)
}