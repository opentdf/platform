package integration

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/docker/docker/api/types/container"
	"github.com/opentdf/platform/service/entityresolution/integration/internal"
	keycloakv2 "github.com/opentdf/platform/service/entityresolution/keycloak/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.opentelemetry.io/otel/trace/noop"
)

// TestKeycloakEntityResolutionV2 runs all ERS tests against Keycloak implementation using the generic contract test framework
func TestKeycloakEntityResolutionV2(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Keycloak integration tests in short mode")
	}

	// Use a panic handler to catch Docker unavailability
	defer func() {
		if r := recover(); r != nil {
			if panicStr := fmt.Sprintf("%v", r); strings.Contains(panicStr, "Docker") || strings.Contains(panicStr, "docker") {
				t.Skipf("Docker not available for Keycloak container tests: %v", r)
			} else {
				// Re-panic if it's not a Docker issue
				panic(r)
			}
		}
	}()

	contractSuite := internal.NewContractTestSuite()
	adapter := NewKeycloakTestAdapter()

	contractSuite.RunContractTestsWithAdapter(t, adapter)
}

var keycloakContainer tc.Container

// KeycloakTestConfig holds Keycloak-specific test configuration
type KeycloakTestConfig struct {
	URL          string `json:"url"`
	AdminURL     string `json:"admin_url"`
	Realm        string `json:"realm" default:"opentdf"`
	ClientID     string `json:"client_id" default:"test-client"`
	ClientSecret string `json:"client_secret" default:"test-secret"`
	AdminUser    string `json:"admin_user" default:"admin"`
	AdminPass    string `json:"admin_pass" default:"admin_password"`
	Host         string `json:"host" default:"localhost"`
	Port         int    `json:"port" default:"8080"`
}

// KeycloakTestAdapter implements ERSTestAdapter for Keycloak ERS testing
type KeycloakTestAdapter struct {
	service        *keycloakv2.EntityResolutionServiceV2
	keycloakClient *gocloak.GoCloak
	adminToken     *gocloak.JWT
	config         *KeycloakTestConfig
	containerSetup bool
}

// NewKeycloakTestAdapter creates a new Keycloak test adapter
func NewKeycloakTestAdapter() *KeycloakTestAdapter {
	return &KeycloakTestAdapter{
		config: &KeycloakTestConfig{
			Realm:        "opentdf",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			AdminUser:    "admin",
			AdminPass:    "admin_password",
			Host:         "localhost",
			Port:         8080,
		},
	}
}

// GetScopeName returns the scope name for Keycloak ERS
func (a *KeycloakTestAdapter) GetScopeName() string {
	return "Keycloak"
}

// SetupTestData sets up Keycloak container and injects test data using Admin API
func (a *KeycloakTestAdapter) SetupTestData(ctx context.Context, testDataSet *internal.ContractTestDataSet) error {
	// Setup Keycloak container if not already done
	if !a.containerSetup {
		if err := a.setupKeycloakContainer(ctx); err != nil {
			return fmt.Errorf("failed to setup Keycloak container: %w", err)
		}
		a.containerSetup = true
	}

	// Initialize Keycloak admin client
	if err := a.initializeKeycloakClient(ctx); err != nil {
		return fmt.Errorf("failed to initialize Keycloak client: %w", err)
	}

	// Create realm if it doesn't exist
	if err := a.createTestRealm(ctx); err != nil {
		return fmt.Errorf("failed to create test realm: %w", err)
	}

	// Create test client
	if err := a.createTestClient(ctx); err != nil {
		return fmt.Errorf("failed to create test client: %w", err)
	}

	// Inject test users
	if err := a.injectTestUsers(ctx, testDataSet.Users); err != nil {
		return fmt.Errorf("failed to inject test users: %w", err)
	}

	// Inject test clients (additional clients)
	if err := a.injectTestClients(ctx, testDataSet.Clients); err != nil {
		return fmt.Errorf("failed to inject test clients: %w", err)
	}

	return nil
}

// CreateERSService creates and returns a configured Keycloak ERS service
func (a *KeycloakTestAdapter) CreateERSService(_ context.Context) (internal.ERSImplementation, error) {
	keycloakConfig := map[string]interface{}{
		"url":            a.config.URL,
		"realm":          a.config.Realm,
		"clientid":       a.config.ClientID,
		"clientsecret":   a.config.ClientSecret,
		"legacykeycloak": false,
		"subgroups":      false,
		"inferid": map[string]interface{}{
			"from": map[string]interface{}{
				"clientid": true,
				"email":    true,
				"username": true,
			},
		},
	}

	testLogger := logger.CreateTestLogger()

	// Create a test cache - using nil for simplicity in tests
	var testCache *cache.Cache

	service, _ := keycloakv2.RegisterKeycloakERS(keycloakConfig, testLogger, testCache)

	// Set a no-op tracer for testing to prevent nil pointer dereference
	service.Tracer = noop.NewTracerProvider().Tracer("test-keycloak-v2")

	a.service = service
	return service, nil
}

// TeardownTestData cleans up Keycloak test data and resources
func (a *KeycloakTestAdapter) TeardownTestData(ctx context.Context) error {
	if keycloakContainer != nil {
		if err := keycloakContainer.Terminate(ctx); err != nil {
			return fmt.Errorf("failed to terminate Keycloak container: %w", err)
		}
		keycloakContainer = nil
		a.containerSetup = false
	}
	return nil
}

// createKeycloakContainerConfig returns a Keycloak container configuration
func (a *KeycloakTestAdapter) createKeycloakContainerConfig() internal.ContainerConfig {
	return internal.ContainerConfig{
		Image:        "quay.io/keycloak/keycloak:23.0",
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"KEYCLOAK_ADMIN":          a.config.AdminUser,
			"KEYCLOAK_ADMIN_PASSWORD": a.config.AdminPass,
			"KC_HTTP_ENABLED":         "true",
			"KC_HOSTNAME_STRICT":      "false",
			"KC_HEALTH_ENABLED":       "true",
			"KC_METRICS_ENABLED":      "false",
			"KC_LOG_LEVEL":            "WARN", // Reduce log noise for faster startup
		},
		Cmd:          []string{"start-dev"},
		WaitStrategy: wait.ForListeningPort("8080/tcp").WithStartupTimeout(2 * time.Minute),
		Timeout:      4 * time.Minute,
	}
}

// setupKeycloakContainer starts a Keycloak container for testing
func (a *KeycloakTestAdapter) setupKeycloakContainer(ctx context.Context) error {
	containerConfig := a.createKeycloakContainerConfig()

	req := tc.ContainerRequest{
		Image:        containerConfig.Image,
		ExposedPorts: containerConfig.ExposedPorts,
		Env:          containerConfig.Env,
		Cmd:          containerConfig.Cmd,
		WaitingFor:   containerConfig.WaitStrategy,
		HostConfigModifier: func(hostConfig *container.HostConfig) {
			hostConfig.AutoRemove = true
		},
	}

	container, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		if strings.Contains(err.Error(), "Docker") || strings.Contains(err.Error(), "docker") {
			return fmt.Errorf("Docker not available for Keycloak container tests: %w", err)
		}
		return fmt.Errorf("failed to start Keycloak container: %w", err)
	}

	keycloakContainer = container

	// Get mapped port
	mappedPort, err := container.MappedPort(ctx, "8080")
	if err != nil {
		return fmt.Errorf("failed to get mapped port: %w", err)
	}

	// Update config with actual container details
	a.config.Port = mappedPort.Int()
	a.config.URL = "http://" + net.JoinHostPort(a.config.Host, strconv.Itoa(a.config.Port))
	a.config.AdminURL = a.config.URL

	// Wait for Keycloak to be fully ready
	if err := a.waitForKeycloakReady(ctx); err != nil {
		return fmt.Errorf("Keycloak container not ready: %w", err)
	}

	return nil
}

// waitForKeycloakReady waits for Keycloak to be fully operational
func (a *KeycloakTestAdapter) waitForKeycloakReady(ctx context.Context) error {
	return internal.WaitForContainer(ctx, func() error {
		client := gocloak.NewClient(a.config.AdminURL)
		token, err := client.LoginAdmin(ctx, a.config.AdminUser, a.config.AdminPass, "master")
		if err != nil {
			return fmt.Errorf("admin login failed: %w", err)
		}
		if token.AccessToken == "" {
			return errors.New("empty access token")
		}
		return nil
	}, 20, 1*time.Second) // Reduced retries and faster interval
}

// initializeKeycloakClient initializes the Keycloak admin client
func (a *KeycloakTestAdapter) initializeKeycloakClient(ctx context.Context) error {
	a.keycloakClient = gocloak.NewClient(a.config.AdminURL)

	token, err := a.keycloakClient.LoginAdmin(ctx, a.config.AdminUser, a.config.AdminPass, "master")
	if err != nil {
		return fmt.Errorf("failed to login as admin: %w", err)
	}

	a.adminToken = token
	return nil
}

// createTestRealm creates the test realm in Keycloak
func (a *KeycloakTestAdapter) createTestRealm(ctx context.Context) error {
	realm := gocloak.RealmRepresentation{
		Realm:   gocloak.StringP(a.config.Realm),
		Enabled: gocloak.BoolP(true),
	}

	realmID, err := a.keycloakClient.CreateRealm(ctx, a.adminToken.AccessToken, realm)
	if err != nil {
		// Realm might already exist, check if it's a conflict
		if !isConflictError(err) {
			return fmt.Errorf("failed to create realm: %w", err)
		}
		slog.Debug("realm already exists, continuing", slog.String("realm", a.config.Realm))
	} else {
		slog.Debug("created realm",
			slog.String("realm", a.config.Realm),
			slog.String("id", realmID))
	}

	return nil
}

// createTestClient creates the test client in the realm
func (a *KeycloakTestAdapter) createTestClient(ctx context.Context) error {
	client := gocloak.Client{
		ClientID:                  gocloak.StringP(a.config.ClientID),
		Secret:                    gocloak.StringP(a.config.ClientSecret),
		Enabled:                   gocloak.BoolP(true),
		ServiceAccountsEnabled:    gocloak.BoolP(true),
		DirectAccessGrantsEnabled: gocloak.BoolP(true),
		PublicClient:              gocloak.BoolP(false), // Confidential client for service account
	}

	clientUUID, err := a.keycloakClient.CreateClient(ctx, a.adminToken.AccessToken, a.config.Realm, client)
	if err != nil {
		if !isConflictError(err) {
			return fmt.Errorf("failed to create client: %w", err)
		}
		slog.Debug("client already exists, continuing", slog.String("client", a.config.ClientID))

		// Get existing client UUID for role assignment
		clients, err := a.keycloakClient.GetClients(ctx, a.adminToken.AccessToken, a.config.Realm, gocloak.GetClientsParams{
			ClientID: gocloak.StringP(a.config.ClientID),
		})
		if err != nil {
			return fmt.Errorf("failed to get existing client: %w", err)
		}
		if len(clients) > 0 {
			clientUUID = *clients[0].ID
		}
	} else {
		slog.Debug("created client",
			slog.String("client", a.config.ClientID),
			slog.String("id", clientUUID))
	}

	// Assign realm-management roles to the service account for admin operations
	if err := a.assignServiceAccountRoles(ctx, clientUUID); err != nil {
		return fmt.Errorf("failed to assign service account roles: %w", err)
	}

	return nil
}

// assignServiceAccountRoles assigns necessary roles to service account for admin operations
func (a *KeycloakTestAdapter) assignServiceAccountRoles(ctx context.Context, clientUUID string) error {
	// Get the service account user for this client
	serviceAccountUser, err := a.keycloakClient.GetClientServiceAccount(ctx, a.adminToken.AccessToken, a.config.Realm, clientUUID)
	if err != nil {
		return fmt.Errorf("failed to get service account user: %w", err)
	}

	// Get the realm-management client in the realm
	realmMgmtClients, err := a.keycloakClient.GetClients(ctx, a.adminToken.AccessToken, a.config.Realm, gocloak.GetClientsParams{
		ClientID: gocloak.StringP("realm-management"),
	})
	if err != nil {
		return fmt.Errorf("failed to get realm-management client: %w", err)
	}
	if len(realmMgmtClients) == 0 {
		return errors.New("realm-management client not found")
	}

	realmMgmtClientUUID := *realmMgmtClients[0].ID

	// Get available roles from realm-management client
	availableRoles, err := a.keycloakClient.GetClientRoles(ctx, a.adminToken.AccessToken, a.config.Realm, realmMgmtClientUUID, gocloak.GetRoleParams{})
	if err != nil {
		return fmt.Errorf("failed to get realm-management client roles: %w", err)
	}

	// Find and assign the necessary roles
	var rolesToAssign []gocloak.Role
	neededRoles := []string{"view-users", "query-users", "view-clients", "query-clients", "manage-users", "manage-clients", "view-realm", "query-realms"}

	for _, availableRole := range availableRoles {
		for _, neededRole := range neededRoles {
			if availableRole.Name != nil && *availableRole.Name == neededRole {
				rolesToAssign = append(rolesToAssign, *availableRole)
				break
			}
		}
	}

	if len(rolesToAssign) > 0 {
		err = a.keycloakClient.AddClientRolesToUser(ctx, a.adminToken.AccessToken, a.config.Realm, realmMgmtClientUUID, *serviceAccountUser.ID, rolesToAssign)
		if err != nil {
			return fmt.Errorf("failed to assign roles to service account: %w", err)
		}
		slog.Debug("assigned roles to service account",
			slog.String("client", a.config.ClientID),
			slog.Int("roles", len(rolesToAssign)))
	}

	return nil
}

// injectTestUsers creates test users in Keycloak
func (a *KeycloakTestAdapter) injectTestUsers(ctx context.Context, users []internal.TestUser) error {
	for _, user := range users {
		keycloakUser := gocloak.User{
			Username:      gocloak.StringP(user.Username),
			Email:         gocloak.StringP(user.Email),
			FirstName:     gocloak.StringP(user.DisplayName),
			Enabled:       gocloak.BoolP(true),
			EmailVerified: gocloak.BoolP(true),
		}

		userID, err := a.keycloakClient.CreateUser(ctx, a.adminToken.AccessToken, a.config.Realm, keycloakUser)
		if err != nil {
			if !isConflictError(err) {
				return fmt.Errorf("failed to create user %s: %w", user.Username, err)
			}
			slog.Debug("user already exists, continuing", slog.String("username", user.Username))
			continue
		}

		// Set password for the user
		err = a.keycloakClient.SetPassword(ctx, a.adminToken.AccessToken, userID, a.config.Realm, user.Password, false)
		if err != nil {
			return fmt.Errorf("failed to set password for user %s: %w", user.Username, err)
		}

		slog.Debug("created user",
			slog.String("username", user.Username),
			slog.String("id", userID))
	}

	return nil
}

// injectTestClients creates additional test clients in Keycloak
func (a *KeycloakTestAdapter) injectTestClients(ctx context.Context, clients []internal.TestClient) error {
	for _, client := range clients {
		keycloakClient := gocloak.Client{
			ClientID:    gocloak.StringP(client.ClientID),
			Description: gocloak.StringP(client.Description),
			Enabled:     gocloak.BoolP(true),
		}

		clientID, err := a.keycloakClient.CreateClient(ctx, a.adminToken.AccessToken, a.config.Realm, keycloakClient)
		if err != nil {
			if !isConflictError(err) {
				return fmt.Errorf("failed to create client %s: %w", client.ClientID, err)
			}
			slog.Debug("client already exists, continuing", slog.String("client", client.ClientID))
			continue
		}

		slog.Info("successfully created test client",
			slog.String("client_id", client.ClientID),
			slog.String("uuid", clientID))
	}

	return nil
}

// isConflictError checks if the error is a conflict (resource already exists)
func isConflictError(err error) bool {
	return err != nil && (fmt.Sprintf("%v", err) == "409 Conflict" ||
		fmt.Sprintf("%v", err) == "resource already exists" ||
		containsString(err.Error(), "already exists") ||
		containsString(err.Error(), "409") ||
		containsString(err.Error(), "Conflict"))
}

// containsString checks if a string contains a substring
func containsString(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
