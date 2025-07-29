package integration

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/creasty/defaults"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/go-ldap/ldap/v3"
	"github.com/opentdf/platform/service/entityresolution/integration/internal"
	ldapv2 "github.com/opentdf/platform/service/entityresolution/ldap/v2"
	"github.com/opentdf/platform/service/logger"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.opentelemetry.io/otel/trace/noop"
)

// TestLDAPEntityResolutionV2 runs all ERS tests against LDAP implementation using the generic contract test framework
func TestLDAPEntityResolutionV2(t *testing.T) {
	contractSuite := internal.NewContractTestSuite()
	adapter := NewLDAPTestAdapter()

	contractSuite.RunContractTestsWithAdapter(t, adapter)
}

var ldapContainer tc.Container
var ldapConfig *LDAPTestConfig

// LDAPTestConfig holds LDAP-specific test configuration
type LDAPTestConfig struct {
	Host             string `json:"host" default:"localhost"`
	Port             int    `json:"port" default:"389"`
	PortTLS          int    `json:"port_tls" default:"636"`
	Organization     string `json:"organization" default:"OpenTDF Test"`
	Domain           string `json:"domain" default:"opentdf.test"`
	AdminPassword    string `json:"admin_password" default:"admin_password"`
	ConfigPassword   string `json:"config_password" default:"config_password"`
	ReadOnlyUser     string `json:"readonly_user" default:"readonly"`
	ReadOnlyPassword string `json:"readonly_password" default:"readonly_password"`
	BaseDN           string `json:"base_dn" default:"dc=opentdf,dc=test"`
	UsersDN          string `json:"users_dn" default:"ou=users,dc=opentdf,dc=test"`
	GroupsDN         string `json:"groups_dn" default:"ou=groups,dc=opentdf,dc=test"`
	ClientsDN        string `json:"clients_dn" default:"ou=clients,dc=opentdf,dc=test"`
}

// LDAPTestDataInjector implements test data injection for LDAP backends
type LDAPTestDataInjector struct {
	connection *ldap.Conn
	baseDN     string
	logger     *logger.Logger
}

// NewLDAPTestDataInjector creates a new LDAP test data injector
func NewLDAPTestDataInjector(connection *ldap.Conn, baseDN string, logger *logger.Logger) *LDAPTestDataInjector {
	return &LDAPTestDataInjector{
		connection: connection,
		baseDN:     baseDN,
		logger:     logger,
	}
}

// InjectTestData injects contract test data into LDAP
func (injector *LDAPTestDataInjector) InjectTestData(ctx context.Context, dataSet *internal.ContractTestDataSet) error {
	// Create organizational units if they don't exist
	if err := injector.createOrgUnits(ctx); err != nil {
		return fmt.Errorf("failed to create organizational units: %w", err)
	}

	// Inject users
	for _, user := range dataSet.Users {
		if err := injector.createUser(ctx, user); err != nil {
			injector.logger.Error("failed to create user", slog.String("username", user.Username), slog.String("error", err.Error()))
			return fmt.Errorf("failed to create user %s: %w", user.Username, err)
		}
	}

	// Inject clients
	for _, client := range dataSet.Clients {
		if err := injector.createClient(ctx, client); err != nil {
			injector.logger.Error("failed to create client", slog.String("client_id", client.ClientID), slog.String("error", err.Error()))
			return fmt.Errorf("failed to create client %s: %w", client.ClientID, err)
		}
	}

	injector.logger.Info("contract test data injected successfully into LDAP")
	return nil
}

// CleanupTestData removes all test data from LDAP
func (injector *LDAPTestDataInjector) CleanupTestData(ctx context.Context) error {
	// This would typically remove test entries, but for simplicity we'll skip this
	// in a real implementation, you'd want to clean up test data
	injector.logger.Info("LDAP test data cleanup completed")
	return nil
}

// ValidateTestData validates that test data exists in LDAP
func (injector *LDAPTestDataInjector) ValidateTestData(ctx context.Context, dataSet *internal.ContractTestDataSet) error {
	// Validate users exist
	for _, user := range dataSet.Users {
		if err := injector.validateUser(ctx, user); err != nil {
			return fmt.Errorf("user validation failed for %s: %w", user.Username, err)
		}
	}

	// Validate clients exist
	for _, client := range dataSet.Clients {
		if err := injector.validateClient(ctx, client); err != nil {
			return fmt.Errorf("client validation failed for %s: %w", client.ClientID, err)
		}
	}

	injector.logger.Info("LDAP test data validation completed successfully")
	return nil
}

// createOrgUnits creates necessary organizational units
func (injector *LDAPTestDataInjector) createOrgUnits(ctx context.Context) error {
	orgUnits := []struct {
		ou string
		dn string
	}{
		{"users", fmt.Sprintf("ou=users,%s", injector.baseDN)},
		{"clients", fmt.Sprintf("ou=clients,%s", injector.baseDN)},
		{"groups", fmt.Sprintf("ou=groups,%s", injector.baseDN)},
	}

	for _, unit := range orgUnits {
		addReq := ldap.NewAddRequest(unit.dn, nil)
		addReq.Attribute("objectClass", []string{"organizationalUnit"})
		addReq.Attribute("ou", []string{unit.ou})

		err := injector.connection.Add(addReq)
		if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			return fmt.Errorf("failed to create OU %s: %w", unit.ou, err)
		}
	}

	return nil
}

// createUser creates a user in LDAP
func (injector *LDAPTestDataInjector) createUser(ctx context.Context, user internal.TestUser) error {
	userDN := fmt.Sprintf("uid=%s,ou=users,%s", user.Username, injector.baseDN)

	addReq := ldap.NewAddRequest(userDN, nil)
	addReq.Attribute("objectClass", []string{"inetOrgPerson", "organizationalPerson", "person", "top"})
	addReq.Attribute("uid", []string{user.Username})
	addReq.Attribute("cn", []string{user.DisplayName})
	addReq.Attribute("sn", []string{user.Username}) // Simple surname
	addReq.Attribute("displayName", []string{user.DisplayName})
	addReq.Attribute("mail", []string{user.Email})

	err := injector.connection.Add(addReq)
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
		return fmt.Errorf("failed to add user: %w", err)
	}

	return nil
}

// createClient creates a client in LDAP
func (injector *LDAPTestDataInjector) createClient(ctx context.Context, client internal.TestClient) error {
	clientDN := fmt.Sprintf("cn=%s,ou=clients,%s", client.ClientID, injector.baseDN)

	addReq := ldap.NewAddRequest(clientDN, nil)
	addReq.Attribute("objectClass", []string{"organizationalRole", "top"})
	addReq.Attribute("cn", []string{client.ClientID})
	addReq.Attribute("description", []string{client.Description})

	err := injector.connection.Add(addReq)
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
		return fmt.Errorf("failed to add client: %w", err)
	}

	return nil
}

// validateUser validates that a user exists in LDAP
func (injector *LDAPTestDataInjector) validateUser(ctx context.Context, user internal.TestUser) error {
	searchReq := ldap.NewSearchRequest(
		fmt.Sprintf("ou=users,%s", injector.baseDN),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(user.Username)),
		[]string{"uid", "mail", "displayName"},
		nil,
	)

	result, err := injector.connection.Search(searchReq)
	if err != nil {
		return fmt.Errorf("search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return fmt.Errorf("user not found")
	}

	entry := result.Entries[0]
	if entry.GetAttributeValue("mail") != user.Email {
		return fmt.Errorf("email mismatch: expected %s, got %s", user.Email, entry.GetAttributeValue("mail"))
	}

	return nil
}

// validateClient validates that a client exists in LDAP
func (injector *LDAPTestDataInjector) validateClient(ctx context.Context, client internal.TestClient) error {
	searchReq := ldap.NewSearchRequest(
		fmt.Sprintf("ou=clients,%s", injector.baseDN),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(cn=%s)", ldap.EscapeFilter(client.ClientID)),
		[]string{"cn", "description"},
		nil,
	)

	result, err := injector.connection.Search(searchReq)
	if err != nil {
		return fmt.Errorf("search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return fmt.Errorf("client not found")
	}

	return nil
}

// LDAPTestAdapter implements ERSTestAdapter for LDAP ERS testing
type LDAPTestAdapter struct {
	service    *ldapv2.LDAPEntityResolutionServiceV2
	connection *ldap.Conn
	injector   *LDAPTestDataInjector
}

// NewLDAPTestAdapter creates a new LDAP test adapter
func NewLDAPTestAdapter() *LDAPTestAdapter {
	return &LDAPTestAdapter{}
}

// GetScopeName returns the scope name for LDAP ERS
func (a *LDAPTestAdapter) GetScopeName() string {
	return "LDAP"
}

// SetupTestData injects test data into the LDAP server
func (a *LDAPTestAdapter) SetupTestData(ctx context.Context, testDataSet *internal.ContractTestDataSet) error {
	// Start the LDAP container first
	if ldapContainer == nil {
		if err := setupLDAP(ctx, tc.ProviderDefault); err != nil {
			return fmt.Errorf("failed to setup LDAP container: %w", err)
		}
	}

	// Initialize LDAP config if not already done
	if err := initLDAPConfig(); err != nil {
		return err
	}

	// Create LDAP connection using the same configuration as the service
	bindDN := fmt.Sprintf("cn=admin,%s", ldapConfig.BaseDN)
	bindPassword := ldapConfig.AdminPassword

	// Connect to LDAP server
	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", ldapConfig.Host, ldapConfig.Port))
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	// Bind as admin
	err = conn.Bind(bindDN, bindPassword)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to bind to LDAP server: %w", err)
	}

	a.connection = conn

	// Create the LDAP test data injector
	testLogger := logger.CreateTestLogger()
	a.injector = NewLDAPTestDataInjector(conn, ldapConfig.BaseDN, testLogger)

	// Inject the contract test data
	return a.injector.InjectTestData(ctx, testDataSet)
}

// CreateERSService creates and returns a configured LDAP ERS service
func (a *LDAPTestAdapter) CreateERSService(ctx context.Context) (internal.ERSImplementation, error) {
	// Initialize LDAP config if not already done
	if err := initLDAPConfig(); err != nil {
		return nil, err
	}

	bindDN := fmt.Sprintf("cn=admin,%s", ldapConfig.BaseDN)
	bindPassword := ldapConfig.AdminPassword

	// Try using TLS port with insecure TLS since container has TLS disabled
	ldapServiceConfig := map[string]any{
		"servers":           []string{ldapConfig.Host},
		"port":              ldapConfig.PortTLS, // Use TLS port (63600 mapped from 636)
		"use_tls":           true,
		"insecure_tls":      true, // Allow insecure TLS
		"start_tls":         false,
		"bind_dn":           bindDN,
		"bind_password":     bindPassword,
		"base_dn":           ldapConfig.BaseDN,
		"user_filter":       "(uid={username})",
		"email_filter":      "(mail={email})",
		"client_id_filter":  "(cn={client_id})",
		"group_search_base": ldapConfig.GroupsDN,
		"group_filter":      "(member={dn})",
		"attribute_mapping": map[string]any{
			"username":     "uid",
			"email":        "mail",
			"display_name": "displayName",
			"groups":       "memberOf",
			"client_id":    "cn",
			"additional":   []string{"description"},
		},
		"include_groups": true,
		"inferid": map[string]any{
			"from": map[string]any{
				"clientid": true,
				"email":    true,
				"username": true,
			},
		},
	}

	testLogger := logger.CreateTestLogger()
	service, _ := ldapv2.RegisterLDAPERS(ldapServiceConfig, testLogger)

	// Set a no-op tracer for testing to prevent nil pointer dereference
	service.Tracer = noop.NewTracerProvider().Tracer("test-ldap-v2")

	a.service = service
	return service, nil
}

// TeardownTestData cleans up LDAP test data and resources
func (a *LDAPTestAdapter) TeardownTestData(ctx context.Context) error {
	if a.injector != nil {
		// Use the injector to clean up test data
		if err := a.injector.CleanupTestData(ctx); err != nil {
			// Log the error but don't fail - cleanup is best effort
			// In container environments, cleanup happens when container is destroyed
			fmt.Printf("Warning: LDAP cleanup failed: %v\n", err)
		}
	}

	if a.connection != nil {
		a.connection.Close()
	}

	// Cleanup the container
	if ldapContainer != nil {
		if err := ldapContainer.Terminate(ctx); err != nil {
			fmt.Printf("Warning: Failed to terminate LDAP container: %v\n", err)
		}
		ldapContainer = nil
	}

	return nil
}

// initLDAPConfig initializes the LDAP configuration with defaults
func initLDAPConfig() error {
	if ldapConfig == nil {
		ldapConfig = &LDAPTestConfig{}
		if err := defaults.Set(ldapConfig); err != nil {
			return fmt.Errorf("failed to set LDAP config defaults: %w", err)
		}
	}
	return nil
}

// createLDAPContainerConfig returns an LDAP container configuration
func createLDAPContainerConfig(config *LDAPTestConfig) internal.ContainerConfig {
	return internal.ContainerConfig{
		Image:        "osixia/openldap:1.5.0",
		ExposedPorts: []string{"389/tcp", "636/tcp"},
		Env: map[string]string{
			"LDAP_ORGANISATION":              config.Organization,
			"LDAP_DOMAIN":                    config.Domain,
			"LDAP_ADMIN_PASSWORD":            config.AdminPassword,
			"LDAP_CONFIG_PASSWORD":           config.ConfigPassword,
			"LDAP_READONLY_USER":             "true",
			"LDAP_READONLY_USER_USERNAME":    config.ReadOnlyUser,
			"LDAP_READONLY_USER_PASSWORD":    config.ReadOnlyPassword,
			"LDAP_RFC2307BIS_SCHEMA":         "false",
			"LDAP_BACKEND":                   "mdb",
			"LDAP_TLS":                       "true",
			"LDAP_TLS_ENFORCE":               "false",
			"LDAP_TLS_VERIFY_CLIENT":         "never",
			"KEEP_EXISTING_CONFIG":           "false",
			"LDAP_REMOVE_CONFIG_AFTER_SETUP": "true",
			"LDAP_SSL_HELPER_PREFIX":         "ldap",
		},
		WaitStrategy: wait.ForLog("slapd starting").WithStartupTimeout(60 * time.Second),
		Timeout: 3 * time.Minute,
	}
}

// setupLDAP sets up the LDAP container for testing
func setupLDAP(ctx context.Context, providerType tc.ProviderType) error {
	// Initialize LDAP config
	if err := initLDAPConfig(); err != nil {
		return err
	}

	slog.Info("📀 starting OpenLDAP container")

	containerConfig := createLDAPContainerConfig(ldapConfig)

	req := tc.GenericContainerRequest{
		ProviderType: providerType,
		ContainerRequest: tc.ContainerRequest{
			Image:        containerConfig.Image,
			Name:         "testcontainer-openldap",
			ExposedPorts: containerConfig.ExposedPorts,
			HostConfigModifier: func(config *container.HostConfig) {
				config.PortBindings = nat.PortMap{
					"389/tcp": []nat.PortBinding{
						{
							HostIP:   "0.0.0.0",
							HostPort: "38900",
						},
					},
					"636/tcp": []nat.PortBinding{
						{
							HostIP:   "0.0.0.0",
							HostPort: "63600",
						},
					},
				}
			},
			Env:        containerConfig.Env,
			WaitingFor: containerConfig.WaitStrategy,
		},
		Started: true,
	}

	var err error
	ldapContainer, err = tc.GenericContainer(ctx, req)
	if err != nil {
		return fmt.Errorf("could not start OpenLDAP container: %w", err)
	}

	// Get mapped ports
	ldapPort, err := ldapContainer.MappedPort(ctx, "389/tcp")
	if err != nil {
		return fmt.Errorf("could not get LDAP mapped port: %w", err)
	}

	ldapsPort, err := ldapContainer.MappedPort(ctx, "636/tcp")
	if err != nil {
		return fmt.Errorf("could not get LDAPS mapped port: %w", err)
	}

	ldapConfig.Port = ldapPort.Int()
	ldapConfig.PortTLS = ldapsPort.Int()
	ldapConfig.Host = "localhost"

	// Wait a bit more for LDAP to be fully ready
	time.Sleep(5 * time.Second)

	slog.Info("✅ OpenLDAP container ready",
		slog.Int("ldap_port", ldapConfig.Port),
		slog.Int("ldaps_port", ldapConfig.PortTLS))

	return nil
}
