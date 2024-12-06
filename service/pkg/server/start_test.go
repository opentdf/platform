package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/internal/config"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"gopkg.in/yaml.v3"
)

type (
	TestServiceService interface{}
	TestService        struct{}
)

const (
	dbusername = "postgres"
	dbpassword = "changeme"
)

func (t TestService) TestHandler(w http.ResponseWriter, _ *http.Request, _ map[string]string) {
	_, err := w.Write([]byte("hello from test service!"))
	if err != nil {
		panic(err)
	}
}

func mockPostgres() (int, string, error) {
	ctx := context.Background()
	containerreq := tc.ContainerRequest{
		Image:        "postgres:15-alpine",
		Name:         "testcontainer-postgres",
		ExposedPorts: []string{"5431/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     dbusername,
			"POSTGRES_PASSWORD": dbpassword,
			"POSTGRES_DB":       "opentdf",
		},
		WaitingFor: wait.ForExec([]string{"pg_isready", "-h", "localhost", "-U", "postgres"}).WithStartupTimeout(120 * time.Second),
	}
	req := tc.GenericContainerRequest{
		ProviderType:     tc.ProviderDocker,
		ContainerRequest: containerreq,
		Started:          true,
	}

	// cleanup existing containers:
	existingContainers, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: containerreq,
		Started:          false,
	})
	if err == nil {
		err := existingContainers.Terminate(ctx) // Clean up pre-existing containers
		if err != nil {
			slog.Error("could not stop existing container")
		}
	}

	slog.Info("starting postgres container")
	postgres, err := tc.GenericContainer(context.Background(), req)
	if err != nil {
		return 0, "", fmt.Errorf("could not start postgres container, %w", err)
	}

	// Cleanup the container
	defer func() {
		if err := postgres.Terminate(ctx); err != nil {
			slog.Error("could not stop postgres container", slog.String("error", err.Error()))
			return
		}

		if err := recover(); err != nil {
			os.Exit(1)
		}
	}()

	port, err := postgres.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return 0, "", fmt.Errorf("could not get postgres mapped port, %w", err)
	}
	host, err := postgres.Host(ctx)
	if err != nil {
		return 0, "", fmt.Errorf("Failed to get host: %w", err)
	}

	return port.Int(), host, nil
}

func mockKeycloakServer() *httptest.Server {
	discoveryURL := "not set yet"
	discoveryEndpoint := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var resp string
			switch req.URL.Path {
			case "/.well-known/openid-configuration":
				resp = `{
					"issuer":	"https://example.com",
					"authorization_endpoint":	"https://example.com/oauth2/v1/authorize",
					"token_endpoint":	"https://example.com/oauth2/v1/token",
					"userinfo_endpoint": "https://example.com/oauth2/v1/userinfo",
					"registration_endpoint": "https://example.com/oauth2/v1/clients",
					"jwks_uri": "` + discoveryURL + `/oauth2/v1/keys"
				}`
			case "/oauth2/v1/keys":
				resp = `{
					"keys":[{"kty":"RSA","alg":"RS256","kid":"saqvCEEc1QX1kjGRh3sf0o4bdPMiiQBVj9xYz95M-X0","use":"sig","e":"AQAB","n":"yXgJvKqNfKoOoc1KiTg8QYfAO2AA47PjHtqZFsPSh93FI3tobD52t1I9cbD7ZotIYfYmZ6KwDvtrAIMVAPKvqvVUji3xSsNQ_Vv4XRmoWwP1vgJNJxoHOyj7pfDdhjplZZaQEcEEpm_J9rXN6V2lLyL6zYLJr_SlI5JeMc8i0tigFW_yLTUpSQ_85r5fAvkr0VDeUHfonaueaFhF5r-fne-F9EZzAVZvG3P8IG8_K6NEoM6muzsplPWJ-95hheRa3Zh58vYTVHcX8DXd8rpS3laUlLuEmIVs-FlqYrIBKpP2spQYGRvf-P1wpNftMH7OTB4j6ULQjwlNRmiQ34TOhw"}]
				}`
			default:
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(resp))
		}),
	)

	discoveryURL = discoveryEndpoint.URL

	return discoveryEndpoint
}

func mockOpenTDFServer() (*server.OpenTDFServer, error) {
	discoveryEndpoint := mockKeycloakServer()
	// Create new opentdf server
	return server.NewOpenTDFServer(server.Config{
		WellKnownConfigRegister: func(_ string, _ any) error {
			return nil
		},
		Auth: auth.Config{
			AuthNConfig: auth.AuthNConfig{
				Issuer:   discoveryEndpoint.URL,
				Audience: "test",
			},
			PublicRoutes: []string{"/testpath/*"},
		},
		Port: 43481,
	},
		&logger.Logger{
			Logger: slog.New(slog.Default().Handler()),
		},
	)
}

func updateNestedKey(data map[string]interface{}, path []string, value interface{}) error {
	if len(path) == 0 {
		return fmt.Errorf("path cannot be empty")
	}

	current := data
	for i, key := range path[:len(path)-1] {
		if next, ok := current[key]; ok {
			if nextMap, ok2 := next.(map[string]interface{}); ok2 {
				current = nextMap
			} else {
				return fmt.Errorf("key %s at path level %d is not a map", key, i)
			}
		} else {
			// If the key doesn't exist, initialize a new map
			newMap := make(map[string]interface{})
			current[key] = newMap
			current = newMap
		}
	}

	// Set the value at the final key
	current[path[len(path)-1]] = value
	return nil
}

func createTempYAMLFileWithNestedChanges(changes map[string]interface{}, originalFilePath string, newFileName string) (string, error) {
	// Load the original YAML file
	data, err := os.ReadFile(originalFilePath)
	if err != nil {
		return "", err
	}

	var yamlData map[string]interface{}
	if err := yaml.Unmarshal(data, &yamlData); err != nil {
		return "", err
	}

	// Apply all changes
	for keyPath, value := range changes {
		path := strings.Split(keyPath, ".") // Convert dot notation to slice
		if err := updateNestedKey(yamlData, path, value); err != nil {
			return "", err
		}
	}

	// Create a temporary file
	tempFile, err := os.CreateTemp("testdata", newFileName)
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	// Write the modified YAML to the temp file
	encoder := yaml.NewEncoder(tempFile)
	defer encoder.Close()

	if err := encoder.Encode(&yamlData); err != nil {
		return "", err
	}

	return tempFile.Name(), nil
}

type StartTestSuite struct {
	suite.Suite
}

func TestStartTestSuite(t *testing.T) {
	suite.Run(t, new(StartTestSuite))
}

func (suite *StartTestSuite) Test_Start_When_Extra_Service_Registered_Expect_Response() {
	t := suite.T()
	s, err := mockOpenTDFServer()
	require.NoError(t, err)

	logger, err := logger.NewLogger(logger.Config{Output: "stdout", Level: "info", Type: "json"})
	require.NoError(t, err)

	// Register Test Service
	ts := TestService{}
	registerTestService, _ := mockTestServiceRegistry(mockTestServiceOptions{
		serviceObject: ts,
		serviceHandler: func(_ context.Context, mux *runtime.ServeMux) error {
			return mux.HandlePath(http.MethodGet, "/healthz", ts.TestHandler)
		},
	})

	registry := serviceregistry.NewServiceRegistry()
	err = registry.RegisterService(registerTestService, "test")
	suite.Require().NoError(err)
	// Start services with test service
	err = startServices(context.Background(), config.Config{
		Mode: []string{"all"},
		Services: map[string]serviceregistry.ServiceConfig{
			"test": {},
		},
	}, s, nil, logger, registry)
	require.NoError(t, err)

	require.NoError(t, s.Start())
	defer s.Stop()

	var resp *http.Response
	// Make request to test service and ensure it registered
	for i := 3; i > 0; i-- {
		resp, err = http.Get("http://localhost:43481/healthz")
		if err == nil {
			break
		}
		slog.Info("not yet ready", "err", err)
		// retry after a blip
		time.Sleep(100 * time.Millisecond)
	}

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	respBody, err := io.ReadAll(resp.Body)

	require.NoError(t, err)
	assert.Equal(t, "hello from test service!", string(respBody))
}

func (suite *StartTestSuite) Test_Start_Mode_Config_Errors() {
	t := suite.T()
	discoveryEndpoint := mockKeycloakServer()
	originalFilePath := "testdata/all-no-config.yaml"
	testCases := []struct {
		name             string
		changes          map[string]interface{}
		newConfigFile    string
		expErrorContains string
	}{
		{"core without sdk_config",
			map[string]interface{}{
				"mode": "core", "server.auth.issuer": discoveryEndpoint.URL},
			"err-core-no-config-*.yaml", "no sdk config provided"},
		{"kas without sdk_config",
			map[string]interface{}{
				"mode": "kas", "server.auth.issuer": discoveryEndpoint.URL},
			"err-kas-no-config-*.yaml", "no sdk config provided"},
		{"core with sdk_config without ers endpoint",
			map[string]interface{}{
				"mode": "core", "server.auth.issuer": discoveryEndpoint.URL,
				"sdk_config.client_id": "opentdf", "sdk_config.client_secret": "opentdf"},
			"err-core-w-config-no-ers-*.yaml", "entityresolution endpoint must be provided in core mode"},
	}
	var tempFiles []string
	defer func() {
		// Cleanup all created temp files
		for _, tempFile := range tempFiles {
			if err := os.Remove(tempFile); err != nil {
				t.Errorf("Failed to remove temp file %s: %v", tempFile, err)
			}
		}
	}()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tempFilePath, err := createTempYAMLFileWithNestedChanges(tc.changes, originalFilePath, tc.newConfigFile)
			if err != nil {
				t.Fatalf("Failed to create temp YAML file: %v", err)
			}
			tempFiles = append(tempFiles, tempFilePath)

			err = Start(
				WithConfigFile(tempFilePath),
			)
			require.Error(t, err)
			require.ErrorContains(t, err, tc.expErrorContains)
		})
	}
}

func (suite *StartTestSuite) Test_Start_Mode_Config_Success() {
	t := suite.T()
	discoveryEndpoint := mockKeycloakServer()
	port, host, err := mockPostgres()
	require.NoError(t, err)
	originalFilePath := "testdata/all-no-config.yaml"
	testCases := []struct {
		name          string
		changes       map[string]interface{}
		newConfigFile string
	}{
		{"all without sdk_config",
			map[string]interface{}{
				"db.host": host, "db.port": port,
				"db.user": dbusername, "db.password": dbpassword,
				"server.auth.issuer": discoveryEndpoint.URL},
			"all-no-config-*.yaml"},
		{"core,entityresolution without sdk_config",
			map[string]interface{}{"db.host": host, "db.port": port,
				"db.user": dbusername, "db.password": dbpassword,
				"mode": "core,entityresolution", "server.auth.issuer": discoveryEndpoint.URL},
			"all-no-config-*.yaml"},
		{"core,entityresolution,kas without sdk_config",
			map[string]interface{}{"db.host": host, "db.port": port,
				"db.user": dbusername, "db.password": dbpassword,
				"mode": "core,entityresolution,kas", "server.auth.issuer": discoveryEndpoint.URL},
			"all-no-config-*.yaml"},
		{"core with correct sdk_config",
			map[string]interface{}{"db.host": host, "db.port": port,
				"db.user": dbusername, "db.password": dbpassword,
				"mode": "core", "server.auth.issuer": discoveryEndpoint.URL,
				"sdk_config.client_id": "opentdf", "sdk_config.client_secret": "opentdf",
				"sdk_config.entityresolution.endpoint": "http://localhost:8181", "sdk_config.entityresolution.plaintext": "true"},
			"core-w-config-correct-*.yaml"},
	}
	var tempFiles []string
	defer func() {
		// Cleanup all created temp files
		for _, tempFile := range tempFiles {
			if err := os.Remove(tempFile); err != nil {
				t.Errorf("Failed to remove temp file %s: %v", tempFile, err)
			}
		}
	}()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tempFilePath, err := createTempYAMLFileWithNestedChanges(tc.changes, originalFilePath, tc.newConfigFile)
			if err != nil {
				t.Fatalf("Failed to create temp YAML file: %v", err)
			}
			tempFiles = append(tempFiles, tempFilePath)

			err = Start(
				WithConfigFile(tempFilePath),
			)
			require.NoError(t, err)
		})
	}
}
