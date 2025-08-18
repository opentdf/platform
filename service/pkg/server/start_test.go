package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gopkg.in/yaml.v3"
)

const (
	dummyEcCert = `-----BEGIN CERTIFICATE-----
MIIB5DCBzQIUZsQqf2nfB0JuxsKBwrVjfCVjjmUwDQYJKoZIhvcNAQELBQAwGzEZ
MBcGA1UEAwwQY2Eub3BlbnRkZi5sb2NhbDAeFw0yMzA3MTgxOTM5NTJaFw0yMzA3
MTkxOTM5NTJaMA4xDDAKBgNVBAMMA2thczBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABDc+h0JhF0uUuXYY6mKHXTt81nBsBFnb0j+JWcBosyWBqC9GrQaiyfZxJXgX
XkEV8eULg7BztVhjK/qVNG4x5pIwDQYJKoZIhvcNAQELBQADggEBAGP1pPFNpx/i
N3skt5hVVYHPpGAUBxElbIRGx/NEPQ38q3RQ5QFMFHU9rCgQd/27lPZKS6+RLCbM
IsWPNtyPVlD9oPkVWydPiIKdRNJbKsv4FEHl0c5ik80E5er7B5TwzttR/t5B54m+
D0yZnKKXtqEi9KeStxCJKHcdibGuO+OtYJkl1uUhsX+6hDazdAX1jWq22j8L9hNS
buwEf498deOfNt/9PkT3MardMgQR492VPYJd4Ocj7drJEX0t2EeWouuoX9WijZi9
0umFuYEUo0VaLgv00k3hJuqBAUngzqlyepj8FKMsP6dkPpjjp/s9VTKHg2pmxeku
qX8+pZNixMc=
-----END CERTIFICATE-----
`
	dummyEcPrivate = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgdDFmn9LlJUTalXe8
S6/DnZELbJRo+NTpFKfs8VC2SK2hRANCAAQ3PodCYRdLlLl2GOpih107fNZwbARZ
29I/iVnAaLMlgagvRq0Gosn2cSV4F15BFfHlC4Owc7VYYyv6lTRuMeaS
-----END PRIVATE KEY-----
`
	dummyRsaPrivate = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA2+frLbHZOoUcdS3PWtPRkKrXQpMTKLR3B6dKDJwGnMU3jkr3
k5GK4wFnPv0G3fB8Duh/P8qtO8yORQXbSp6Fl6lCvciYMDE5qrPFYa/49iNHeeFM
WvdmRBDvr659UmfrZ+Fh9d2fN3hj7legiaa9kkD8YhJQ+zHplGMC2xMWnAy6NnlB
XAjKB57DtVckxb8SBFUqkSEFZGpl7tm87bPds2YzGwdhoy7eOuvhWb0XeBFt7RWz
98Dir9oB4CxW4YnQGZR2zL/2y6a+jf5kwYl9c+IGR81BPaPzHnrzo55MgmRUSq10
+odecl37TuFP+maU1Iq3jsVvXS5DbipxxPe8kwIDAQABAoIBAQCkdC0xkAZnODLP
AwJF55CagtjWhczXLRazF41OHsTnKqngdPnvVvGp0FvZBDrFcVolgAPhvf2Nce2X
esjDZgd8Iu2xpjkCGV4J5cUfyA0Ebd+/KxkCEnBdSNkm5fP805B9sFSlHSc7wYHi
NY/uQU8V+BmGcjIzmOEYwm7ZTM4kxhBEUyfczd41D0E312j/+J+Y2JFoLDugmyh7
KjYu79OCVvZU+snwcBDlnhdxoXnQTjlO68PDfXxqJmN94Jw/8+GYcA6N74uSwCp9
FZYD0X9AVQm7V/8t865S2UWcoHDNOZwW2IyBjaW37E20NGPx1PcAX9oZW3QsxSxG
gf7uj/zZAoGBAPz3RJq66CSXmcRMnNKk0CAu4LE3FrhKt9UsnGW1I1zzOfLylpHW
EfhCllb9Zsx92SeW6XDXBLEWIJmEQ6/c79cpaMMYkpfi4CsOLceZ3EoON22PsjNF
vSQ72oA6ueSnAC1rSPZV310YmkHgC0JPD+3W0wNe1+4OKR68bDxKNtxPAoGBAN6L
I9oK8AsQFJfTMlZ6SRCXarHVMo7uQZ2x+c5+n/DTlzcl5sk2o7iIuOyY2YFpJwYu
3fdiGohXPi5XnVzkFJTqSoOs6pKCRlD9TgEbNLF5JdnQvCuXDopc7s8BoIAVoQnV
da7L4fDeO6SpkmUd7ZdkegeY5zFL9m8qMPfWErZ9An85T8w7Qh1WLQKpdrIRB0Yg
BH7jp5d+KW983J6SbHeWl4SJhmyWnel0VaG6E682pUyNq6M37X8in+DC5zRuo5+z
H66chPSxdLVVC+FTV4iRPqdQKz40X5h6nRTj+GolY7CmmafuJ4ZzkR9hzWC/pSn2
uLUWDmbdiFfInufmwOmtAoGARghjb+qhP9n/oQfFf5FcDOyZlv0QvAoefBHWGzWd
/5uWqrQyvH+FZj0gdNRlHmSI81ksYP1ufBl4Z/0KeIEOOQ7CBE4WQ6TbnAEa2x5E
ptUJJFKb5NvUp5Y3UM2iRKyJ0R5rumZO5A4LlvYGK+wPKOVlwZ5MoybUlocggd3M
ZcECgYEAia0FTcXO8J1wZCYBTqFi+yvhVWPdn9kjK2ldWrsuJwO1llujjM3AqUto
awYnM8c/bPESvSLtl6+uuG3HcQRPIHz77dxvhRAyv4gltjyni3EYMreQGQwf5PNR
hgm3BlxwSujE0rKUwGCr5ol91yqiVojF/qyY4EwKP646AyMiJSQ=
-----END RSA PRIVATE KEY-----
`
	dummyRsaPublic = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2+frLbHZOoUcdS3PWtPR
kKrXQpMTKLR3B6dKDJwGnMU3jkr3k5GK4wFnPv0G3fB8Duh/P8qtO8yORQXbSp6F
l6lCvciYMDE5qrPFYa/49iNHeeFMWvdmRBDvr659UmfrZ+Fh9d2fN3hj7legiaa9
kkD8YhJQ+zHplGMC2xMWnAy6NnlBXAjKB57DtVckxb8SBFUqkSEFZGpl7tm87bPd
s2YzGwdhoy7eOuvhWb0XeBFt7RWz98Dir9oB4CxW4YnQGZR2zL/2y6a+jf5kwYl9
c+IGR81BPaPzHnrzo55MgmRUSq10+odecl37TuFP+maU1Iq3jsVvXS5DbipxxPe8
kwIDAQAB
-----END PUBLIC KEY-----
`
)

type (
	TestServiceService interface{}
	TestService        struct{}
)

func (t TestService) TestHandler(w http.ResponseWriter, _ *http.Request, _ map[string]string) {
	_, err := w.Write([]byte("hello from test service!"))
	if err != nil {
		panic(err)
	}
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
		&cache.Manager{},
	)
}

func updateNestedKey(data map[string]interface{}, path []string, value interface{}) error {
	if len(path) == 0 {
		return errors.New("path cannot be empty")
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

func (s *StartTestSuite) SetupSuite() {
	// Create dummy KAS key files in testdata
	keyFiles := map[string]string{
		"kas-private.pem":    dummyRsaPrivate,
		"kas-cert.pem":       dummyRsaPublic, // Using public key as cert for dummy purposes
		"kas-ec-private.pem": dummyEcPrivate,
		"kas-ec-cert.pem":    dummyEcCert,
	}

	for filename, content := range keyFiles {
		filePath := filepath.Join("testdata", filename)
		err := os.WriteFile(filePath, []byte(content), 0o600)
		s.Require().NoError(err, "Failed to write dummy key file: %s", filename)
	}
}

func (s *StartTestSuite) TearDownSuite() {
	ignoreFile := "all-no-config.yaml"

	entries, err := os.ReadDir("testdata")
	s.Require().NoError(err, "Failed to read testdata directory")

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if entry.Name() == ignoreFile {
			continue
		}
		err = os.Remove("testdata/" + entry.Name())
		s.Require().NoError(err, "Failed to remove testdata file: %s", entry.Name())
	}
}

func (s *StartTestSuite) Test_Start_When_Extra_Service_Registered() {
	testCases := []struct {
		name         string
		mode         []string
		status       int
		responseBody string
	}{
		{
			name:         "All_Mode",
			mode:         []string{"all"},
			status:       http.StatusOK,
			responseBody: "hello from test service!",
		},
		{
			name:         "And_Mode_Core",
			mode:         []string{"core"},
			status:       http.StatusNotFound,
			responseBody: "{\"code\":5,\"message\":\"Not Found\",\"details\":[]}",
		},
		{
			name:         "And_Mode_Core_Plus_Test",
			mode:         []string{"core", "test"},
			status:       http.StatusOK,
			responseBody: "hello from test service!",
		},
		{
			name:         "And_Mode_All_Plus_Test",
			mode:         []string{"all", "test"},
			status:       http.StatusOK,
			responseBody: "hello from test service!",
		},
		{
			name:         "And_Mode_Kas",
			mode:         []string{"kas"},
			status:       http.StatusNotFound,
			responseBody: "{\"code\":5,\"message\":\"Not Found\",\"details\":[]}",
		},
		{
			name:         "And_Mode_Kas_Plus_Test",
			mode:         []string{"kas", "test"},
			status:       http.StatusOK,
			responseBody: "hello from test service!",
		},
		{
			name:         "And_Mode_EntityResolution",
			mode:         []string{"entityresolution"},
			status:       http.StatusNotFound,
			responseBody: "{\"code\":5,\"message\":\"Not Found\",\"details\":[]}",
		},
		{
			name:         "And_Mode_EntityResolution_Plus_Test",
			mode:         []string{"entityresolution", "test"},
			status:       http.StatusOK,
			responseBody: "hello from test service!",
		},
		{
			name:         "And_Mode_Unknown",
			mode:         []string{"unknown"},
			status:       http.StatusNotFound,
			responseBody: "{\"code\":5,\"message\":\"Not Found\",\"details\":[]}",
		},
		{
			name:         "And_Mode_Unknown_Plus_Test",
			mode:         []string{"unknown", "test"},
			status:       http.StatusOK,
			responseBody: "hello from test service!",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			t := s.T()
			server, err := mockOpenTDFServer()
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
			require.NoError(t, err)

			// Start services with test service
			cleanup, err := startServices(context.Background(), startServicesParams{
				cfg: &config.Config{
					Mode: tc.mode,
					Services: map[string]config.ServiceConfig{
						"test": {},
					},
				},
				otdf:                server,
				client:              nil,
				keyManagerFactories: []trust.NamedKeyManagerFactory{},
				logger:              logger,
				reg:                 registry,
				cacheManager:        &cache.Manager{},
			})
			require.NoError(t, err)
			defer cleanup()

			require.NoError(t, server.Start())
			defer server.Stop()

			var resp *http.Response
			// Make request to test service and ensure it registered
			for i := 3; i > 0; i-- {
				resp, err = http.Get("http://localhost:43481/healthz")
				if err == nil {
					break
				}
				slog.Error("not yet ready", slog.Any("err", err))
				// retry after a blip
				time.Sleep(100 * time.Millisecond)
			}

			require.NoError(t, err)
			assert.Equal(t, tc.status, resp.StatusCode)

			respBody, err := io.ReadAll(resp.Body)

			require.NoError(t, err)

			// Here we compare values as JSON, otherwise the test can be flaky
			var expectedJSON, actualJSON map[string]interface{}
			err = json.Unmarshal([]byte(tc.responseBody), &expectedJSON)
			if err == nil {
				err = json.Unmarshal(respBody, &actualJSON)
				require.NoError(t, err)
				assert.Equal(t, expectedJSON, actualJSON)
			} else {
				assert.Equal(t, tc.responseBody, string(respBody))
			}
		})
	}
}

func (s *StartTestSuite) Test_Start_Mode_Config_Errors() {
	t := s.T()
	discoveryEndpoint := mockKeycloakServer()
	originalFilePath := "testdata/all-no-config.yaml"
	testCases := []struct {
		name             string
		changes          map[string]interface{}
		newConfigFile    string
		expErrorContains string
	}{
		{
			"core without sdk_config",
			map[string]interface{}{
				"mode": "core", "server.auth.issuer": discoveryEndpoint.URL,
			},
			"err-core-no-config-*.yaml", "no sdk config provided",
		},
		{
			"kas without sdk_config",
			map[string]interface{}{
				"mode": "kas", "server.auth.issuer": discoveryEndpoint.URL,
			},
			"err-kas-no-config-*.yaml", "no sdk config provided",
		},
		{
			"core with sdk_config without ers endpoint",
			map[string]interface{}{
				"mode": "core", "server.auth.issuer": discoveryEndpoint.URL,
				"sdk_config.client_id": "opentdf", "sdk_config.client_secret": "opentdf",
			},
			"err-core-w-config-no-ers-*.yaml", "entityresolution endpoint must be provided in core mode",
		},
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

// REGRESSION TEST: Ensure extra services don't start in non-matching modes
// This test protects against "fixing" the intentional mode filtering behavior
func (s *StartTestSuite) Test_ExtraService_ModeFiltering_IsIntentional_NotABug() {
	// This test documents that the behavior where extra services don't start
	// in KAS mode (unless explicitly configured) is INTENTIONAL design
	t := s.T()
	otdf, err := mockOpenTDFServer()
	require.NoError(t, err)

	logger, err := logger.NewLogger(logger.Config{Output: "stdout", Level: "info", Type: "json"})
	require.NoError(t, err)

	// Register an extra service with namespace "myextraservice"
	testService, testSpy := mockTestServiceRegistry(mockTestServiceOptions{
		namespace:     "myextraservice",
		serviceName:   "MyExtraService",
		serviceObject: TestService{},
	})

	registry := serviceregistry.NewServiceRegistry()

	// Register using the original WithServices() logic: service.GetNamespace() as mode
	err = registry.RegisterService(testService, testService.GetNamespace()) // "myextraservice"
	require.NoError(t, err)

	// Start services in KAS mode
	cleanup, err := startServices(context.Background(), startServicesParams{
		cfg: &config.Config{
			Mode: []string{"kas"}, // KAS mode only
			Services: map[string]config.ServiceConfig{
				"myextraservice": {},
			},
		},
		otdf:                otdf,
		client:              nil,
		keyManagerFactories: []trust.NamedKeyManagerFactory{},
		logger:              logger,
		reg:                 registry,
		cacheManager:        &cache.Manager{},
	})
	require.NoError(t, err)
	defer cleanup()

	// CRITICAL: The service should NOT start because:
	// - Service is registered with mode "myextraservice"
	// - Config mode is "kas"
	// - "kas" != "myextraservice" → service filtered out
	// This is INTENTIONAL to keep KAS mode lightweight
	require.False(t, testSpy.wasCalled,
		"REGRESSION PROTECTION: Extra service should NOT start in KAS mode. "+
			"This is intentional to maintain backwards compatibility. "+
			"If you're seeing this test fail, you may have 'fixed' behavior that was actually correct. "+
			"Use WithServiceForModes() instead for explicit mode control.")

	// Now test that it DOES work when the mode matches
	registry2 := serviceregistry.NewServiceRegistry()
	testService2, testSpy2 := mockTestServiceRegistry(mockTestServiceOptions{
		namespace:     "myextraservice",
		serviceName:   "MyExtraService2",
		serviceObject: TestService{},
	})
	err = registry2.RegisterService(testService2, testService2.GetNamespace())
	require.NoError(t, err)

	cleanup2, err := startServices(context.Background(), startServicesParams{
		cfg: &config.Config{
			Mode: []string{"myextraservice"}, // Mode matches service namespace
			Services: map[string]config.ServiceConfig{
				"myextraservice": {},
			},
		},
		otdf:                otdf,
		client:              nil,
		keyManagerFactories: []trust.NamedKeyManagerFactory{},
		logger:              logger,
		reg:                 registry2,
		cacheManager:        &cache.Manager{},
	})
	require.NoError(t, err)
	defer cleanup2()

	// This SHOULD work because modes match
	require.True(t, testSpy2.wasCalled,
		"Service should start when config mode matches service namespace")
}

func (s *StartTestSuite) Test_Start_Mode_Config_Success() {
	t := s.T()
	discoveryEndpoint := mockKeycloakServer()
	// require.NoError(t, err)
	originalFilePath := "testdata/all-no-config.yaml"
	testCases := []struct {
		name          string
		changes       map[string]interface{}
		newConfigFile string
	}{
		{
			"all without sdk_config",
			map[string]interface{}{
				"server.auth.issuer": discoveryEndpoint.URL,
			},
			"all-no-config-*.yaml",
		},
		{
			"core,entityresolution without sdk_config",
			map[string]interface{}{
				"mode": "core,entityresolution", "server.auth.issuer": discoveryEndpoint.URL,
			},
			"all-no-config-*.yaml",
		},
		{
			"core,entityresolution,kas without sdk_config",
			map[string]interface{}{
				"mode": "core,entityresolution,kas", "server.auth.issuer": discoveryEndpoint.URL,
			},
			"all-no-config-*.yaml",
		},
		{
			"core with correct sdk_config",
			map[string]interface{}{
				"mode": "core", "server.auth.issuer": discoveryEndpoint.URL,
				"sdk_config.client_id": "opentdf", "sdk_config.client_secret": "opentdf",
				"sdk_config.entityresolution.endpoint": "http://localhost:8181", "sdk_config.entityresolution.plaintext": "true",
			},
			"core-w-config-correct-*.yaml",
		},
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
			// require that it got past the service config and mode setup
			// expected error when trying to establish db connection
			require.ErrorContains(t, err, "failed to connect to database")
		})
	}
}
