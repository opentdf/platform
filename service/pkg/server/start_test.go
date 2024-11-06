package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

func mockOpenTDFServer() (*server.OpenTDFServer, error) {
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
	ts := &TestService{}
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
