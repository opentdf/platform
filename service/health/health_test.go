package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/grpchealth"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type pingOnlyPGX struct {
	db.PgxIface
	ping func(context.Context) error
}

func (p pingOnlyPGX) Ping(ctx context.Context) error {
	return p.ping(ctx)
}

func TestDatabaseReadinessAffectsOnlyReadinessEndpoint(t *testing.T) {
	ResetReadinessChecks()
	t.Cleanup(ResetReadinessChecks)

	pingErr := error(nil)
	client := db.Client{Pgx: pingOnlyPGX{
		ping: func(context.Context) error { return pingErr },
	}}
	require.NoError(t, RegisterReadinessCheck("policy", client.ReadinessCheck(databaseCheckTimeout)))

	lgr, err := logger.NewLogger(logger.Config{Output: "stdout", Level: "info", Type: "json"})
	require.NoError(t, err)
	registration := NewRegistration()
	_, registerHandler := registration.RegisterFunc(serviceregistry.RegistrationParams{
		Logger: lgr,
		WellKnownConfig: func(string, any) error {
			return nil
		},
	})
	mux := http.NewServeMux()
	require.NoError(t, registerHandler(t.Context(), mux))

	assertStatus := func(path string, want int) {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		assert.Equal(t, want, response.Code)
	}

	assertStatus("/healthz?service=all", http.StatusOK)

	// Simulate a database connection that was healthy at startup and then dropped.
	pingErr = assert.AnError
	assertStatus("/healthz?service=all", http.StatusServiceUnavailable)
	assertStatus("/healthz", http.StatusOK)
}

const databaseCheckTimeout = 100 * time.Millisecond

type HealthCheckSuite struct {
	suite.Suite
}

func (s *HealthCheckSuite) SetupSuite() {
}

func (s *HealthCheckSuite) TearDownTest() {
	// Because its a global we need to reset it after each test
	ResetReadinessChecks()
}

func TestHealthCheckSuite(t *testing.T) {
	suite.Run(t, new(HealthCheckSuite))
}

func (s *HealthCheckSuite) TestRegisterReadinessCheck() {
	// TestRegisterReadinessCheck tests the registration of a health check.

	// Register the health check.
	err := RegisterReadinessCheck("service_1", func(context.Context) error {
		return nil
	})
	s.Require().NoError(err)

	// Check the health check.
	err = serviceHealthChecks["service_1"](s.T().Context())
	s.NoError(err)
}

func (s *HealthCheckSuite) TestRegisterReadinessCheckCombinesChecksForNamespace() {
	calls := make([]string, 0, 2)
	err := RegisterReadinessCheck("service_2", func(context.Context) error {
		calls = append(calls, "first")
		return nil
	})
	s.Require().NoError(err)

	err = RegisterReadinessCheck("service_2", func(context.Context) error {
		calls = append(calls, "second")
		return nil
	})
	s.Require().NoError(err)

	err = serviceHealthChecks["service_2"](s.T().Context())
	s.Require().NoError(err)
	s.Equal([]string{"first", "second"}, calls)
}

func (s *HealthCheckSuite) TestRegisterReadinessCheckReturnsFirstError() {
	secondCalled := false
	err := RegisterReadinessCheck("service_2", func(context.Context) error {
		return assert.AnError
	})
	s.Require().NoError(err)

	err = RegisterReadinessCheck("service_2", func(context.Context) error {
		secondCalled = true
		return nil
	})
	s.Require().NoError(err)

	err = serviceHealthChecks["service_2"](s.T().Context())
	s.Require().ErrorIs(err, assert.AnError)
	s.False(secondCalled)
}

func (s *HealthCheckSuite) TestCheck() {
	// TestCheck tests the health check.
	hs := &HealthService{}

	// Register the health check.
	err := RegisterReadinessCheck("success_3", func(context.Context) error {
		return nil
	})
	s.Require().NoError(err)

	err = RegisterReadinessCheck("success_4", func(context.Context) error {
		return nil
	})
	s.Require().NoError(err)

	// Check the health check.
	result, err := hs.Check(s.T().Context(), &grpchealth.CheckRequest{
		Service: "all",
	})
	s.Require().NoError(err)
	s.Equal(grpchealth.StatusServing, result.Status)
}

func (s *HealthCheckSuite) TestCheckServiceUnknown() {
	// TestCheckServiceUnknown tests the health check with an unknown service.
	hs := &HealthService{}

	// Check the health check.
	result, err := hs.Check(s.T().Context(), &grpchealth.CheckRequest{
		Service: "unknown",
	})
	s.Require().NoError(err)
	s.Equal(grpchealth.StatusUnknown, result.Status)
}

func (s *HealthCheckSuite) TestCheckNotServing() {
	// TestCheckNotServing tests the health check when a service is not serving.
	lgr, err := logger.NewLogger(logger.Config{
		Output: "stdout",
		Level:  "info",
		Type:   "json",
	})
	s.Require().NoError(err)

	hs := &HealthService{
		logger: lgr,
	}

	// Register the health check.
	err = RegisterReadinessCheck("failing", func(context.Context) error {
		return assert.AnError
	})

	s.Require().NoError(err)

	// Check the health check.
	result, err := hs.Check(s.T().Context(), &grpchealth.CheckRequest{
		Service: "failing",
	})
	s.Require().NoError(err)
	s.Equal(grpchealth.StatusNotServing, result.Status)
}
