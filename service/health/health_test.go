package health

import (
	"context"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/health/grpc_health_v1"
)

type HealthCheckSuite struct {
	suite.Suite
}

func (s *HealthCheckSuite) SetupSuite() {
}

func (s *HealthCheckSuite) TearDownTest() {
	// Because its a global we need to reset it after each test
	serviceHealthChecks = make(map[string]func(context.Context) error)
}

func (s *HealthCheckSuite) TestRegisterReadinessCheck() {
	// TestRegisterReadinessCheck tests the registration of a health check.

	// Register the health check.
	err := RegisterReadinessCheck("service_1", func(context.Context) error {
		return nil
	})
	s.Require().NoError(err)

	// Check the health check.
	err = serviceHealthChecks["service_1"](context.Background())
	s.NoError(err)
}

func (s *HealthCheckSuite) TestRegisterHealthCheckAlreadyExists() {
	// TestRegisterReadinessCheckAlreadyExists tests the registration of a health check that already exists.

	// Register the health check.
	err := RegisterReadinessCheck("service_2", func(context.Context) error {
		return nil
	})
	s.Require().NoError(err)

	// Check the health check.
	err = RegisterReadinessCheck("service_2", func(context.Context) error {
		return nil
	})

	s.Error(err)
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
	result, err := hs.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{
		Service: "all",
	})
	s.Require().NoError(err)
	s.Equal("SERVING", result.GetStatus().String())
}

func (s *HealthCheckSuite) TestCheckServiceUnknown() {
	// TestCheckServiceUnknown tests the health check with an unknown service.
	hs := &HealthService{}

	// Check the health check.
	result, err := hs.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{
		Service: "unknown",
	})
	s.Require().NoError(err)
	s.Equal("SERVICE_UNKNOWN", result.GetStatus().String())
}

func (s *HealthCheckSuite) TestCheckNotServing() {
	// TestCheckNotServing tests the health check when a service is not serving.
	hs := &HealthService{}

	// Register the health check.
	err := RegisterReadinessCheck("failing", func(context.Context) error {
		return assert.AnError
	})

	s.Require().NoError(err)

	// Check the health check.
	result, err := hs.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{
		Service: "failing",
	})
	s.Require().NoError(err)
	s.Equal("NOT_SERVING", result.GetStatus().String())
}
