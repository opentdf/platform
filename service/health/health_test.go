package health

import (
	"context"
	"testing"

	"connectrpc.com/grpchealth"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
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
	result, err := hs.Check(context.Background(), &grpchealth.CheckRequest{
		Service: "all",
	})
	s.Require().NoError(err)
	s.Equal(grpchealth.StatusServing, result.Status)
}

func (s *HealthCheckSuite) TestCheckServiceUnknown() {
	// TestCheckServiceUnknown tests the health check with an unknown service.
	hs := &HealthService{}

	// Check the health check.
	result, err := hs.Check(context.Background(), &grpchealth.CheckRequest{
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
	result, err := hs.Check(context.Background(), &grpchealth.CheckRequest{
		Service: "failing",
	})
	s.Require().NoError(err)
	s.Equal(grpchealth.StatusNotServing, result.Status)
}
