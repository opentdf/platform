package server

import (
	"context"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/service/internal/config"
	"github.com/opentdf/platform/service/internal/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
)

type spyTestService struct {
	wasCalled  bool
	callParams []any
}

type mockTestServiceOptions struct {
	namespace          string
	serviceName        string
	serviceHandlerType any
	serviceObject      any
	serviceHandler     func(ctx context.Context, mux *runtime.ServeMux, server any) error
	dbRegister         serviceregistry.DBRegister
}

func mockTestServiceRegistry(opts mockTestServiceOptions) (func() error, *spyTestService) {
	spy := &spyTestService{}
	mockTestServiceDefaults := mockTestServiceOptions{
		namespace:          "test",
		serviceName:        "TestService",
		serviceHandlerType: (*interface{})(nil),
		serviceHandler: func(_ context.Context, _ *runtime.ServeMux, _ any) error {
			return nil
		},
	}

	namespace := mockTestServiceDefaults.namespace
	serviceName := mockTestServiceDefaults.serviceName
	serviceHandler := mockTestServiceDefaults.serviceHandler
	serviceHandlerType := mockTestServiceDefaults.serviceHandlerType

	if opts.namespace != "" {
		namespace = opts.namespace
	}
	if opts.serviceName != "" {
		serviceName = opts.serviceName
	}
	if opts.serviceHandler != nil {
		serviceHandler = opts.serviceHandler
	}

	return func() error {
		return serviceregistry.RegisterService(serviceregistry.Registration{
			Namespace: namespace,
			ServiceDesc: &grpc.ServiceDesc{
				ServiceName: serviceName,
				HandlerType: serviceHandlerType,
			},
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
				return opts.serviceObject, func(ctx context.Context, mux *runtime.ServeMux, server any) error {
					spy.wasCalled = true
					spy.callParams = append(spy.callParams, srp, ctx, mux, server)
					return serviceHandler(ctx, mux, server)
				}
			},

			DB: opts.dbRegister,
		})
	}, spy
}

type ServiceTestSuite struct {
	suite.Suite
}

func TestServiceTestSuite(t *testing.T) {
	suite.Run(t, new(StartTestSuite))
}

func (suite *ServiceTestSuite) BeforeTest(_, _ string) {
	serviceregistry.RegisteredServices = make(serviceregistry.NamespaceMap)
}

func (suite *ServiceTestSuite) TestRegisterServicesIsSuccessful() {
	t := suite.T()
	err := registerServices()
	require.NoError(t, err)
}

func (suite *ServiceTestSuite) TestStartServicesWithVariousCases() {
	t := suite.T()
	ctx := context.Background()

	// Test service which will be enabled
	registerTest, testSpy := mockTestServiceRegistry(mockTestServiceOptions{})
	err := registerTest()
	require.NoError(t, err)

	// Test service with DB which will be enabled
	registerTestWithDB, testWithDBSpy := mockTestServiceRegistry(mockTestServiceOptions{
		namespace:   "test_with_db",
		serviceName: "TestWithDBService",
		dbRegister: serviceregistry.DBRegister{
			Required: true,
		},
	})
	err = registerTestWithDB()
	require.NoError(t, err)

	// FooBar service which won't be enabled
	registerFoobar, foobarSpy := mockTestServiceRegistry(mockTestServiceOptions{
		namespace:   "foobar",
		serviceName: "FooBarService",
	})
	err = registerFoobar()
	require.NoError(t, err)

	otdf, err := mockOpenTDFServer()
	require.NoError(t, err)

	logger, err := logger.NewLogger(logger.Config{Output: "stdout", Level: "info", Type: "json"})
	require.NoError(t, err)

	cF, services, err := startServices(ctx, config.Config{
		DB: db.Config{
			Host:          "localhost",
			Port:          5432,
			Database:      "opentdf",
			User:          "",
			Password:      "",
			RunMigrations: false,
		},
		Services: map[string]serviceregistry.ServiceConfig{
			"test": {
				Enabled: true,
			},
			"test_with_db": {
				Enabled: true,
			},
			"foobar": {
				Enabled: false,
			},
		},
	}, otdf, nil, nil, logger)
	require.NoError(t, err)
	require.NotNil(t, cF)
	assert.Lenf(t, services, 2, "expected 2 services enabled, got %d", len(services))

	// Expecting a test service with no DBClient
	assert.True(t, testSpy.wasCalled)
	regParams, ok := testSpy.callParams[0].(serviceregistry.RegistrationParams)
	require.True(t, ok)
	assert.Nil(t, regParams.DBClient)

	// Expecting a test service with a DBClient
	assert.True(t, testWithDBSpy.wasCalled)
	regParams, ok = testWithDBSpy.callParams[0].(serviceregistry.RegistrationParams)
	require.True(t, ok)
	assert.NotNil(t, regParams.DBClient)

	// Not expecting a foobar service since it's not enabled
	assert.False(t, foobarSpy.wasCalled)

	// call close function
	cF()
}
