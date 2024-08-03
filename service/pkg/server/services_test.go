package server

import (
	"context"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/service/internal/config"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
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

func mockTestServiceRegistry(opts mockTestServiceOptions) (serviceregistry.Registration, *spyTestService) {
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

	return serviceregistry.Registration{
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
	}, spy
}

type ServiceTestSuite struct {
	suite.Suite
}

func TestServiceTestSuite(t *testing.T) {
	suite.Run(t, new(ServiceTestSuite))
}

func (suite *ServiceTestSuite) TestRegisterEssentialServiceRegistrationIsSuccessful() {
	registry := serviceregistry.NewServiceRegistry()
	err := registerEssentialServices(registry)
	suite.Require().NoError(err)
	service := registry.TotalRegisteredServices("health")
	suite.Equal(1, service)
}

func (suite *ServiceTestSuite) Test_RegisterCoreServices_In_Mode_ALL_Expect_All_Services_Registered() {
	registry := serviceregistry.NewServiceRegistry()
	_, err := registerCoreServices(registry, []string{"all"})
	suite.Require().NoError(err)

	authz := registry.TotalRegisteredServices("authorization")
	suite.Equal(1, authz)

	kas := registry.TotalRegisteredServices("kas")
	suite.Equal(1, kas)

	policy := registry.TotalRegisteredServices("policy")
	suite.Equal(6, policy)

	wellKnown := registry.TotalRegisteredServices("wellknown")
	suite.Equal(1, wellKnown)

	ers := registry.TotalRegisteredServices("entityresolution")
	suite.Equal(1, ers)
}

// Every service except kas is registered
func (suite *ServiceTestSuite) Test_RegisterCoreServices_In_Mode_Core_Expect_Core_Services_Registered() {
	registry := serviceregistry.NewServiceRegistry()
	_, err := registerCoreServices(registry, []string{"core"})
	suite.Require().NoError(err)

	authz := registry.TotalRegisteredServices("authorization")
	suite.Equal(1, authz)

	kas := registry.TotalRegisteredServices("kas")
	suite.Equal(0, kas)

	policy := registry.TotalRegisteredServices("policy")
	suite.Equal(6, policy)

	wellKnown := registry.TotalRegisteredServices("wellknown")
	suite.Equal(1, wellKnown)

	ers := registry.TotalRegisteredServices("entityresolution")
	suite.Equal(1, ers)
}

func (suite *ServiceTestSuite) TestStartServicesWithVariousCases() {
	ctx := context.Background()

	registry := serviceregistry.NewServiceRegistry()

	// Test service which will be enabled
	registerTest, testSpy := mockTestServiceRegistry(mockTestServiceOptions{
		serviceObject: &TestService{},
	})
	err := registry.RegisterService(registerTest, "test")
	suite.Require().NoError(err)

	/*
	   Configuring test with db now tries to connect to database.
	*/
	// Test service with DB which will be enabled
	// registerTestWithDB, testWithDBSpy := mockTestServiceRegistry(mockTestServiceOptions{
	// 	namespace:   "test_with_db",
	// 	serviceName: "TestWithDBService",
	// 	dbRegister: serviceregistry.DBRegister{
	// 		Required: true,
	// 	},
	// })
	// err = registry.RegisterService(registerTestWithDB, "test_with_db")
	// require.NoError(t, err)

	// FooBar service which won't be enabled
	registerFoobar, foobarSpy := mockTestServiceRegistry(mockTestServiceOptions{
		namespace:   "foobar",
		serviceName: "FooBarService",
	})
	err = registry.RegisterService(registerFoobar, "foobar")
	suite.Require().NoError(err)

	otdf, err := mockOpenTDFServer()
	suite.Require().NoError(err)

	newLogger, err := logger.NewLogger(logger.Config{Output: "stdout", Level: "info", Type: "json"})
	suite.Require().NoError(err)

	err = startServices(ctx, config.Config{
		Mode:   []string{"test"},
		Logger: logger.Config{Output: "stdout", Level: "info", Type: "json"},
		// DB: db.Config{
		// 	Host:          "localhost",
		// 	Port:          5432,
		// 	Database:      "opentdf",
		// 	User:          "",
		// 	Password:      "",
		// 	RunMigrations: false,
		// },
		Services: map[string]serviceregistry.ServiceConfig{
			"test":         {},
			"test_with_db": {},
			"foobar":       {},
		},
	}, otdf, nil, newLogger, registry)
	suite.Require().NoError(err)
	// require.NotNil(t, cF)
	// assert.Lenf(t, services, 2, "expected 2 services enabled, got %d", len(services))

	// Expecting a test service with no DBClient
	suite.True(testSpy.wasCalled)
	regParams, ok := testSpy.callParams[0].(serviceregistry.RegistrationParams)
	suite.Require().True(ok)
	suite.Nil(regParams.DBClient)

	// Expecting a test service with a DBClient
	// assert.True(t, testWithDBSpy.wasCalled)
	// regParams, ok = testWithDBSpy.callParams[0].(serviceregistry.RegistrationParams)
	// require.True(t, ok)
	// assert.NotNil(t, regParams.DBClient)

	// Not expecting a foobar service since it's not enabled
	suite.False(foobarSpy.wasCalled)

	// call close function
	registry.Shutdown()
}
