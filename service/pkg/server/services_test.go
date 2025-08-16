package server

import (
	"context"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/trust"
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
	serviceHandler     func(ctx context.Context, mux *runtime.ServeMux) error
	dbRegister         serviceregistry.DBRegister
}

const (
	numExpectedPolicyServices                  = 10
	numExpectedEntityResolutionServiceVersions = 2
	numExpectedAuthorizationServiceVersions    = 2
)

func mockTestServiceRegistry(opts mockTestServiceOptions) (serviceregistry.IService, *spyTestService) {
	spy := &spyTestService{}
	mockTestServiceDefaults := mockTestServiceOptions{
		namespace:          "test",
		serviceName:        "TestService",
		serviceHandlerType: (*interface{})(nil),
		serviceHandler: func(_ context.Context, _ *runtime.ServeMux) error {
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

	return &serviceregistry.Service[TestService]{
		ServiceOptions: serviceregistry.ServiceOptions[TestService]{
			Namespace: namespace,
			ServiceDesc: &grpc.ServiceDesc{
				ServiceName: serviceName,
				HandlerType: serviceHandlerType,
			},
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (TestService, serviceregistry.HandlerServer) {
				var ts TestService
				var ok bool
				if ts, ok = opts.serviceObject.(TestService); !ok {
					panic("serviceObject is not a TestService")
				}
				return ts, func(ctx context.Context, mux *runtime.ServeMux) error {
					spy.wasCalled = true
					spy.callParams = append(spy.callParams, srp, ctx, mux, ts)
					return serviceHandler(ctx, mux)
				}
			},

			DB: opts.dbRegister,
		},
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
	ns, err := registry.GetNamespace("health")
	suite.Require().NoError(err)
	suite.Len(ns.Services, 1)
	suite.Equal(modeEssential, ns.Mode)
}

func (suite *ServiceTestSuite) Test_RegisterCoreServices_In_Mode_ALL_Expect_All_Services_Registered() {
	registry := serviceregistry.NewServiceRegistry()
	_, err := registerCoreServices(registry, []string{modeALL})
	suite.Require().NoError(err)

	authz, err := registry.GetNamespace(serviceAuthorization)
	suite.Require().NoError(err)
	suite.Len(authz.Services, numExpectedAuthorizationServiceVersions)
	suite.Equal(modeCore, authz.Mode)

	kas, err := registry.GetNamespace(serviceKAS)
	suite.Require().NoError(err)
	suite.Len(kas.Services, 1)
	suite.Equal(modeCore, kas.Mode)

	policy, err := registry.GetNamespace(servicePolicy)
	suite.Require().NoError(err)
	suite.Len(policy.Services, numExpectedPolicyServices)
	suite.Equal(modeCore, policy.Mode)

	wellKnown, err := registry.GetNamespace(serviceWellKnown)
	suite.Require().NoError(err)
	suite.Len(wellKnown.Services, 1)
	suite.Equal(modeCore, wellKnown.Mode)

	ers, err := registry.GetNamespace(serviceEntityResolution)
	suite.Require().NoError(err)
	suite.Len(ers.Services, numExpectedEntityResolutionServiceVersions)
	suite.Equal(modeCore, ers.Mode)
}

// Every service except kas is registered
func (suite *ServiceTestSuite) Test_RegisterCoreServices_In_Mode_Core_Expect_Core_Services_Registered() {
	registry := serviceregistry.NewServiceRegistry()
	_, err := registerCoreServices(registry, []string{modeCore})
	suite.Require().NoError(err)

	authz, err := registry.GetNamespace(serviceAuthorization)
	suite.Require().NoError(err)
	suite.Len(authz.Services, numExpectedAuthorizationServiceVersions)
	suite.Equal(modeCore, authz.Mode)

	_, err = registry.GetNamespace(serviceKAS)
	suite.Require().Error(err)
	suite.Require().ErrorContains(err, "namespace not found")

	policy, err := registry.GetNamespace(servicePolicy)
	suite.Require().NoError(err)
	suite.Len(policy.Services, numExpectedPolicyServices)
	suite.Equal(modeCore, policy.Mode)

	wellKnown, err := registry.GetNamespace(serviceWellKnown)
	suite.Require().NoError(err)
	suite.Len(wellKnown.Services, 1)
	suite.Equal(modeCore, wellKnown.Mode)
}

// Register core and kas services
func (suite *ServiceTestSuite) Test_RegisterServices_In_Mode_Core_Plus_Kas_Expect_Core_And_Kas_Services_Registered() {
	registry := serviceregistry.NewServiceRegistry()
	_, err := registerCoreServices(registry, []string{modeCore, modeKAS})
	suite.Require().NoError(err)

	authz, err := registry.GetNamespace(serviceAuthorization)
	suite.Require().NoError(err)
	suite.Len(authz.Services, numExpectedAuthorizationServiceVersions)
	suite.Equal(modeCore, authz.Mode)

	kas, err := registry.GetNamespace(serviceKAS)
	suite.Require().NoError(err)
	suite.Len(kas.Services, 1)
	suite.Equal(modeKAS, kas.Mode)

	policy, err := registry.GetNamespace(servicePolicy)
	suite.Require().NoError(err)
	suite.Len(policy.Services, numExpectedPolicyServices)
	suite.Equal(modeCore, policy.Mode)

	wellKnown, err := registry.GetNamespace(serviceWellKnown)
	suite.Require().NoError(err)
	suite.Len(wellKnown.Services, 1)
	suite.Equal(modeCore, wellKnown.Mode)
}

// Register core and kas and ERS services
func (suite *ServiceTestSuite) Test_RegisterServices_In_Mode_Core_Plus_Kas_Expect_Core_And_Kas_And_ERS_Services_Registered() {
	registry := serviceregistry.NewServiceRegistry()
	_, err := registerCoreServices(registry, []string{modeCore, modeKAS, modeERS})
	suite.Require().NoError(err)

	authz, err := registry.GetNamespace(serviceAuthorization)
	suite.Require().NoError(err)
	suite.Len(authz.Services, numExpectedAuthorizationServiceVersions)
	suite.Equal(modeCore, authz.Mode)

	kas, err := registry.GetNamespace(serviceKAS)
	suite.Require().NoError(err)
	suite.Len(kas.Services, 1)
	suite.Equal(modeKAS, kas.Mode)

	policy, err := registry.GetNamespace(servicePolicy)
	suite.Require().NoError(err)
	suite.Len(policy.Services, numExpectedPolicyServices)
	suite.Equal(modeCore, policy.Mode)

	wellKnown, err := registry.GetNamespace(serviceWellKnown)
	suite.Require().NoError(err)
	suite.Len(wellKnown.Services, 1)
	suite.Equal(modeCore, wellKnown.Mode)

	ers, err := registry.GetNamespace(serviceEntityResolution)
	suite.Require().NoError(err)
	suite.Len(ers.Services, numExpectedEntityResolutionServiceVersions)
	suite.Equal(modeERS, ers.Mode)
}

func (suite *ServiceTestSuite) TestStartServicesWithVariousCases() {
	ctx := context.Background()

	registry := serviceregistry.NewServiceRegistry()

	// Test service which will be enabled
	registerTest, testSpy := mockTestServiceRegistry(mockTestServiceOptions{
		serviceObject: TestService{},
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

	cleanup, err := startServices(ctx, startServicesParams{
		cfg: &config.Config{
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
			Services: map[string]config.ServiceConfig{
				"test":         {},
				"test_with_db": {},
				"foobar":       {},
			},
		},
		otdf:                otdf,
		client:              nil,
		keyManagerFactories: []trust.NamedKeyManagerFactory{},
		logger:              newLogger,
		reg:                 registry,
	})

	// call cleanup function
	defer cleanup()

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
