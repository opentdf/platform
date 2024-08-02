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
	service := registry.GetService("health", "grpc.health.v1.Health")
	suite.Require().NotNil(service)
	suite.Equal("grpc.health.v1.Health", service.ServiceDesc.ServiceName)
}

func (suite *ServiceTestSuite) Test_RegisterCoreServices_In_Mode_ALL_Expect_All_Services_Registered() {
	registry := serviceregistry.NewServiceRegistry()
	_, err := registerCoreServices(registry, []string{"all"})
	suite.Require().NoError(err)

	authz := registry.GetService("authorization", "authorization.AuthorizationService")
	suite.Require().NotNil(authz)
	suite.Equal("authorization.AuthorizationService", authz.ServiceDesc.ServiceName)

	kas := registry.GetService("kas", "kas.AccessService")
	suite.Require().NotNil(kas)
	suite.Equal("kas.AccessService", kas.ServiceDesc.ServiceName)

	attr := registry.GetService("policy", "policy.attributes.AttributesService")
	suite.Require().NotNil(attr)
	suite.Equal("policy.attributes.AttributesService", attr.ServiceDesc.ServiceName)

	namespace := registry.GetService("policy", "policy.namespaces.NamespaceService")
	suite.Require().NotNil(namespace)
	suite.Equal("policy.namespaces.NamespaceService", namespace.ServiceDesc.ServiceName)

	resourcemapping := registry.GetService("policy", "policy.resourcemapping.ResourceMappingService")
	suite.Require().NotNil(resourcemapping)
	suite.Equal("policy.resourcemapping.ResourceMappingService", resourcemapping.ServiceDesc.ServiceName)

	subjectmapping := registry.GetService("policy", "policy.subjectmapping.SubjectMappingService")
	suite.Require().NotNil(subjectmapping)
	suite.Equal("policy.subjectmapping.SubjectMappingService", subjectmapping.ServiceDesc.ServiceName)

	kasregistry := registry.GetService("policy", "policy.kasregistry.KeyAccessServerRegistryService")
	suite.Require().NotNil(kasregistry)
	suite.Equal("policy.kasregistry.KeyAccessServerRegistryService", kasregistry.ServiceDesc.ServiceName)

	unsafe := registry.GetService("policy", "policy.unsafe.UnsafeService")
	suite.Require().NotNil(unsafe)
	suite.Equal("policy.unsafe.UnsafeService", unsafe.ServiceDesc.ServiceName)

	wellKnown := registry.GetService("wellknown", "wellknownconfiguration.WellKnownService")
	suite.Require().NotNil(wellKnown)
	suite.Equal("wellknownconfiguration.WellKnownService", wellKnown.ServiceDesc.ServiceName)

	ers := registry.GetService("entityresolution", "entityresolution.EntityResolutionService")
	suite.Require().NotNil(ers)
	suite.Equal("entityresolution.EntityResolutionService", ers.ServiceDesc.ServiceName)
}

// Every service except kas is registered
func (suite *ServiceTestSuite) Test_RegisterCoreServices_In_Mode_Core_Expect_Core_Services_Registered() {
	registry := serviceregistry.NewServiceRegistry()
	_, err := registerCoreServices(registry, []string{"core"})
	suite.Require().NoError(err)

	authz := registry.GetService("authorization", "authorization.AuthorizationService")
	suite.Require().NotNil(authz)
	suite.Equal("authorization.AuthorizationService", authz.ServiceDesc.ServiceName)

	wellKnown := registry.GetService("wellknown", "wellknownconfiguration.WellKnownService")
	suite.Require().NotNil(wellKnown)
	suite.Equal("wellknownconfiguration.WellKnownService", wellKnown.ServiceDesc.ServiceName)

	ers := registry.GetService("entityresolution", "entityresolution.EntityResolutionService")
	suite.Require().NotNil(ers)
	suite.Equal("entityresolution.EntityResolutionService", ers.ServiceDesc.ServiceName)

	attr := registry.GetService("policy", "policy.attributes.AttributesService")
	suite.Require().NotNil(attr)
	suite.Equal("policy.attributes.AttributesService", attr.ServiceDesc.ServiceName)

	namespace := registry.GetService("policy", "policy.namespaces.NamespaceService")
	suite.Require().NotNil(namespace)
	suite.Equal("policy.namespaces.NamespaceService", namespace.ServiceDesc.ServiceName)

	resourcemapping := registry.GetService("policy", "policy.resourcemapping.ResourceMappingService")
	suite.Require().NotNil(resourcemapping)
	suite.Equal("policy.resourcemapping.ResourceMappingService", resourcemapping.ServiceDesc.ServiceName)

	subjectmapping := registry.GetService("policy", "policy.subjectmapping.SubjectMappingService")
	suite.Require().NotNil(subjectmapping)
	suite.Equal("policy.subjectmapping.SubjectMappingService", subjectmapping.ServiceDesc.ServiceName)

	kasregistry := registry.GetService("policy", "policy.kasregistry.KeyAccessServerRegistryService")
	suite.Require().NotNil(kasregistry)
	suite.Equal("policy.kasregistry.KeyAccessServerRegistryService", kasregistry.ServiceDesc.ServiceName)

	unsafe := registry.GetService("policy", "policy.unsafe.UnsafeService")
	suite.Require().NotNil(unsafe)
	suite.Equal("policy.unsafe.UnsafeService", unsafe.ServiceDesc.ServiceName)

	kas := registry.GetService("kas", "kas.AccessService")
	suite.Require().Nil(kas)
}

func (suite *ServiceTestSuite) TestStartServicesWithVariousCases() {
	ctx := context.Background()

	registry := serviceregistry.NewServiceRegistry()

	// Test service which will be enabled
	registerTest, testSpy := mockTestServiceRegistry(mockTestServiceOptions{})
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
