package server

import (
	"context"
	"embed"
	"net/http"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/service/internal/server"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
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
	err := RegisterEssentialServices(registry)
	suite.Require().NoError(err)
	ns, err := registry.GetNamespace("health")
	suite.Require().NoError(err)
	suite.Len(ns.Services, 1)
	suite.Equal(string(serviceregistry.ModeEssential), ns.Mode)
}

func (suite *ServiceTestSuite) Test_RegisterCoreServices_In_Mode_ALL_Expect_All_Services_Registered() {
	registry := serviceregistry.NewServiceRegistry()
	_, err := RegisterCoreServices(registry, []serviceregistry.ModeName{serviceregistry.ModeALL})
	suite.Require().NoError(err)

	authz, err := registry.GetNamespace(ServiceAuthorization.String())
	suite.Require().NoError(err)
	suite.Len(authz.Services, numExpectedAuthorizationServiceVersions)
	suite.Equal(serviceregistry.ModeALL.String(), authz.Mode)

	kas, err := registry.GetNamespace(ServiceKAS.String())
	suite.Require().NoError(err)
	suite.Len(kas.Services, 1)
	suite.Equal(serviceregistry.ModeALL.String(), kas.Mode)

	policy, err := registry.GetNamespace(ServicePolicy.String())
	suite.Require().NoError(err)
	suite.Len(policy.Services, numExpectedPolicyServices)
	suite.Equal(serviceregistry.ModeALL.String(), policy.Mode)

	wellKnown, err := registry.GetNamespace(ServiceWellKnown.String())
	suite.Require().NoError(err)
	suite.Len(wellKnown.Services, 1)
	suite.Equal(serviceregistry.ModeALL.String(), wellKnown.Mode)

	ers, err := registry.GetNamespace(ServiceEntityResolution.String())
	suite.Require().NoError(err)
	suite.Len(ers.Services, numExpectedEntityResolutionServiceVersions)
	suite.Equal(serviceregistry.ModeALL.String(), ers.Mode)
}

// Every service except kas is registered
func (suite *ServiceTestSuite) Test_RegisterCoreServices_In_Mode_Core_Expect_Core_Services_Registered() {
	registry := serviceregistry.NewServiceRegistry()
	_, err := RegisterCoreServices(registry, []serviceregistry.ModeName{serviceregistry.ModeCore})
	suite.Require().NoError(err)

	authz, err := registry.GetNamespace(ServiceAuthorization.String())
	suite.Require().NoError(err)
	suite.Len(authz.Services, numExpectedAuthorizationServiceVersions)
	suite.Equal(serviceregistry.ModeCore.String(), authz.Mode)

	_, err = registry.GetNamespace(ServiceKAS.String())
	suite.Require().Error(err)
	suite.Require().ErrorContains(err, "namespace not found")

	policy, err := registry.GetNamespace(ServicePolicy.String())
	suite.Require().NoError(err)
	suite.Len(policy.Services, numExpectedPolicyServices)
	suite.Equal(serviceregistry.ModeCore.String(), policy.Mode)

	wellKnown, err := registry.GetNamespace(ServiceWellKnown.String())
	suite.Require().NoError(err)
	suite.Len(wellKnown.Services, 1)
	suite.Equal(serviceregistry.ModeCore.String(), wellKnown.Mode)
}

// Register core and kas services
func (suite *ServiceTestSuite) Test_RegisterServices_In_Mode_Core_Plus_Kas_Expect_Core_And_Kas_Services_Registered() {
	registry := serviceregistry.NewServiceRegistry()
	_, err := RegisterCoreServices(registry, []serviceregistry.ModeName{serviceregistry.ModeCore, serviceregistry.ModeKAS})
	suite.Require().NoError(err)

	authz, err := registry.GetNamespace(ServiceAuthorization.String())
	suite.Require().NoError(err)
	suite.Len(authz.Services, numExpectedAuthorizationServiceVersions)
	suite.Equal(serviceregistry.ModeCore.String(), authz.Mode)

	kas, err := registry.GetNamespace(ServiceKAS.String())
	suite.Require().NoError(err)
	suite.Len(kas.Services, 1)
	suite.Equal(serviceregistry.ModeKAS.String(), kas.Mode)

	policy, err := registry.GetNamespace(ServicePolicy.String())
	suite.Require().NoError(err)
	suite.Len(policy.Services, numExpectedPolicyServices)
	suite.Equal(serviceregistry.ModeCore.String(), policy.Mode)

	wellKnown, err := registry.GetNamespace(ServiceWellKnown.String())
	suite.Require().NoError(err)
	suite.Len(wellKnown.Services, 1)
	suite.Equal(serviceregistry.ModeCore.String(), wellKnown.Mode)
}

// Register core and kas and ERS services
func (suite *ServiceTestSuite) Test_RegisterServices_In_Mode_Core_Plus_Kas_Expect_Core_And_Kas_And_ERS_Services_Registered() {
	registry := serviceregistry.NewServiceRegistry()
	_, err := RegisterCoreServices(registry, []serviceregistry.ModeName{serviceregistry.ModeCore, serviceregistry.ModeKAS, serviceregistry.ModeERS})
	suite.Require().NoError(err)

	authz, err := registry.GetNamespace(ServiceAuthorization.String())
	suite.Require().NoError(err)
	suite.Len(authz.Services, numExpectedAuthorizationServiceVersions)
	suite.Equal(serviceregistry.ModeCore.String(), authz.Mode)

	kas, err := registry.GetNamespace(ServiceKAS.String())
	suite.Require().NoError(err)
	suite.Len(kas.Services, 1)
	suite.Equal(serviceregistry.ModeKAS.String(), kas.Mode)

	policy, err := registry.GetNamespace(ServicePolicy.String())
	suite.Require().NoError(err)
	suite.Len(policy.Services, numExpectedPolicyServices)
	suite.Equal(serviceregistry.ModeCore.String(), policy.Mode)

	wellKnown, err := registry.GetNamespace(ServiceWellKnown.String())
	suite.Require().NoError(err)
	suite.Len(wellKnown.Services, 1)
	suite.Equal(serviceregistry.ModeCore.String(), wellKnown.Mode)

	ers, err := registry.GetNamespace(ServiceEntityResolution.String())
	suite.Require().NoError(err)
	suite.Len(ers.Services, numExpectedEntityResolutionServiceVersions)
	suite.Equal(serviceregistry.ModeERS.String(), ers.Mode)
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
		otdf:   otdf,
		client: nil,
		logger: newLogger,
		reg:    registry,
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

// Test service negation functionality
func (suite *ServiceTestSuite) TestRegisterCoreServices_WithNegation() {
	testCases := []struct {
		name                  string
		modes                 []serviceregistry.ModeName
		expectedServices      []string
		excludedServices      []string // Services that MUST NOT be in the registry
		shouldError           bool
		expectedErrorContains string
	}{
		{
			name:             "All_Minus_KAS",
			modes:            []serviceregistry.ModeName{"all", "-kas"},
			expectedServices: []string{"policy", "authorization", "wellknown", "entityresolution"},
			excludedServices: []string{"kas"},
		},
		{
			name:             "All_Minus_EntityResolution",
			modes:            []serviceregistry.ModeName{"all", "-entityresolution"},
			expectedServices: []string{"policy", "authorization", "kas", "wellknown"},
			excludedServices: []string{"entityresolution"},
		},
		{
			name:             "All_Minus_Multiple_Services",
			modes:            []serviceregistry.ModeName{"all", "-kas", "-entityresolution"},
			expectedServices: []string{"policy", "authorization", "wellknown"},
			excludedServices: []string{"kas", "entityresolution"},
		},
		{
			name:             "Core_Minus_Policy",
			modes:            []serviceregistry.ModeName{"core", "-policy"},
			expectedServices: []string{"authorization", "wellknown"},
			excludedServices: []string{"policy", "kas", "entityresolution"},
		},
		{
			name:             "Core_Minus_Authorization",
			modes:            []serviceregistry.ModeName{"core", "-authorization"},
			expectedServices: []string{"policy", "wellknown"},
			excludedServices: []string{"authorization", "kas", "entityresolution"},
		},
		{
			name:             "Core_Minus_WellKnown",
			modes:            []serviceregistry.ModeName{"core", "-wellknown"},
			expectedServices: []string{"policy", "authorization"},
			excludedServices: []string{"wellknown", "kas", "entityresolution"},
		},
		{
			name:             "All_Minus_Policy_And_Authorization",
			modes:            []serviceregistry.ModeName{"all", "-policy", "-authorization"},
			expectedServices: []string{"kas", "wellknown", "entityresolution"},
			excludedServices: []string{"policy", "authorization"},
		},
		{
			name:             "All_Minus_Three_Services",
			modes:            []serviceregistry.ModeName{"all", "-kas", "-entityresolution", "-policy"},
			expectedServices: []string{"authorization", "wellknown"},
			excludedServices: []string{"kas", "entityresolution", "policy"},
		},
		{
			name:             "Core_Minus_Multiple_Services",
			modes:            []serviceregistry.ModeName{"core", "-policy", "-wellknown"},
			expectedServices: []string{"authorization"},
			excludedServices: []string{"policy", "wellknown", "kas", "entityresolution"},
		},
		{
			name:                  "Negation_Without_Base_Mode",
			modes:                 []serviceregistry.ModeName{"-kas"},
			shouldError:           true,
			expectedErrorContains: "cannot exclude services without including base modes",
		},
		{
			name:                  "Invalid_Empty_Negation",
			modes:                 []serviceregistry.ModeName{"all", "-"},
			shouldError:           true,
			expectedErrorContains: "empty service name after '-'",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			t := suite.T()
			registry := serviceregistry.NewServiceRegistry()

			registeredServices, err := RegisterCoreServices(registry, tc.modes)

			if tc.shouldError {
				suite.Require().Error(err)
				if tc.expectedErrorContains != "" {
					suite.Contains(err.Error(), tc.expectedErrorContains)
				}
				return
			}

			modeStrings := make([]string, len(tc.modes))
			for i, m := range tc.modes {
				modeStrings[i] = m.String()
			}

			suite.Require().NoError(err)
			suite.ElementsMatch(tc.expectedServices, registeredServices)

			// Verify expected services ARE registered in the registry
			for _, expectedService := range tc.expectedServices {
				ns, err := registry.GetNamespace(expectedService)
				suite.Require().NoError(err, "Expected service '%s' should be registered", expectedService)
				if err == nil {
					suite.NotEmpty(ns.Services, "Service '%s' should have implementations", expectedService)
				}
			}

			// Verify excluded services are NOT in the registry
			for _, excludedService := range tc.excludedServices {
				_, err := registry.GetNamespace(excludedService)
				suite.Require().Error(err, "Service '%s' should NOT be registered", excludedService)
				if err != nil {
					suite.Contains(err.Error(), "namespace not found",
						"Should get 'namespace not found' for excluded service '%s'", excludedService)
					t.Logf("✓ Service '%s' correctly excluded", excludedService)
				}
			}

			// check that registered namespaces are enabled
			for _, namespace := range registry.GetNamespaces() {
				suite.Contains(tc.expectedServices, namespace.Name)
				suite.Contains(modeStrings, namespace.Namespace.Mode)

				suite.True(namespace.Namespace.IsEnabled(modeStrings))
			}
		})
	}
}

// Test backward compatibility - existing modes should work unchanged
func (suite *ServiceTestSuite) TestRegisterCoreServices_BackwardCompatibility() {
	testCases := []struct {
		name             string
		mode             []serviceregistry.ModeName
		expectedServices []string
		excludedServices []string
	}{
		{
			name:             "All_Mode_No_Negation",
			mode:             []serviceregistry.ModeName{"all"},
			expectedServices: []string{ServicePolicy.String(), ServiceAuthorization.String(), ServiceKAS.String(), ServiceWellKnown.String(), ServiceEntityResolution.String()},
			excludedServices: []string{},
		},
		{
			name:             "Core_Mode_No_Negation",
			mode:             []serviceregistry.ModeName{"core"},
			expectedServices: []string{ServicePolicy.String(), ServiceAuthorization.String(), ServiceWellKnown.String()},
			excludedServices: []string{ServiceKAS.String(), ServiceEntityResolution.String()},
		},
		{
			name:             "KAS_Mode_No_Negation",
			mode:             []serviceregistry.ModeName{"kas"},
			expectedServices: []string{ServiceKAS.String()},
			excludedServices: []string{ServicePolicy.String(), ServiceAuthorization.String(), ServiceWellKnown.String(), ServiceEntityResolution.String()},
		},
		{
			name:             "EntityResolution_Mode_No_Negation",
			mode:             []serviceregistry.ModeName{"entityresolution"},
			expectedServices: []string{ServiceEntityResolution.String()},
			excludedServices: []string{ServicePolicy.String(), ServiceAuthorization.String(), ServiceWellKnown.String(), ServiceKAS.String()},
		},
		{
			name:             "Core_Plus_KAS",
			mode:             []serviceregistry.ModeName{"core", "kas"},
			expectedServices: []string{ServicePolicy.String(), ServiceAuthorization.String(), ServiceWellKnown.String(), ServiceKAS.String()},
			excludedServices: []string{ServiceEntityResolution.String()},
		},
		{
			name:             "Core_Plus_EntityResolution",
			mode:             []serviceregistry.ModeName{"core", "entityresolution"},
			expectedServices: []string{ServicePolicy.String(), ServiceAuthorization.String(), ServiceWellKnown.String(), ServiceEntityResolution.String()},
			excludedServices: []string{ServiceKAS.String()},
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			registry := serviceregistry.NewServiceRegistry()

			registeredServices, err := RegisterCoreServices(registry, tc.mode)

			suite.Require().NoError(err)
			suite.ElementsMatch(tc.expectedServices, registeredServices)

			// Verify expected services ARE registered
			for _, expectedService := range tc.expectedServices {
				ns, err := registry.GetNamespace(expectedService)
				suite.Require().NoError(err, "Expected service '%s' should be registered", expectedService)
				if err == nil {
					suite.NotEmpty(ns.Services, "Service '%s' should have implementations", expectedService)
				}
			}

			// Verify excluded services are NOT registered
			for _, excludedService := range tc.excludedServices {
				_, err := registry.GetNamespace(excludedService)
				suite.Require().Error(err, "Service '%s' should NOT be registered", excludedService)
				if err != nil {
					suite.Contains(err.Error(), "namespace not found")
				}
			}

			modeStrings := make([]string, len(tc.mode))
			for i, m := range tc.mode {
				modeStrings[i] = m.String()
			}
			// check that registered namespaces are enabled
			for _, namespace := range registry.GetNamespaces() {
				suite.Contains(tc.expectedServices, namespace.Name)
				suite.Contains(modeStrings, namespace.Namespace.Mode)

				suite.True(namespace.Namespace.IsEnabled(modeStrings))
			}
		})
	}
}

// Test the isNamespaceEnabled helper function
func (suite *ServiceTestSuite) TestIsNamespaceEnabled() {
	testCases := []struct {
		name           string
		configModes    []string
		namespaceMode  string
		expectedResult bool
	}{
		{
			name:           "All_Mode_Enables_Any_Namespace",
			configModes:    []string{"all"},
			namespaceMode:  "core",
			expectedResult: true,
		},
		{
			name:           "Essential_Always_Enabled",
			configModes:    []string{"core"},
			namespaceMode:  "essential",
			expectedResult: true,
		},
		{
			name:           "Matching_Mode_Enabled",
			configModes:    []string{"core", "kas"},
			namespaceMode:  "kas",
			expectedResult: true,
		},
		{
			name:           "Non_Matching_Mode_Disabled",
			configModes:    []string{"core"},
			namespaceMode:  "kas",
			expectedResult: false,
		},
		{
			name:           "Case_Insensitive_Matching",
			configModes:    []string{"CORE"},
			namespaceMode:  "core",
			expectedResult: true,
		},
		{
			name:           "Multiple_Modes_One_Match",
			configModes:    []string{"core", "entityresolution"},
			namespaceMode:  "entityresolution",
			expectedResult: true,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			// Create a namespace with the test mode
			namespace := serviceregistry.Namespace{Mode: tc.namespaceMode}
			result := namespace.IsEnabled(tc.configModes)
			suite.Equal(tc.expectedResult, result,
				"Expected %v for modes %v and namespace %s, got %v",
				tc.expectedResult, tc.configModes, tc.namespaceMode, result)
		})
	}
}

// mockOrderTrackingService is a mock implementation of IService for testing start order.
type mockOrderTrackingService struct {
	namespace         string
	serviceName       string
	startOrderTracker *[]string
}

func (m *mockOrderTrackingService) GetNamespace() string { return m.namespace }
func (m *mockOrderTrackingService) GetVersion() string   { return "v1" }
func (m *mockOrderTrackingService) GetServiceDesc() *grpc.ServiceDesc {
	return &grpc.ServiceDesc{ServiceName: m.serviceName}
}
func (m *mockOrderTrackingService) IsDBRequired() bool      { return false }
func (m *mockOrderTrackingService) DBMigrations() *embed.FS { return nil }
func (m *mockOrderTrackingService) IsStarted() bool         { return true }
func (m *mockOrderTrackingService) Shutdown() error         { return nil }
func (m *mockOrderTrackingService) Start(_ context.Context, _ serviceregistry.RegistrationParams) error {
	*m.startOrderTracker = append(*m.startOrderTracker, m.serviceName)
	return nil
}

func (m *mockOrderTrackingService) RegisterConfigUpdateHook(context.Context, func(config.ChangeHook)) error {
	return nil
}

func (m *mockOrderTrackingService) RegisterConnectRPCServiceHandler(context.Context, *server.ConnectRPC) error {
	return nil
}

func (m *mockOrderTrackingService) RegisterGRPCGatewayHandler(context.Context, *runtime.ServeMux, *grpc.ClientConn) error {
	return nil
}

func (m *mockOrderTrackingService) RegisterHTTPHandlers(context.Context, *runtime.ServeMux) error {
	return nil
}

func (suite *ServiceTestSuite) TestStartServices_StartsInRegistrationOrder() {
	ctx := context.Background()
	startOrderTracker := make([]string, 0)
	registry := serviceregistry.NewServiceRegistry()

	// Define the services and their registration order
	servicesToRegister := []struct {
		name      string
		namespace string
		mode      serviceregistry.ModeName
	}{
		{"ServiceA", "namespace1", "test"},
		{"ServiceB", "namespace2", "test"},
		{"ServiceC", "namespace1", "test"},
		{"ServiceD", "namespace3", "test"},
		{"ServiceE", "namespace2", "test"},
	}

	for _, s := range servicesToRegister {
		mockSvc := &mockOrderTrackingService{
			namespace:         s.namespace,
			serviceName:       s.name,
			startOrderTracker: &startOrderTracker,
		}
		err := registry.RegisterService(mockSvc, s.mode)
		suite.Require().NoError(err)
	}

	// Prepare to call startServices
	otdf, err := mockOpenTDFServer()
	suite.Require().NoError(err)
	defer otdf.Stop()

	newLogger, err := logger.NewLogger(logger.Config{Output: "stdout", Level: "info", Type: "json"})
	suite.Require().NoError(err)
	cleanup, err := startServices(ctx, startServicesParams{
		cfg: &config.Config{
			Mode: []string{"test"}, // Enable the mode for our test services
			Services: map[string]config.ServiceConfig{
				"namespace1": {},
				"namespace2": {},
				"namespace3": {},
			},
		},
		otdf:   otdf,
		logger: newLogger,
		reg:    registry,
	})
	suite.Require().NoError(err)
	defer cleanup()

	// The startServices function iterates through namespaces in the order they were first registered,
	// and then through the services within that namespace in their registration order.
	// Namespace registration order: namespace1, namespace2, namespace3
	// Services in namespace1: ServiceA, ServiceC
	// Services in namespace2: ServiceB, ServiceE
	// Services in namespace3: ServiceD
	expectedStartOrder := []string{"ServiceA", "ServiceC", "ServiceB", "ServiceE", "ServiceD"}

	suite.Require().Equal(expectedStartOrder, startOrderTracker, "Services should start in the order they were registered, grouped by namespace")

	// call close function
	registry.Shutdown()
}

// Test_Extra_Services_With_Mode_Negation validates that extra services (both extra core services
// and standalone extra services) behave correctly with mode negation
func (suite *ServiceTestSuite) Test_Extra_Services_With_Mode_Negation() {
	testCases := []struct {
		name                   string
		modes                  []serviceregistry.ModeName
		useExtraCoreServices   bool
		useExtraServices       bool
		extraCoreNamespace     string
		extraServiceNamespace  string
		expectExtraCoreService bool
		expectExtraService     bool
		description            string
	}{
		{
			name:                   "All_Mode_With_Extra_Core_Service",
			modes:                  []serviceregistry.ModeName{serviceregistry.ModeALL},
			useExtraCoreServices:   true,
			useExtraServices:       false,
			extraCoreNamespace:     "extracore",
			expectExtraCoreService: true,
			expectExtraService:     false,
			description:            "All mode should register extra core services",
		},
		{
			name:                   "Core_Mode_With_Extra_Core_Service",
			modes:                  []serviceregistry.ModeName{serviceregistry.ModeCore},
			useExtraCoreServices:   true,
			useExtraServices:       false,
			extraCoreNamespace:     "extracore",
			expectExtraCoreService: true,
			expectExtraService:     false,
			description:            "Core mode should register extra core services",
		},
		{
			name:                   "All_Mode_With_Extra_Service",
			modes:                  []serviceregistry.ModeName{serviceregistry.ModeALL},
			useExtraCoreServices:   false,
			useExtraServices:       true,
			extraServiceNamespace:  "extraservice",
			expectExtraCoreService: false,
			expectExtraService:     true,
			description:            "All mode should register extra services",
		},
		{
			name:                   "Extra_Service_Needs_Individual_Mode",
			modes:                  []serviceregistry.ModeName{"test", "extraservice"},
			useExtraCoreServices:   false,
			useExtraServices:       true,
			extraServiceNamespace:  "extraservice",
			expectExtraCoreService: false,
			expectExtraService:     true,
			description:            "Extra services need their individual mode included to be active",
		},
		{
			name:                   "All_Minus_ExtraCore_Excludes_Extra_Core_Service",
			modes:                  []serviceregistry.ModeName{serviceregistry.ModeALL, "-extracore"},
			useExtraCoreServices:   true,
			useExtraServices:       false,
			extraCoreNamespace:     "extracore",
			expectExtraCoreService: false,
			expectExtraService:     false,
			description:            "Service negation should exclude extra core services",
		},
		{
			name:                   "Core_Minus_ExtraCore_Excludes_Extra_Core_Service",
			modes:                  []serviceregistry.ModeName{serviceregistry.ModeCore, "-extracore"},
			useExtraCoreServices:   true,
			useExtraServices:       false,
			extraCoreNamespace:     "extracore",
			expectExtraCoreService: false,
			expectExtraService:     false,
			description:            "Core mode with negation should exclude extra core services",
		},
		{
			name:                   "All_Minus_ExtraService_With_Extra_Services",
			modes:                  []serviceregistry.ModeName{serviceregistry.ModeALL, "extraservice", "-extraservice"},
			useExtraCoreServices:   false,
			useExtraServices:       true,
			extraServiceNamespace:  "extraservice",
			expectExtraCoreService: false,
			expectExtraService:     false,
			description:            "Negating an extra service should exclude it even if its mode is included",
		},
		{
			name:                   "All_With_Both_Extra_Types",
			modes:                  []serviceregistry.ModeName{serviceregistry.ModeALL, "extraservice"},
			useExtraCoreServices:   true,
			useExtraServices:       true,
			extraCoreNamespace:     "extracore",
			extraServiceNamespace:  "extraservice",
			expectExtraCoreService: true,
			expectExtraService:     true,
			description:            "All mode should register both extra core and extra services",
		},
		{
			name:                   "All_Minus_ExtraCore_With_ExtraService",
			modes:                  []serviceregistry.ModeName{serviceregistry.ModeALL, "-extracore", "extraservice"},
			useExtraCoreServices:   true,
			useExtraServices:       true,
			extraCoreNamespace:     "extracore",
			extraServiceNamespace:  "extraservice",
			expectExtraCoreService: false,
			expectExtraService:     true,
			description:            "Service negation excludes extra core services; extra services need their mode included",
		},
		{
			name:                   "Core_With_Both_Extra_Types",
			modes:                  []serviceregistry.ModeName{serviceregistry.ModeCore, "extraservice"},
			useExtraCoreServices:   true,
			useExtraServices:       true,
			extraCoreNamespace:     "extracore",
			extraServiceNamespace:  "extraservice",
			expectExtraCoreService: true,
			expectExtraService:     true,
			description:            "Both extra core services (inherit core) and extra services (need individual mode) should register",
		},
		{
			name:                   "All_Minus_Multiple_Including_ExtraCore",
			modes:                  []serviceregistry.ModeName{serviceregistry.ModeALL, "-kas", "-extracore"},
			useExtraCoreServices:   true,
			useExtraServices:       false,
			extraCoreNamespace:     "extracore",
			expectExtraCoreService: false,
			expectExtraService:     false,
			description:            "Multiple negations including extra core service should exclude all specified services",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			// Create service registry
			registry := serviceregistry.NewServiceRegistry()

			// Register essential services
			err := RegisterEssentialServices(registry)
			suite.Require().NoError(err, "Failed to register essential services")

			// Register core services with the specified modes
			_, err = RegisterCoreServices(registry, tc.modes)
			suite.Require().NoError(err, "Failed to register core services")
			// Create extra core services if needed (inherit from core/all modes)
			var extraCoreServices []serviceregistry.IService
			if tc.useExtraCoreServices {
				extraCoreService, _ := mockTestServiceRegistry(mockTestServiceOptions{
					namespace:     tc.extraCoreNamespace,
					serviceName:   "ExtraCoreService",
					serviceObject: TestService{},
					serviceHandler: func(_ context.Context, mux *runtime.ServeMux) error {
						return mux.HandlePath(http.MethodGet, "/extracore/status", TestService{}.TestHandler)
					},
				})
				extraCoreServices = append(extraCoreServices, extraCoreService)
			}

			// Create extra services if needed (need individual mode specified)
			var extraServices []serviceregistry.IService
			if tc.useExtraServices {
				extraService, _ := mockTestServiceRegistry(mockTestServiceOptions{
					namespace:     tc.extraServiceNamespace,
					serviceName:   "ExtraService",
					serviceObject: TestService{},
					serviceHandler: func(_ context.Context, mux *runtime.ServeMux) error {
						return mux.HandlePath(http.MethodGet, "/extraservice/status", TestService{}.TestHandler)
					},
				})
				extraServices = append(extraServices, extraService)
			}

			// Convert ModeName slice to string slice for RegisterServicesFromConfiguration
			modeStrings := make([]string, len(tc.modes))
			for i, m := range tc.modes {
				modeStrings[i] = string(m)
			}

			// Register extra core services if provided (inherit from core/all modes)
			if len(extraCoreServices) > 0 {
				extraCoreServiceConfigs := getServiceConfigurationsFromIServices(
					extraCoreServices,
					[]serviceregistry.ModeName{serviceregistry.ModeCore}, // Inherit core mode
					false, // Don't create individual modes
				)
				_, err := registry.RegisterServicesFromConfiguration(modeStrings, extraCoreServiceConfigs)
				suite.Require().NoError(err, "Failed to register extra core services")
			}

			// Register extra services if provided (need individual mode)
			if len(extraServices) > 0 {
				extraServiceConfigs := getServiceConfigurationsFromIServices(
					extraServices,
					nil,  // Don't inherit any modes
					true, // Create individual mode for each service
				)
				_, err := registry.RegisterServicesFromConfiguration(modeStrings, extraServiceConfigs)
				suite.Require().NoError(err, "Failed to register extra services")
			}

			// Verify extra core service registration
			if tc.useExtraCoreServices {
				ns, err := registry.GetNamespace(tc.extraCoreNamespace)
				if tc.expectExtraCoreService {
					suite.Require().NoError(err, "Extra core service namespace should exist when expected")
					suite.NotEmpty(ns.Services, "Extra core service should be registered")
				} else {
					suite.Require().Error(err, "Extra core service namespace should not exist when excluded")
					suite.Contains(err.Error(), "namespace not found", "Should get 'namespace not found' error")
				}
			}

			// Verify extra service registration
			if tc.useExtraServices {
				ns, err := registry.GetNamespace(tc.extraServiceNamespace)
				if tc.expectExtraService {
					suite.Require().NoError(err, "Extra service namespace should exist when expected")
					suite.NotEmpty(ns.Services, "Extra service should be registered")
				} else {
					suite.Require().Error(err, "Extra service namespace should not exist when excluded")
					suite.Contains(err.Error(), "namespace not found", "Should get 'namespace not found' error")
				}
			}
		})
	}
}
