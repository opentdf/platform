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
	numExpectedPolicyServices                  = 9
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
	suite.Equal(string(serviceregistry.ModeEssential), ns.Mode)
}

func (suite *ServiceTestSuite) Test_RegisterCoreServices_In_Mode_ALL_Expect_All_Services_Registered() {
	registry := serviceregistry.NewServiceRegistry()
	_, err := registerCoreServices(registry, []serviceregistry.ModeName{serviceregistry.ModeALL})
	suite.Require().NoError(err)

	authz, err := registry.GetNamespace(string(serviceregistry.ServiceAuthorization))
	suite.Require().NoError(err)
	suite.Len(authz.Services, numExpectedAuthorizationServiceVersions)
	suite.Equal(string(serviceregistry.ModeCore), authz.Mode)

	kas, err := registry.GetNamespace(string(serviceregistry.ServiceKAS))
	suite.Require().NoError(err)
	suite.Len(kas.Services, 1)
	suite.Equal(string(serviceregistry.ModeCore), kas.Mode)

	policy, err := registry.GetNamespace(string(serviceregistry.ServicePolicy))
	suite.Require().NoError(err)
	suite.Len(policy.Services, numExpectedPolicyServices)
	suite.Equal(string(serviceregistry.ModeCore), policy.Mode)

	wellKnown, err := registry.GetNamespace(string(serviceregistry.ServiceWellKnown))
	suite.Require().NoError(err)
	suite.Len(wellKnown.Services, 1)
	suite.Equal(string(serviceregistry.ModeCore), wellKnown.Mode)

	ers, err := registry.GetNamespace(string(serviceregistry.ServiceEntityResolution))
	suite.Require().NoError(err)
	suite.Len(ers.Services, numExpectedEntityResolutionServiceVersions)
	suite.Equal(string(serviceregistry.ModeCore), ers.Mode)
}

// Every service except kas is registered
func (suite *ServiceTestSuite) Test_RegisterCoreServices_In_Mode_Core_Expect_Core_Services_Registered() {
	registry := serviceregistry.NewServiceRegistry()
	_, err := registerCoreServices(registry, []serviceregistry.ModeName{serviceregistry.ModeCore})
	suite.Require().NoError(err)

	authz, err := registry.GetNamespace(string(serviceregistry.ServiceAuthorization))
	suite.Require().NoError(err)
	suite.Len(authz.Services, numExpectedAuthorizationServiceVersions)
	suite.Equal(string(serviceregistry.ModeCore), authz.Mode)

	_, err = registry.GetNamespace(string(serviceregistry.ServiceKAS))
	suite.Require().Error(err)
	suite.Require().ErrorContains(err, "namespace not found")

	policy, err := registry.GetNamespace(string(serviceregistry.ServicePolicy))
	suite.Require().NoError(err)
	suite.Len(policy.Services, numExpectedPolicyServices)
	suite.Equal(string(serviceregistry.ModeCore), policy.Mode)

	wellKnown, err := registry.GetNamespace(string(serviceregistry.ServiceWellKnown))
	suite.Require().NoError(err)
	suite.Len(wellKnown.Services, 1)
	suite.Equal(string(serviceregistry.ModeCore), wellKnown.Mode)
}

// Register core and kas services
func (suite *ServiceTestSuite) Test_RegisterServices_In_Mode_Core_Plus_Kas_Expect_Core_And_Kas_Services_Registered() {
	registry := serviceregistry.NewServiceRegistry()
	_, err := registerCoreServices(registry, []serviceregistry.ModeName{serviceregistry.ModeCore, serviceregistry.ModeKAS})
	suite.Require().NoError(err)

	authz, err := registry.GetNamespace(string(serviceregistry.ServiceAuthorization))
	suite.Require().NoError(err)
	suite.Len(authz.Services, numExpectedAuthorizationServiceVersions)
	suite.Equal(string(serviceregistry.ModeCore), authz.Mode)

	kas, err := registry.GetNamespace(string(serviceregistry.ServiceKAS))
	suite.Require().NoError(err)
	suite.Len(kas.Services, 1)
	suite.Equal(string(serviceregistry.ModeKAS), kas.Mode)

	policy, err := registry.GetNamespace(string(serviceregistry.ServicePolicy))
	suite.Require().NoError(err)
	suite.Len(policy.Services, numExpectedPolicyServices)
	suite.Equal(string(serviceregistry.ModeCore), policy.Mode)

	wellKnown, err := registry.GetNamespace(string(serviceregistry.ServiceWellKnown))
	suite.Require().NoError(err)
	suite.Len(wellKnown.Services, 1)
	suite.Equal(string(serviceregistry.ModeCore), wellKnown.Mode)
}

// Register core and kas and ERS services
func (suite *ServiceTestSuite) Test_RegisterServices_In_Mode_Core_Plus_Kas_Expect_Core_And_Kas_And_ERS_Services_Registered() {
	registry := serviceregistry.NewServiceRegistry()
	_, err := registerCoreServices(registry, []serviceregistry.ModeName{serviceregistry.ModeCore, serviceregistry.ModeKAS, serviceregistry.ModeERS})
	suite.Require().NoError(err)

	authz, err := registry.GetNamespace(string(serviceregistry.ServiceAuthorization))
	suite.Require().NoError(err)
	suite.Len(authz.Services, numExpectedAuthorizationServiceVersions)
	suite.Equal(string(serviceregistry.ModeCore), authz.Mode)

	kas, err := registry.GetNamespace(string(serviceregistry.ServiceKAS))
	suite.Require().NoError(err)
	suite.Len(kas.Services, 1)
	suite.Equal(string(serviceregistry.ModeKAS), kas.Mode)

	policy, err := registry.GetNamespace(string(serviceregistry.ServicePolicy))
	suite.Require().NoError(err)
	suite.Len(policy.Services, numExpectedPolicyServices)
	suite.Equal(string(serviceregistry.ModeCore), policy.Mode)

	wellKnown, err := registry.GetNamespace(string(serviceregistry.ServiceWellKnown))
	suite.Require().NoError(err)
	suite.Len(wellKnown.Services, 1)
	suite.Equal(string(serviceregistry.ModeCore), wellKnown.Mode)

	ers, err := registry.GetNamespace(string(serviceregistry.ServiceEntityResolution))
	suite.Require().NoError(err)
	suite.Len(ers.Services, numExpectedEntityResolutionServiceVersions)
	suite.Equal(string(serviceregistry.ModeERS), ers.Mode)
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

// Test service negation functionality
func (suite *ServiceTestSuite) TestRegisterCoreServices_WithNegation_ExpectCorrectServicesRegistered() {
	testCases := []struct {
		name                     string
		mode                     []serviceregistry.ModeName
		expectedServices         []string
		expectedNotRegistered    []string
		shouldError              bool
		expectedErrorContains    string
	}{
		{
			name:                  "All_Minus_KAS",
			mode:                  []serviceregistry.ModeName{"all", "-kas"},
			expectedServices:      []string{string(serviceregistry.ServicePolicy), string(serviceregistry.ServiceAuthorization), string(serviceregistry.ServiceWellKnown), string(serviceregistry.ServiceEntityResolution)},
			expectedNotRegistered: []string{string(serviceregistry.ServiceKAS)},
			shouldError:           false,
		},
		{
			name:                  "All_Minus_EntityResolution",
			mode:                  []serviceregistry.ModeName{"all", "-entityresolution"},
			expectedServices:      []string{string(serviceregistry.ServicePolicy), string(serviceregistry.ServiceAuthorization), string(serviceregistry.ServiceKAS), string(serviceregistry.ServiceWellKnown)},
			expectedNotRegistered: []string{string(serviceregistry.ServiceEntityResolution)},
			shouldError:           false,
		},
		{
			name:                  "All_Minus_Multiple_Services",
			mode:                  []serviceregistry.ModeName{"all", "-kas", "-entityresolution"},
			expectedServices:      []string{string(serviceregistry.ServicePolicy), string(serviceregistry.ServiceAuthorization), string(serviceregistry.ServiceWellKnown)},
			expectedNotRegistered: []string{string(serviceregistry.ServiceKAS), string(serviceregistry.ServiceEntityResolution)},
			shouldError:           false,
		},
		{
			name:                  "Core_Plus_KAS_Minus_Policy",
			mode:                  []serviceregistry.ModeName{"core", "kas", "-policy"},
			expectedServices:      []string{string(serviceregistry.ServiceAuthorization), string(serviceregistry.ServiceWellKnown), string(serviceregistry.ServiceKAS)},
			expectedNotRegistered: []string{string(serviceregistry.ServicePolicy), string(serviceregistry.ServiceEntityResolution)},
			shouldError:           false,
		},
		{
			name:                "Negation_Without_Base_Mode",
			mode:                []serviceregistry.ModeName{"-kas"},
			expectedServices:    nil,
			shouldError:         true,
			expectedErrorContains: "cannot exclude services without including base modes",
		},
		{
			name:                "Invalid_Empty_Negation",
			mode:                []serviceregistry.ModeName{"all", "-"},
			expectedServices:    nil,
			shouldError:         true,
			expectedErrorContains: "empty service name after '-'",
		},
		{
			name:                  "Negation_Nonexistent_Service",
			mode:                  []serviceregistry.ModeName{"all", "-nonexistent"},
			expectedServices:      []string{string(serviceregistry.ServicePolicy), string(serviceregistry.ServiceAuthorization), string(serviceregistry.ServiceKAS), string(serviceregistry.ServiceWellKnown), string(serviceregistry.ServiceEntityResolution)},
			expectedNotRegistered: []string{},
			shouldError:           false,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			registry := serviceregistry.NewServiceRegistry()

			registeredServices, err := registerCoreServices(registry, tc.mode)

			if tc.shouldError {
				suite.Error(err)
				if tc.expectedErrorContains != "" {
					suite.Contains(err.Error(), tc.expectedErrorContains)
				}
				return
			}

			suite.NoError(err)

			// Check that expected services are registered
			for _, expectedService := range tc.expectedServices {
				suite.Contains(registeredServices, expectedService, 
					"Expected service %s to be registered", expectedService)
			}

			// Check that expected services are NOT registered
			for _, notExpectedService := range tc.expectedNotRegistered {
				suite.NotContains(registeredServices, notExpectedService, 
					"Expected service %s to NOT be registered", notExpectedService)
			}

			// Verify the total count matches expectations
			suite.Equal(len(tc.expectedServices), len(registeredServices),
				"Expected %d services, got %d: %v", 
				len(tc.expectedServices), len(registeredServices), registeredServices)
		})
	}
}

// Test backward compatibility - existing modes should work unchanged
func (suite *ServiceTestSuite) TestRegisterCoreServices_BackwardCompatibility() {
	testCases := []struct {
		name             string
		mode             []serviceregistry.ModeName
		expectedServices []string
	}{
		{
			name:             "All_Mode_No_Negation",
			mode:             []serviceregistry.ModeName{"all"},
			expectedServices: []string{string(serviceregistry.ServicePolicy), string(serviceregistry.ServiceAuthorization), string(serviceregistry.ServiceKAS), string(serviceregistry.ServiceWellKnown), string(serviceregistry.ServiceEntityResolution)},
		},
		{
			name:             "Core_Mode_No_Negation",
			mode:             []serviceregistry.ModeName{"core"},
			expectedServices: []string{string(serviceregistry.ServicePolicy), string(serviceregistry.ServiceAuthorization), string(serviceregistry.ServiceWellKnown)},
		},
		{
			name:             "KAS_Mode_No_Negation",
			mode:             []serviceregistry.ModeName{"kas"},
			expectedServices: []string{string(serviceregistry.ServiceKAS)},
		},
		{
			name:             "EntityResolution_Mode_No_Negation",
			mode:             []serviceregistry.ModeName{"entityresolution"},
			expectedServices: []string{string(serviceregistry.ServiceEntityResolution)},
		},
		{
			name:             "Mixed_Modes_No_Negation",
			mode:             []serviceregistry.ModeName{"core", "kas"},
			expectedServices: []string{string(serviceregistry.ServicePolicy), string(serviceregistry.ServiceAuthorization), string(serviceregistry.ServiceWellKnown), string(serviceregistry.ServiceKAS)},
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			registry := serviceregistry.NewServiceRegistry()

			registeredServices, err := registerCoreServices(registry, tc.mode)

			suite.NoError(err)
			suite.ElementsMatch(tc.expectedServices, registeredServices)
		})
	}
}

// Test edge cases and error conditions
// Test the IsNamespaceEnabled method works correctly
func (suite *ServiceTestSuite) TestIsNamespaceEnabled() {
	sm, err := createServiceManager()
	suite.NoError(err)

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
			result := sm.IsNamespaceEnabled(tc.configModes, tc.namespaceMode)
			suite.Equal(tc.expectedResult, result, 
				"Expected %v for modes %v and namespace %s, got %v", 
				tc.expectedResult, tc.configModes, tc.namespaceMode, result)
		})
	}
}

func (suite *ServiceTestSuite) TestParseModeWithNegation_EdgeCases() {
	testCases := []struct {
		name              string
		modes             []string
		expectedIncluded  []string
		expectedExcluded  []string
		shouldError       bool
		expectedErrorContains string
	}{
		{
			name:             "Normal_Modes_Only",
			modes:            []string{"all", "core"},
			expectedIncluded: []string{"all", "core"},
			expectedExcluded: []string{},
			shouldError:      false,
		},
		{
			name:             "Negation_Modes_Only_Should_Error",
			modes:            []string{"-kas", "-policy"},
			expectedIncluded: []string{},
			expectedExcluded: []string{"kas", "policy"},
			shouldError:      true,
			expectedErrorContains: "cannot exclude services without including base modes",
		},
		{
			name:             "Mixed_Modes_With_Negation",
			modes:            []string{"all", "-kas", "core", "-policy"},
			expectedIncluded: []string{"all", "core"},
			expectedExcluded: []string{"kas", "policy"},
			shouldError:      false,
		},
		{
			name:              "Empty_Negation",
			modes:             []string{"all", "-"},
			expectedIncluded:  nil,
			expectedExcluded:  nil,
			shouldError:       true,
			expectedErrorContains: "empty service name after '-'",
		},
		{
			name:             "Duplicate_Exclusions",
			modes:            []string{"all", "-kas", "-kas"},
			expectedIncluded: []string{"all"},
			expectedExcluded: []string{"kas", "kas"},
			shouldError:      false,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			sm, smErr := createServiceManager()
			suite.NoError(smErr)
			included, excluded, err := sm.ParseModes(tc.modes)

			if tc.shouldError {
				suite.Error(err)
				if tc.expectedErrorContains != "" {
					suite.Contains(err.Error(), tc.expectedErrorContains)
				}
				return
			}

			suite.NoError(err)
			suite.ElementsMatch(tc.expectedIncluded, included)
			suite.ElementsMatch(tc.expectedExcluded, excluded)
		})
	}
}
