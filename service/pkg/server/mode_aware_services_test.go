package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/trust"
)

type ModeAwareServicesTestSuite struct {
	suite.Suite
}

func TestModeAwareServicesTestSuite(t *testing.T) {
	suite.Run(t, new(ModeAwareServicesTestSuite))
}

func (suite *ModeAwareServicesTestSuite) TestModeAwareServiceRegistration() {
	testCases := []struct {
		name            string
		serviceNamespace string
		serviceModes     []string
		configModes     []string
		shouldRegister  bool
		description     string
	}{
		{
			name:            "Service_For_KAS_Mode_In_KAS_Config",
			serviceNamespace: "testservice",
			serviceModes:     []string{"kas"},
			configModes:     []string{"kas"},
			shouldRegister:  true,
			description:     "Service configured for KAS mode should register when config is KAS",
		},
		{
			name:            "Service_For_KAS_Mode_In_Core_Config",
			serviceNamespace: "testservice",
			serviceModes:     []string{"kas"},
			configModes:     []string{"core"},
			shouldRegister:  false,
			description:     "Service configured for KAS mode should NOT register when config is core",
		},
		{
			name:            "Service_For_Multiple_Modes_In_Matching_Config",
			serviceNamespace: "testservice",
			serviceModes:     []string{"kas", "core"},
			configModes:     []string{"kas"},
			shouldRegister:  true,
			description:     "Service configured for multiple modes should register when config matches one",
		},
		{
			name:            "Service_For_Multiple_Modes_In_Non_Matching_Config",
			serviceNamespace: "testservice",
			serviceModes:     []string{"kas", "core"},
			configModes:     []string{"entityresolution"},
			shouldRegister:  false,
			description:     "Service configured for multiple modes should NOT register when config matches none",
		},
		{
			name:            "Service_For_All_Mode",
			serviceNamespace: "testservice",
			serviceModes:     []string{"all"},
			configModes:     []string{"kas"},
			shouldRegister:  true,
			description:     "Service configured for 'all' mode should register in any config",
		},
		{
			name:            "Service_For_All_Mode_In_All_Config",
			serviceNamespace: "testservice",
			serviceModes:     []string{"all"},
			configModes:     []string{"all"},
			shouldRegister:  true,
			description:     "Service configured for 'all' mode should register in 'all' config",
		},
		{
			name:            "Service_With_Config_All_Mode",
			serviceNamespace: "testservice", 
			serviceModes:     []string{"kas"},
			configModes:     []string{"all"},
			shouldRegister:  true,
			description:     "Any service should register when config is 'all'",
		},
		{
			name:            "Service_Mode_Matches_Service_Namespace",
			serviceNamespace: "customservice",
			serviceModes:     []string{"customservice"},
			configModes:     []string{"customservice"},
			shouldRegister:  true,
			description:     "Service should register when mode matches its own namespace",
		},
		{
			name:            "Service_Mode_Matches_Service_Namespace_But_Config_Different",
			serviceNamespace: "customservice",
			serviceModes:     []string{"customservice"},
			configModes:     []string{"kas"},
			shouldRegister:  false,
			description:     "Service should NOT register when mode doesn't match config",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			// Create registry
			registry := serviceregistry.NewServiceRegistry()

			// Register essential services (required)
			err := registerEssentialServices(registry)
			suite.Require().NoError(err)

			// Create mock service
			testService, _ := mockTestServiceRegistry(mockTestServiceOptions{
				namespace:   tc.serviceNamespace,
				serviceName: "TestModeAwareService",
				serviceObject: TestService{},
			})

			// Create StartConfig with mode-aware service
			startConfig := StartConfig{
				modeAwareServices: []ModeAwareService{
					{
						Service: testService,
						Modes:   tc.serviceModes,
					},
				},
			}

			// Simulate the registration logic from start.go
			for _, modeService := range startConfig.modeAwareServices {
				// Check if any of the service's modes match the current configuration modes  
				shouldRegister := false
				for _, serviceMode := range modeService.Modes {
					for _, configMode := range tc.configModes {
						if configMode == serviceMode || serviceMode == "all" || configMode == "all" {
							shouldRegister = true
							break
						}
					}
					if shouldRegister {
						break
					}
				}

				if shouldRegister {
					// Use the first matching mode for registration
					registrationMode := modeService.Service.GetNamespace()
					for _, serviceMode := range modeService.Modes {
						for _, configMode := range tc.configModes {
							if configMode == serviceMode {
								registrationMode = serviceMode
								goto found
							}
						}
					}
					if contains(modeService.Modes, "all") {
						registrationMode = "all"
					}
					found:
					err := registry.RegisterService(modeService.Service, registrationMode)
					suite.Require().NoError(err)
				}
			}

			// Verify registration result
			ns, err := registry.GetNamespace(tc.serviceNamespace)
			if tc.shouldRegister {
				suite.NoError(err, "Service should have been registered: %s", tc.description)
				suite.Len(ns.Services, 1, "Service should be in registry: %s", tc.description)
			} else {
				suite.Error(err, "Service should NOT have been registered: %s", tc.description)
				suite.Contains(err.Error(), "namespace not found", "Expected namespace not found error: %s", tc.description)
			}
		})
	}
}

func (suite *ModeAwareServicesTestSuite) TestModeAwareServiceStartupIntegration() {
	// Create mock OpenTDF server
	otdf, err := mockOpenTDFServer()
	suite.Require().NoError(err)

	logger, err := logger.NewLogger(logger.Config{Output: "stdout", Level: "info", Type: "json"})
	suite.Require().NoError(err)

	// Create registry
	registry := serviceregistry.NewServiceRegistry()
	err = registerEssentialServices(registry)
	suite.Require().NoError(err)

	// Create test services
	kasService, kasSpy := mockTestServiceRegistry(mockTestServiceOptions{
		namespace:     "kasspecific",
		serviceName:   "KASSpecificService", 
		serviceObject: TestService{},
	})

	coreService, coreSpy := mockTestServiceRegistry(mockTestServiceOptions{
		namespace:     "corespecific",
		serviceName:   "CoreSpecificService",
		serviceObject: TestService{},
	})

	universalService, universalSpy := mockTestServiceRegistry(mockTestServiceOptions{
		namespace:     "universal",
		serviceName:   "UniversalService",
		serviceObject: TestService{},
	})

	// Register mode-aware services 
	modeAwareServices := []ModeAwareService{
		{Service: kasService, Modes: []string{"kas"}},
		{Service: coreService, Modes: []string{"core"}}, 
		{Service: universalService, Modes: []string{"all"}},
	}

	// Simulate start.go registration logic for KAS mode
	configModes := []string{"kas"}
	for _, modeService := range modeAwareServices {
		shouldRegister := false
		for _, serviceMode := range modeService.Modes {
			if contains(configModes, serviceMode) || serviceMode == "all" {
				shouldRegister = true
				break
			}
		}

		if shouldRegister {
			registrationMode := modeService.Service.GetNamespace()
			for _, serviceMode := range modeService.Modes {
				if contains(configModes, serviceMode) {
					registrationMode = serviceMode
					break
				}
			}
			if contains(modeService.Modes, "all") {
				registrationMode = "all"
			}

			err := registry.RegisterService(modeService.Service, registrationMode)
			suite.Require().NoError(err)
		}
	}

	// Start services with KAS mode
	cleanup, err := startServices(context.Background(), startServicesParams{
		cfg: &config.Config{
			Mode: []string{"kas"},
			Services: map[string]config.ServiceConfig{
				"kasspecific": {},
				"corespecific": {},
				"universal": {},
			},
		},
		otdf:                otdf,
		client:              nil,
		keyManagerFactories: []trust.NamedKeyManagerFactory{},
		logger:              logger,
		reg:                 registry,
		cacheManager:        &cache.Manager{},
	})
	suite.Require().NoError(err)
	defer cleanup()

	// Verify which services were started
	suite.True(kasSpy.wasCalled, "KAS-specific service should have started in KAS mode")
	suite.False(coreSpy.wasCalled, "Core-specific service should NOT have started in KAS mode")
	suite.True(universalSpy.wasCalled, "Universal service should have started in KAS mode")
}

// Test the original behavior preservation
func (suite *ModeAwareServicesTestSuite) TestOriginalExtraServiceBehaviorPreserved() {
	// This test ensures we don't regress the original WithServices() behavior
	// Based on the existing Test_Start_When_Extra_Service_Registered test

	testCases := []struct {
		name            string
		configModes     []string 
		serviceEnabled  bool
		description     string
	}{
		{
			name:           "Extra_Service_In_KAS_Mode_Should_NOT_Start",
			configModes:    []string{"kas"},
			serviceEnabled: false,
			description:    "Original behavior: extra services don't start in non-matching modes",
		},
		{
			name:           "Extra_Service_In_KAS_Plus_Test_Mode_Should_Start", 
			configModes:    []string{"kas", "test"},
			serviceEnabled: true,
			description:    "Original behavior: extra services start when mode matches",
		},
		{
			name:           "Extra_Service_In_All_Mode_Should_Start",
			configModes:    []string{"all"},
			serviceEnabled: true,
			description:    "Original behavior: extra services start in 'all' mode",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			// Create mock OpenTDF server
			otdf, err := mockOpenTDFServer()
			suite.Require().NoError(err)

			logger, err := logger.NewLogger(logger.Config{Output: "stdout", Level: "info", Type: "json"})
			suite.Require().NoError(err)

			// Create registry and register test service using original WithServices logic
			registry := serviceregistry.NewServiceRegistry()
			err = registerEssentialServices(registry)
			suite.Require().NoError(err)

			testService, testSpy := mockTestServiceRegistry(mockTestServiceOptions{
				namespace:     "test",
				serviceName:   "TestService",
				serviceObject: TestService{},
			})

			// Register service using original logic (service namespace as mode)
			err = registry.RegisterService(testService, testService.GetNamespace()) 
			suite.Require().NoError(err)

			// Start services
			cleanup, err := startServices(context.Background(), startServicesParams{
				cfg: &config.Config{
					Mode: tc.configModes,
					Services: map[string]config.ServiceConfig{
						"test": {},
					},
				},
				otdf:                otdf,
				client:              nil, 
				keyManagerFactories: []trust.NamedKeyManagerFactory{},
				logger:              logger,
				reg:                 registry,
				cacheManager:        &cache.Manager{},
			})
			suite.Require().NoError(err)
			defer cleanup()

			// Verify original behavior is preserved
			if tc.serviceEnabled {
				suite.True(testSpy.wasCalled, "Service should have started: %s", tc.description)
			} else {
				suite.False(testSpy.wasCalled, "Service should NOT have started: %s", tc.description)
			}
		})
	}
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}