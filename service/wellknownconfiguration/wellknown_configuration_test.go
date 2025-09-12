package wellknownconfiguration

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	wellknown "github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type WellKnownConfigurationSuite struct {
	suite.Suite
	service *WellKnownService
	logger  *logger.Logger
}

func (s *WellKnownConfigurationSuite) SetupSuite() {
	s.logger = logger.CreateTestLogger()

	s.service = &WellKnownService{
		logger: s.logger,
	}
}

func (s *WellKnownConfigurationSuite) TearDownTest() {
	// Reset the global configuration map after each test
	rwMutex.Lock()
	wellKnownConfiguration = make(map[string]any)
	rwMutex.Unlock()
}

func TestWellKnownConfigurationSuite(t *testing.T) {
	suite.Run(t, new(WellKnownConfigurationSuite))
}

func (s *WellKnownConfigurationSuite) TestRegisterConfiguration_Success() {
	config := map[string]any{
		"key1": "value1",
		"key2": 42,
		"key3": true,
	}

	err := RegisterConfiguration("test_namespace", config)
	s.Require().NoError(err)

	// Verify configuration was registered
	rwMutex.RLock()
	registeredConfig := wellKnownConfiguration["test_namespace"]
	rwMutex.RUnlock()

	s.Equal(config, registeredConfig)
}

func (s *WellKnownConfigurationSuite) TestRegisterConfiguration_DuplicateNamespace() {
	config1 := map[string]any{"key": "value1"}
	config2 := map[string]any{"key": "value2"}

	// Register first configuration
	err := RegisterConfiguration("duplicate_namespace", config1)
	s.Require().NoError(err)

	// Attempt to register second configuration with same namespace
	err = RegisterConfiguration("duplicate_namespace", config2)
	s.Require().Error(err)
	s.Contains(err.Error(), "namespace duplicate_namespace configuration already registered")
}

func (s *WellKnownConfigurationSuite) TestUpdateConfigurationBaseKey() {
	baseConfig := map[string]any{
		"base_key1": "base_value1",
		"base_key2": 100,
	}

	UpdateConfigurationBaseKey(baseConfig)

	// Verify base key configuration was set
	rwMutex.RLock()
	registeredConfig := wellKnownConfiguration[baseKeyWellKnown]
	rwMutex.RUnlock()

	s.Equal(baseConfig, registeredConfig)
}

func (s *WellKnownConfigurationSuite) TestGetWellKnownConfiguration_EmptyConfig() {
	req := connect.NewRequest(&wellknown.GetWellKnownConfigurationRequest{})
	resp, err := s.service.GetWellKnownConfiguration(context.Background(), req)

	s.Require().NoError(err)
	s.NotNil(resp)
	s.NotNil(resp.Msg.GetConfiguration())

	// Should return an empty struct
	s.Empty(resp.Msg.GetConfiguration().GetFields())
}

func (s *WellKnownConfigurationSuite) TestGetWellKnownConfiguration_WithConfigurations() {
	// Register multiple configurations
	config1 := map[string]any{
		"service1_key": "service1_value",
		"enabled":      true,
	}
	config2 := map[string]any{
		"service2_key": "service2_value",
		"port":         8080,
	}
	baseConfig := map[string]any{
		"base_setting": "base_value",
	}

	err := RegisterConfiguration("service1", config1)
	s.Require().NoError(err)

	err = RegisterConfiguration("service2", config2)
	s.Require().NoError(err)

	UpdateConfigurationBaseKey(baseConfig)

	// Get the configuration
	req := connect.NewRequest(&wellknown.GetWellKnownConfigurationRequest{})
	resp, err := s.service.GetWellKnownConfiguration(context.Background(), req)

	s.Require().NoError(err)
	s.NotNil(resp)
	s.NotNil(resp.Msg.GetConfiguration())

	// Verify all configurations are present
	fields := resp.Msg.GetConfiguration().GetFields()
	s.Len(fields, 3) // service1, service2, base_key

	// Verify service1 configuration
	service1Field, exists := fields["service1"]
	s.True(exists)
	s.NotNil(service1Field.GetStructValue())

	// Verify service2 configuration
	service2Field, exists := fields["service2"]
	s.True(exists)
	s.NotNil(service2Field.GetStructValue())

	// Verify base_key configuration
	baseField, exists := fields[baseKeyWellKnown]
	s.True(exists)
	s.NotNil(baseField.GetStructValue())
}

func (s *WellKnownConfigurationSuite) TestGetWellKnownConfiguration_KeyManagersStructure() {
	// Test the key managers configuration structure that was causing the original error
	keyManagersConfig := map[string]any{
		"manager_0": map[string]any{
			"name":        "basic",
			"description": "Key manager: basic",
		},
		"manager_1": map[string]any{
			"name":        "aws",
			"description": "Key manager: aws",
		},
	}

	err := RegisterConfiguration("key_managers", keyManagersConfig)
	s.Require().NoError(err)

	req := connect.NewRequest(&wellknown.GetWellKnownConfigurationRequest{})
	resp, err := s.service.GetWellKnownConfiguration(context.Background(), req)

	s.Require().NoError(err)
	s.NotNil(resp)
	s.NotNil(resp.Msg.GetConfiguration())

	// Verify key managers configuration is present and structured correctly
	fields := resp.Msg.GetConfiguration().GetFields()
	keyManagersField, exists := fields["key_managers"]
	s.True(exists)
	s.NotNil(keyManagersField.GetStructValue())

	keyManagersStruct := keyManagersField.GetStructValue()
	s.Len(keyManagersStruct.GetFields(), 2) // manager_0, manager_1

	// Verify manager_0
	manager0Field, exists := keyManagersStruct.GetFields()["manager_0"]
	s.True(exists)
	manager0Struct := manager0Field.GetStructValue()
	s.NotNil(manager0Struct)
	s.Equal("basic", manager0Struct.GetFields()["name"].GetStringValue())
	s.Equal("Key manager: basic", manager0Struct.GetFields()["description"].GetStringValue())

	// Verify manager_1
	manager1Field, exists := keyManagersStruct.GetFields()["manager_1"]
	s.True(exists)
	manager1Struct := manager1Field.GetStructValue()
	s.NotNil(manager1Struct)
	s.Equal("aws", manager1Struct.GetFields()["name"].GetStringValue())
	s.Equal("Key manager: aws", manager1Struct.GetFields()["description"].GetStringValue())
}

func (s *WellKnownConfigurationSuite) TestGetWellKnownConfiguration_InvalidData() {
	// Test with data that cannot be converted to structpb
	invalidConfig := map[string]any{
		"invalid_channel": make(chan int), // channels cannot be converted to protobuf
	}

	err := RegisterConfiguration("invalid_service", invalidConfig)
	s.Require().NoError(err)

	req := connect.NewRequest(&wellknown.GetWellKnownConfigurationRequest{})
	resp, err := s.service.GetWellKnownConfiguration(context.Background(), req)

	s.Require().Error(err)
	s.Nil(resp)

	// Verify it's a connect error with internal code
	connectErr := &connect.Error{}
	ok := errors.As(err, &connectErr)
	s.True(ok)
	s.Equal(connect.CodeInternal, connectErr.Code())
	s.Contains(connectErr.Message(), "failed to create struct for wellknown configuration")
}

func (s *WellKnownConfigurationSuite) TestConcurrentAccess() {
	// Test concurrent access to the configuration map
	done := make(chan bool)
	numGoroutines := 10

	// Start multiple goroutines that register configurations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			config := map[string]any{
				"concurrent_key": id,
			}
			err := RegisterConfiguration(string(rune(65+id)), config) // A, B, C, etc.
			s.NoError(err)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify all configurations were registered
	req := connect.NewRequest(&wellknown.GetWellKnownConfigurationRequest{})
	resp, err := s.service.GetWellKnownConfiguration(context.Background(), req)

	s.Require().NoError(err)
	s.NotNil(resp)
	s.Len(resp.Msg.GetConfiguration().GetFields(), numGoroutines)
}

func TestRegisterConfiguration_Standalone(t *testing.T) {
	// Reset configuration before test
	rwMutex.Lock()
	wellKnownConfiguration = make(map[string]any)
	rwMutex.Unlock()

	config := map[string]any{"test": "value"}
	err := RegisterConfiguration("standalone_test", config)
	require.NoError(t, err)

	assert.NoError(t, err)
	assert.Equal(t, config, wellKnownConfiguration["standalone_test"])
}

func TestUpdateConfigurationBaseKey_Standalone(t *testing.T) {
	// Reset configuration before test
	rwMutex.Lock()
	wellKnownConfiguration = make(map[string]any)
	rwMutex.Unlock()

	baseConfig := map[string]any{"base": "config"}
	UpdateConfigurationBaseKey(baseConfig)

	assert.Equal(t, baseConfig, wellKnownConfiguration[baseKeyWellKnown])
}

func TestNewRegistration(t *testing.T) {
	registration := NewRegistration()

	assert.NotNil(t, registration)
	assert.Equal(t, "wellknown", registration.ServiceOptions.Namespace)
	assert.NotNil(t, registration.ServiceOptions.ServiceDesc)
	assert.NotNil(t, registration.ServiceOptions.ConnectRPCFunc)
	assert.NotNil(t, registration.ServiceOptions.RegisterFunc)
}
