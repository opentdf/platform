package wellknownconfiguration

import (
	"reflect"
	"testing"

	"connectrpc.com/connect"
	wellknown "github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test struct for conversion testing
type TestStruct struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Count       int    `json:"count"`
	Active      bool   `json:"active"`
}

type NestedStruct struct {
	ID     string     `json:"id"`
	Data   TestStruct `json:"data"`
	Items  []string   `json:"items"`
	Active *bool      `json:"active,omitempty"`
}

func TestRegisterConfiguration(t *testing.T) {
	// Clear configuration before test
	wellKnownConfiguration = make(map[string]any)

	tests := []struct {
		name      string
		namespace string
		config    any
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "Register simple string",
			namespace: "test1",
			config:    "simple string",
			wantErr:   false,
		},
		{
			name:      "Register map",
			namespace: "test2",
			config:    map[string]string{"key": "value"},
			wantErr:   false,
		},
		{
			name:      "Register slice",
			namespace: "test3",
			config:    []string{"item1", "item2"},
			wantErr:   false,
		},
		{
			name:      "Register duplicate namespace",
			namespace: "test1", // Already registered above
			config:    "duplicate",
			wantErr:   true,
			errMsg:    "already registered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RegisterConfiguration(tt.namespace, tt.config)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.config, wellKnownConfiguration[tt.namespace])
			}
		})
	}
}

func TestUpdateConfigurationBaseKey(t *testing.T) {
	// Clear configuration before test
	wellKnownConfiguration = make(map[string]any)

	testConfig := map[string]string{"test": "value"}

	UpdateConfigurationBaseKey(testConfig)

	assert.Equal(t, testConfig, wellKnownConfiguration[baseKeyWellKnown])

	// Test update
	newConfig := map[string]string{"new": "value"}
	UpdateConfigurationBaseKey(newConfig)

	assert.Equal(t, newConfig, wellKnownConfiguration[baseKeyWellKnown])
}

func TestConvertToSerializable(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
	}{
		{
			name:     "Basic string",
			input:    "test string",
			expected: "test string",
		},
		{
			name:     "Basic int",
			input:    42,
			expected: 42,
		},
		{
			name:     "Basic bool",
			input:    true,
			expected: true,
		},
		{
			name:     "String slice",
			input:    []string{"a", "b", "c"},
			expected: []interface{}{"a", "b", "c"},
		},
		{
			name:     "Simple struct",
			input:    TestStruct{Name: "test", Description: "desc", Count: 5, Active: true},
			expected: map[string]interface{}{"name": "test", "description": "desc", "count": 5, "active": true},
		},
		{
			name: "Struct slice",
			input: []TestStruct{
				{Name: "first", Description: "first desc", Count: 1, Active: true},
				{Name: "second", Description: "second desc", Count: 2, Active: false},
			},
			expected: []interface{}{
				map[string]interface{}{"name": "first", "description": "first desc", "count": 1, "active": true},
				map[string]interface{}{"name": "second", "description": "second desc", "count": 2, "active": false},
			},
		},
		{
			name: "Nested struct",
			input: NestedStruct{
				ID:     "123",
				Data:   TestStruct{Name: "nested", Description: "nested desc", Count: 10, Active: false},
				Items:  []string{"item1", "item2"},
				Active: nil,
			},
			expected: map[string]interface{}{
				"id": "123",
				"data": map[string]interface{}{
					"name":        "nested",
					"description": "nested desc",
					"count":       10,
					"active":      false,
				},
				"items":  []interface{}{"item1", "item2"},
				"active": nil,
			},
		},
		{
			name:     "Map with interface values",
			input:    map[string]interface{}{"key1": "value1", "key2": 42, "key3": true},
			expected: map[string]interface{}{"key1": "value1", "key2": 42, "key3": true},
		},
		{
			name:     "Nil value",
			input:    nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertToSerializable(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertValue(t *testing.T) {
	t.Run("Invalid value", func(t *testing.T) {
		var invalidValue reflect.Value
		result := convertValue(invalidValue)
		if result.IsValid() {
			assert.Nil(t, result.Interface())
		} else {
			assert.False(t, result.IsValid())
		}
	})

	t.Run("Nil pointer", func(t *testing.T) {
		var nilPtr *string
		result := convertValue(reflect.ValueOf(nilPtr))
		if result.IsValid() {
			assert.Nil(t, result.Interface())
		} else {
			assert.False(t, result.IsValid())
		}
	})

	t.Run("Valid pointer", func(t *testing.T) {
		str := "test"
		ptr := &str
		result := convertValue(reflect.ValueOf(ptr))
		assert.Equal(t, "test", result.Interface())
	})

	t.Run("Nil interface", func(t *testing.T) {
		var nilInterface interface{}
		result := convertValue(reflect.ValueOf(&nilInterface).Elem())
		if result.IsValid() {
			assert.Nil(t, result.Interface())
		} else {
			assert.False(t, result.IsValid())
		}
	})
}

func TestConvertStruct(t *testing.T) {
	t.Run("Struct with unexported fields", func(t *testing.T) {
		type StructWithPrivate struct {
			Public  string `json:"public"`
			private string `json:"private"` //nolint: govet // needed for testing
		}

		input := StructWithPrivate{Public: "visible", private: "hidden"}
		result := convertStruct(reflect.ValueOf(input))

		expected := map[string]interface{}{"public": "visible"}
		assert.Equal(t, expected, result.Interface())
	})

	t.Run("Struct with json tags", func(t *testing.T) {
		type TaggedStruct struct {
			Field1 string `json:"custom_name"`
			Field2 string `json:"another_name,omitempty"`
			Field3 string `json:",omitempty"`
			Field4 string `json:"-"`
		}

		input := TaggedStruct{
			Field1: "value1",
			Field2: "value2",
			Field3: "value3",
			Field4: "value4",
		}
		result := convertStruct(reflect.ValueOf(input))

		expected := map[string]interface{}{
			"custom_name":  "value1",
			"another_name": "value2",
			"Field3":       "value3",
			// Field4 should be excluded due to json:"-"
		}
		assert.Equal(t, expected, result.Interface())
	})
}

func TestConvertSlice(t *testing.T) {
	t.Run("Empty slice", func(t *testing.T) {
		input := []string{}
		result := convertSlice(reflect.ValueOf(input))
		assert.Equal(t, []interface{}{}, result.Interface())
	})

	t.Run("Mixed type slice", func(t *testing.T) {
		input := []interface{}{1, "string", true}
		result := convertSlice(reflect.ValueOf(input))
		assert.Equal(t, []interface{}{1, "string", true}, result.Interface())
	})
}

func TestConvertMap(t *testing.T) {
	t.Run("String key map", func(t *testing.T) {
		input := map[string]int{"one": 1, "two": 2}
		result := convertMap(reflect.ValueOf(input))
		expected := map[string]interface{}{"one": 1, "two": 2}
		assert.Equal(t, expected, result.Interface())
	})

	t.Run("Non-string key map", func(t *testing.T) {
		input := map[int]string{1: "one", 2: "two"}
		result := convertMap(reflect.ValueOf(input))
		expected := map[string]interface{}{"1": "one", "2": "two"}
		assert.Equal(t, expected, result.Interface())
	})
}

func TestWellKnownService_GetWellKnownConfiguration(t *testing.T) {
	// Setup
	wellKnownConfiguration = make(map[string]any)
	logger := logger.CreateTestLogger()
	service := WellKnownService{logger: logger}

	t.Run("Empty configuration", func(t *testing.T) {
		req := connect.NewRequest(&wellknown.GetWellKnownConfigurationRequest{})

		resp, err := service.GetWellKnownConfiguration(t.Context(), req)

		require.NoError(t, err)
		assert.NotNil(t, resp.Msg.GetConfiguration())
		assert.Empty(t, resp.Msg.GetConfiguration().GetFields())
	})

	t.Run("With simple configuration", func(t *testing.T) {
		// Register some test configuration
		testConfig := map[string]interface{}{
			"string_val": "test",
			"int_val":    42,
			"bool_val":   true,
		}
		wellKnownConfiguration["test"] = testConfig

		req := connect.NewRequest(&wellknown.GetWellKnownConfigurationRequest{})

		resp, err := service.GetWellKnownConfiguration(t.Context(), req)

		require.NoError(t, err)
		assert.NotNil(t, resp.Msg.GetConfiguration())
		assert.Contains(t, resp.Msg.GetConfiguration().GetFields(), "test")
	})

	t.Run("With struct configuration", func(t *testing.T) {
		// Clear previous config
		wellKnownConfiguration = make(map[string]any)

		// Register struct configuration that needs conversion
		testStructs := []TestStruct{
			{Name: "manager1", Description: "First manager", Count: 1, Active: true},
			{Name: "manager2", Description: "Second manager", Count: 2, Active: false},
		}
		wellKnownConfiguration["key_managers"] = testStructs

		req := connect.NewRequest(&wellknown.GetWellKnownConfigurationRequest{})

		resp, err := service.GetWellKnownConfiguration(t.Context(), req)

		require.NoError(t, err)
		assert.NotNil(t, resp.Msg.GetConfiguration())
		assert.Contains(t, resp.Msg.GetConfiguration().GetFields(), "key_managers")

		// Verify the struct was converted properly
		keyManagersField := resp.Msg.GetConfiguration().GetFields()["key_managers"]
		assert.NotNil(t, keyManagersField)
	})

	t.Run("With complex nested configuration", func(t *testing.T) {
		// Clear previous config
		wellKnownConfiguration = make(map[string]any)

		// Register complex nested configuration
		complexConfig := map[string]interface{}{
			"simple": "value",
			"nested": NestedStruct{
				ID: "test-id",
				Data: TestStruct{
					Name:        "nested-test",
					Description: "nested description",
					Count:       99,
					Active:      true,
				},
				Items: []string{"item1", "item2", "item3"},
			},
			"struct_slice": []TestStruct{
				{Name: "first", Count: 1},
				{Name: "second", Count: 2},
			},
		}
		wellKnownConfiguration["complex"] = complexConfig

		req := connect.NewRequest(&wellknown.GetWellKnownConfigurationRequest{})

		resp, err := service.GetWellKnownConfiguration(t.Context(), req)

		require.NoError(t, err)
		assert.NotNil(t, resp.Msg.GetConfiguration())
		assert.Contains(t, resp.Msg.GetConfiguration().GetFields(), "complex")
	})
}

func TestNewRegistration(t *testing.T) {
	registration := NewRegistration()

	assert.NotNil(t, registration)
	assert.Equal(t, "wellknown", registration.ServiceOptions.Namespace)
	assert.NotNil(t, registration.ServiceOptions.ServiceDesc)
	assert.NotNil(t, registration.ServiceOptions.ConnectRPCFunc)
	assert.NotNil(t, registration.ServiceOptions.GRPCGatewayFunc)
	assert.NotNil(t, registration.ServiceOptions.RegisterFunc)
}

// Benchmark tests for performance
func BenchmarkConvertToSerializable(b *testing.B) {
	testData := []TestStruct{
		{Name: "manager1", Description: "First manager", Count: 1, Active: true},
		{Name: "manager2", Description: "Second manager", Count: 2, Active: false},
		{Name: "manager3", Description: "Third manager", Count: 3, Active: true},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = convertToSerializable(testData)
	}
}

func BenchmarkConvertNestedStruct(b *testing.B) {
	testData := NestedStruct{
		ID: "benchmark-test",
		Data: TestStruct{
			Name:        "benchmark",
			Description: "benchmark test",
			Count:       1000,
			Active:      true,
		},
		Items: []string{"item1", "item2", "item3", "item4", "item5"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = convertToSerializable(testData)
	}
}
