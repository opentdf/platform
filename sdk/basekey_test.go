package sdk

import (
	"context"
	"errors"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	wellknownpb "github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	testPem    = "a-pem"
	testKasURI = "https://test-kas.example.com"
	testKid    = "test-key-id"
)

// Mock implementation of the WellKnownServiceClient for testing
type mockWellKnownService struct {
	configMap map[string]interface{}
	err       error
	called    bool
}

// Test suite for getBaseKey function
type BaseKeyTestSuite struct {
	suite.Suite
	sdk SDK
}

func newMockWellKnownService(configMap map[string]interface{}, err error) *mockWellKnownService {
	return &mockWellKnownService{
		configMap: configMap,
		err:       err,
		called:    false,
	}
}

func (m *mockWellKnownService) GetWellKnownConfiguration(
	_ context.Context,
	_ *wellknownpb.GetWellKnownConfigurationRequest,
) (*wellknownpb.GetWellKnownConfigurationResponse, error) {
	m.called = true

	if m.err != nil {
		return nil, m.err
	}

	// Convert map to structpb
	configStruct, err := structpb.NewStruct(m.configMap)
	if err != nil {
		return nil, err
	}

	return &wellknownpb.GetWellKnownConfigurationResponse{
		Configuration: configStruct,
	}, nil
}

func TestGetKasKeyAlg(t *testing.T) {
	tests := []struct {
		name     string
		algStr   string
		expected policy.Algorithm
	}{
		{
			name:     "rsa 2048",
			algStr:   string(ocrypto.RSA2048Key),
			expected: policy.Algorithm_ALGORITHM_RSA_2048,
		},
		{
			name:     "rsa 4096",
			algStr:   "rsa:4096",
			expected: policy.Algorithm_ALGORITHM_RSA_4096,
		},
		{
			name:     "ec secp256r1",
			algStr:   string(ocrypto.EC256Key),
			expected: policy.Algorithm_ALGORITHM_EC_P256,
		},
		{
			name:     "ec secp384r1",
			algStr:   string(ocrypto.EC384Key),
			expected: policy.Algorithm_ALGORITHM_EC_P384,
		},
		{
			name:     "ec secp521r1",
			algStr:   string(ocrypto.EC521Key),
			expected: policy.Algorithm_ALGORITHM_EC_P521,
		},
		{
			name:     "unsupported algorithm",
			algStr:   "unsupported",
			expected: policy.Algorithm_ALGORITHM_UNSPECIFIED,
		},
		{
			name:     "empty string",
			algStr:   "",
			expected: policy.Algorithm_ALGORITHM_UNSPECIFIED,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := getKasKeyAlg(test.algStr)
			assert.Equal(t, test.expected, result, "Algorithm enum mismatch")
		})
	}
}

func TestFormatAlg(t *testing.T) {
	tests := []struct {
		name        string
		alg         policy.Algorithm
		expected    string
		expectError bool
	}{
		{
			name:        "RSA 2048",
			alg:         policy.Algorithm_ALGORITHM_RSA_2048,
			expected:    string(ocrypto.RSA2048Key),
			expectError: false,
		},
		{
			name:        "RSA 4096",
			alg:         policy.Algorithm_ALGORITHM_RSA_4096,
			expected:    "rsa:4096",
			expectError: false,
		},
		{
			name:        "EC P256",
			alg:         policy.Algorithm_ALGORITHM_EC_P256,
			expected:    string(ocrypto.EC256Key),
			expectError: false,
		},
		{
			name:        "EC P384",
			alg:         policy.Algorithm_ALGORITHM_EC_P384,
			expected:    string(ocrypto.EC384Key),
			expectError: false,
		},
		{
			name:        "EC P521",
			alg:         policy.Algorithm_ALGORITHM_EC_P521,
			expected:    string(ocrypto.EC521Key), // Note: This matches the implementation
			expectError: false,
		},
		{
			name:        "Unspecified algorithm",
			alg:         policy.Algorithm_ALGORITHM_UNSPECIFIED,
			expected:    "",
			expectError: true,
		},
		{
			name:        "Invalid algorithm",
			alg:         policy.Algorithm(99),
			expected:    "",
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := formatAlg(test.alg)
			if test.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expected, result, "Algorithm string mismatch")
			}
		})
	}
}

func (s *BaseKeyTestSuite) SetupTest() {
	s.sdk = SDK{}
}

func TestBaseKeySuite(t *testing.T) {
	suite.Run(t, new(BaseKeyTestSuite))
}

func (s *BaseKeyTestSuite) TestGetBaseKeySuccess() {
	// Create a valid base key configuration
	wellknownConfig := map[string]interface{}{
		baseKeyWellKnown: map[string]interface{}{
			"kas_uri": "https://test-kas.example.com",
			baseKeyPublicKey: map[string]interface{}{
				baseKeyAlg: "rsa:2048",
				"kid":      testKid,
				"pem":      testPem,
			},
		},
	}

	// Set up mock wellknown service
	mockService := newMockWellKnownService(wellknownConfig, nil)
	s.sdk.wellknownConfiguration = mockService

	// Call exported API
	baseKey, err := s.sdk.GetBaseKey(s.T().Context())

	// Validate result
	s.Require().NoError(err)
	s.Require().True(mockService.called)
	s.Require().NotNil(baseKey)
	s.Require().Equal(testKasURI, baseKey.GetKasUri())
	s.Require().NotNil(baseKey.GetPublicKey())
	s.Require().Equal(testKid, baseKey.GetPublicKey().GetKid())
	s.Require().Equal(policy.Algorithm_ALGORITHM_RSA_2048, baseKey.GetPublicKey().GetAlgorithm())
	s.Require().Equal(testPem, baseKey.GetPublicKey().GetPem())
}

func (s *BaseKeyTestSuite) TestGetBaseKeyServiceError() {
	// Setup mock service with error
	mockService := newMockWellKnownService(nil, errors.New("service unavailable"))
	s.sdk.wellknownConfiguration = mockService

	// Call exported API
	baseKey, err := s.sdk.GetBaseKey(s.T().Context())

	// Validate result
	s.Require().True(mockService.called)
	s.Require().Error(err)
	s.Require().Nil(baseKey)
	s.Require().Contains(err.Error(), "unable to retrieve config information")
	s.Require().Contains(err.Error(), "service unavailable")
}

func (s *BaseKeyTestSuite) TestGetBaseKeyMissingBaseKey() {
	// Create wellknown configuration without base key
	wellknownConfig := map[string]interface{}{
		"some_other_config": "value",
	}

	mockService := newMockWellKnownService(wellknownConfig, nil)
	s.sdk.wellknownConfiguration = mockService

	// Call exported API
	baseKey, err := s.sdk.GetBaseKey(s.T().Context())

	// Validate result
	s.Require().True(mockService.called)
	s.Require().Error(err)
	s.Require().Nil(baseKey)
	s.Require().ErrorIs(err, ErrBaseKeyNotFound)
}

func (s *BaseKeyTestSuite) TestGetBaseKeyInvalidBaseKeyFormat() {
	wellknownConfig := map[string]interface{}{
		baseKeyWellKnown: "invalid-base-key",
	}

	mockService := newMockWellKnownService(wellknownConfig, nil)
	s.sdk.wellknownConfiguration = mockService

	// Call exported API
	baseKey, err := s.sdk.GetBaseKey(s.T().Context())

	// Validate result
	s.Require().True(mockService.called)
	s.Require().Error(err)
	s.Require().Nil(baseKey)
	s.Require().ErrorIs(err, ErrBaseKeyInvalidFormat)
}

func (s *BaseKeyTestSuite) TestGetBaseKeyEmptyBaseKey() {
	// Create empty base key map
	wellknownConfig := map[string]interface{}{
		baseKeyWellKnown: map[string]interface{}{},
	}

	mockService := newMockWellKnownService(wellknownConfig, nil)
	s.sdk.wellknownConfiguration = mockService

	// Call exported API
	baseKey, err := s.sdk.GetBaseKey(s.T().Context())

	// Validate result
	s.Require().True(mockService.called)
	s.Require().Error(err)
	s.Require().Nil(baseKey)
	s.Require().ErrorIs(err, ErrBaseKeyEmpty)
}

func (s *BaseKeyTestSuite) TestGetBaseKeyMissingPublicKey() {
	// Create base key without public_key field
	wellknownConfig := map[string]interface{}{
		baseKeyWellKnown: map[string]interface{}{
			"kas_uri": "https://test-kas.example.com",
			// Missing public_key field
		},
	}

	mockService := newMockWellKnownService(wellknownConfig, nil)
	s.sdk.wellknownConfiguration = mockService

	// Call exported API
	baseKey, err := s.sdk.GetBaseKey(s.T().Context())

	// Validate result
	s.Require().True(mockService.called)
	s.Require().Error(err)
	s.Require().Nil(baseKey)
	s.Require().ErrorIs(err, ErrBaseKeyInvalidFormat)
}

func (s *BaseKeyTestSuite) TestGetBaseKeyInvalidPublicKey() {
	// Create base key with invalid public_key (string instead of map)
	wellknownConfig := map[string]interface{}{
		baseKeyWellKnown: map[string]interface{}{
			"kas_uri":        "https://test-kas.example.com",
			baseKeyPublicKey: "invalid-public-key", // Should be a map
		},
	}

	mockService := newMockWellKnownService(wellknownConfig, nil)
	s.sdk.wellknownConfiguration = mockService

	// Call exported API
	baseKey, err := s.sdk.GetBaseKey(s.T().Context())

	// Validate result
	s.Require().True(mockService.called)
	s.Require().Error(err)
	s.Require().Nil(baseKey)
	s.Require().ErrorIs(err, ErrBaseKeyInvalidFormat)
}
