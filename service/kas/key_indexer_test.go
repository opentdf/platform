package kas

import (
	"context"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/trust"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type MockKeyAccessServerRegistryClient struct {
	mock.Mock
}

func (m *MockKeyAccessServerRegistryClient) CreateKeyAccessServer(context.Context, *kasregistry.CreateKeyAccessServerRequest) (*kasregistry.CreateKeyAccessServerResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockKeyAccessServerRegistryClient) GetKeyAccessServer(context.Context, *kasregistry.GetKeyAccessServerRequest) (*kasregistry.GetKeyAccessServerResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockKeyAccessServerRegistryClient) ListKeyAccessServers(context.Context, *kasregistry.ListKeyAccessServersRequest) (*kasregistry.ListKeyAccessServersResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockKeyAccessServerRegistryClient) UpdateKeyAccessServer(context.Context, *kasregistry.UpdateKeyAccessServerRequest) (*kasregistry.UpdateKeyAccessServerResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockKeyAccessServerRegistryClient) DeleteKeyAccessServer(context.Context, *kasregistry.DeleteKeyAccessServerRequest) (*kasregistry.DeleteKeyAccessServerResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockKeyAccessServerRegistryClient) ListKeyAccessServerGrants(context.Context, *kasregistry.ListKeyAccessServerGrantsRequest) (*kasregistry.ListKeyAccessServerGrantsResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockKeyAccessServerRegistryClient) CreateKey(context.Context, *kasregistry.CreateKeyRequest) (*kasregistry.CreateKeyResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockKeyAccessServerRegistryClient) GetKey(context.Context, *kasregistry.GetKeyRequest) (*kasregistry.GetKeyResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockKeyAccessServerRegistryClient) ListKeys(ctx context.Context, req *kasregistry.ListKeysRequest) (*kasregistry.ListKeysResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	var resp *kasregistry.ListKeysResponse
	var ok bool
	if resp, ok = args.Get(0).(*kasregistry.ListKeysResponse); !ok {
		return nil, args.Error(1)
	}
	return resp, args.Error(1)
}

func (m *MockKeyAccessServerRegistryClient) UpdateKey(context.Context, *kasregistry.UpdateKeyRequest) (*kasregistry.UpdateKeyResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockKeyAccessServerRegistryClient) RotateKey(context.Context, *kasregistry.RotateKeyRequest) (*kasregistry.RotateKeyResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockKeyAccessServerRegistryClient) SetBaseKey(context.Context, *kasregistry.SetBaseKeyRequest) (*kasregistry.SetBaseKeyResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockKeyAccessServerRegistryClient) GetBaseKey(context.Context, *kasregistry.GetBaseKeyRequest) (*kasregistry.GetBaseKeyResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockKeyAccessServerRegistryClient) ListKeyMappings(context.Context, *kasregistry.ListKeyMappingsRequest) (*kasregistry.ListKeyMappingsResponse, error) {
	return nil, errors.New("not implemented")
}

type KeyIndexTestSuite struct {
	suite.Suite
	rsaKey trust.KeyDetails
}

func (s *KeyIndexTestSuite) SetupTest() {
	s.rsaKey = &KeyAdapter{
		key: &policy.KasKey{
			KasId: "test-kas-id",
			Key: &policy.AsymmetricKey{
				Id:           "test-id",
				KeyId:        "test-key-id",
				KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
				KeyStatus:    policy.KeyStatus_KEY_STATUS_ACTIVE,
				KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
				PublicKeyCtx: &policy.PublicKeyCtx{
					Pem: "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF3SEw0TkVrOFpDa0JzNjZXQVpWagpIS3NseDRseWdmaXN3aW42RUx5OU9OczZLVDRYa1crRGxsdExtck14bHZkbzVRaDg1UmFZS01mWUdDTWtPM0dGCkFsK0JOeWFOM1kwa0N1QjNPU2ErTzdyMURhNVZteVVuaEJNbFBrYnVPY1Y0cjlLMUhOSGd3eDl2UFp3RjRpQW8KQStEY1VBcWFEeHlvYjV6enNGZ0hUNjJHLzdLdEtiZ2hYT1dCanRUYUl1ZHpsK2FaSjFPemY0U1RkOXhST2QrMQordVo2VG1ocmFEUm9zdDUrTTZUN0toL2lGWk40TTFUY2hwWXU1TDhKR2tVaG9YaEdZcHUrMGczSzlqYlh6RVh5CnpJU3VXN2d6SGRWYUxvcnBkQlNkRHpOWkNvTFVoL0U1T3d5TFZFQkNKaDZJVUtvdWJ5WHVucnIxQnJmK2tLbEsKeHdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
				},
				ProviderConfig: &policy.KeyProviderConfig{
					Id:         "test-provider-id",
					Name:       "openbao-west",
					Manager:    "openbao",
					ConfigJson: []byte("config"),
				},
			},
		},
	}
}
func (s *KeyIndexTestSuite) TearDownTest() {}

func (s *KeyIndexTestSuite) TestKeyDetails() {
	s.Equal("test-key-id", string(s.rsaKey.ID()))
	s.Equal(ocrypto.RSA2048Key, s.rsaKey.Algorithm())
	s.False(s.rsaKey.IsLegacy())
	s.Equal("openbao", s.rsaKey.System())
	s.Equal("config", string(s.rsaKey.ProviderConfig().GetConfigJson()))
}

func (s *KeyIndexTestSuite) TestKeyExportPublicKey_JWKFormat() {
	// Export JWK format
	jwkString, err := s.rsaKey.ExportPublicKey(context.Background(), trust.KeyTypeJWK)
	s.Require().NoError(err)
	s.Require().NotEmpty(jwkString)

	rsaKey, err := jwk.ParseKey([]byte(jwkString))
	s.Require().NoError(err)
	s.Require().NotNil(rsaKey)
}

func (s *KeyIndexTestSuite) TestKeyExportPublicKey_PKCSFormat() {
	// Export JWK format
	pem, err := s.rsaKey.ExportPublicKey(context.Background(), trust.KeyTypePKCS8)
	s.Require().NoError(err)
	s.Require().NotEmpty(pem)

	keyAdapter, ok := s.rsaKey.(*KeyAdapter)
	s.Require().True(ok)
	pubCtx := keyAdapter.key.GetKey().GetPublicKeyCtx()
	s.Require().NotEmpty(pubCtx)
	base64Pem := ocrypto.Base64Encode([]byte(pem))
	s.Equal(pubCtx.GetPem(), string(base64Pem))
}

func (s *KeyIndexTestSuite) TestKeyDetails_Legacy() {
	legacyKey := &KeyAdapter{
		key: &policy.KasKey{
			KasId: "test-kas-id",
			Key: &policy.AsymmetricKey{
				Id:           "test-id-legacy",
				KeyId:        "test-key-id-legacy",
				KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
				KeyStatus:    policy.KeyStatus_KEY_STATUS_ACTIVE,
				KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
				Legacy:       true, // Mark as legacy
				PublicKeyCtx: &policy.PublicKeyCtx{
					Pem: "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF3SEw0TkVrOFpDa0JzNjZXQVpWagpIS3NseDRseWdmaXN3aW42RUx5OU9OczZLVDRYa1crRGxsdExtck14bHZkbzVRaDg1UmFZS01mWUdDTWtPM0dGCkFsK0JOeWFOM1kwa0N1QjNPU2ErTzdyMURhNVZteVVuaEJNbFBrYnVPY1Y0cjlLMUhOSGd3eDl2UFp3RjRpQW8KQStEY1VBcWFEeHlvYjV6enNGZ0hUNjJHLzdLdEtiZ2hYT1dCanRUYUl1ZHpsK2FaSjFPemY0U1RkOXhST2QrMQordVo2VG1ocmFEUm9zdDUrTTZUN0toL2lGWk40TTFUY2hwWXU1TDhKR2tVaG9YaEdZcHUrMGczSzlqYlh6RVh5CnpJU3VXN2d6SGRWYUxvcnBkQlNkRHpOWkNvTFVoL0U1T3d5TFZFQkNKaDZJVUtvdWJ5WHVucnIxQnJmK2tLbEsKeHdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
				},
			},
		},
	}
	s.True(legacyKey.IsLegacy())
}

func (s *KeyIndexTestSuite) TestListKeysWith() {
	mockClient := new(MockKeyAccessServerRegistryClient)
	keyIndexer := &KeyIndexer{
		sdk: &sdk.SDK{
			KeyAccessServerRegistry: mockClient,
		},
	}

	// Mock the ListKeys function to return a specific key based on the legacy flag
	mockClient.On("ListKeys", mock.Anything, mock.MatchedBy(func(req *kasregistry.ListKeysRequest) bool {
		return req.GetLegacy()
	})).Return(&kasregistry.ListKeysResponse{
		KasKeys: []*policy.KasKey{
			{
				Key: &policy.AsymmetricKey{
					KeyId: "legacy-key-id",
				},
			},
		},
	}, nil)

	mockClient.On("ListKeys", mock.Anything, mock.MatchedBy(func(req *kasregistry.ListKeysRequest) bool {
		return req.Legacy == nil
	})).Return(&kasregistry.ListKeysResponse{
		KasKeys: []*policy.KasKey{
			{
				Key: &policy.AsymmetricKey{
					KeyId: "non-legacy-key-id",
				},
			},
			{
				Key: &policy.AsymmetricKey{
					KeyId: "legacy-key-id",
				},
			},
		},
	}, nil)

	// Test with legacy flag set to true
	keys, err := keyIndexer.ListKeysWith(context.Background(), trust.ListKeyOptions{LegacyOnly: true})
	s.Require().NoError(err)
	s.Len(keys, 1)
	s.Equal("legacy-key-id", string(keys[0].ID()))

	// Test with legacy flag set to false
	keys, err = keyIndexer.ListKeysWith(context.Background(), trust.ListKeyOptions{LegacyOnly: false})
	s.Require().NoError(err)
	s.Len(keys, 2)
	s.Equal("non-legacy-key-id", string(keys[0].ID()))
	s.Equal("legacy-key-id", string(keys[1].ID()))
}

func (s *KeyIndexTestSuite) TestListKeys() {
	mockClient := new(MockKeyAccessServerRegistryClient)
	keyIndexer := &KeyIndexer{
		sdk: &sdk.SDK{
			KeyAccessServerRegistry: mockClient,
		},
	}

	mockClient.On("ListKeys", mock.Anything, mock.MatchedBy(func(req *kasregistry.ListKeysRequest) bool {
		return !req.GetLegacy()
	})).Return(&kasregistry.ListKeysResponse{
		KasKeys: []*policy.KasKey{
			{
				Key: &policy.AsymmetricKey{
					KeyId: "test-key-id",
				},
			},
		},
	}, nil)

	keys, err := keyIndexer.ListKeys(context.Background())
	s.Require().NoError(err)
	s.Len(keys, 1)
	s.Equal("test-key-id", string(keys[0].ID()))
}

func (s *KeyIndexTestSuite) TestFindKeyByAlgorithm() {
	mockClient := new(MockKeyAccessServerRegistryClient)
	keyIndexer := &KeyIndexer{
		sdk: &sdk.SDK{
			KeyAccessServerRegistry: mockClient,
		},
	}

	mockClient.On("ListKeys", mock.Anything, mock.MatchedBy(func(req *kasregistry.ListKeysRequest) bool {
		return req.GetKeyAlgorithm() == policy.Algorithm_ALGORITHM_RSA_2048 && (req.Legacy != nil && req.GetLegacy() == false)
	})).Return(&kasregistry.ListKeysResponse{
		KasKeys: []*policy.KasKey{
			{
				Key: &policy.AsymmetricKey{
					KeyId:        "test-key-id",
					KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
					KeyStatus:    policy.KeyStatus_KEY_STATUS_ACTIVE,
				},
			},
		},
	}, nil)

	mockClient.On("ListKeys", mock.Anything, mock.MatchedBy(func(req *kasregistry.ListKeysRequest) bool {
		return req.GetKeyAlgorithm() == policy.Algorithm_ALGORITHM_RSA_2048 && req.Legacy == nil
	})).Return(&kasregistry.ListKeysResponse{
		KasKeys: []*policy.KasKey{
			{
				Key: &policy.AsymmetricKey{
					KeyId:        "test-legacy-key-id",
					KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
					KeyStatus:    policy.KeyStatus_KEY_STATUS_ACTIVE,
				},
			},
			{
				Key: &policy.AsymmetricKey{
					KeyId:        "test-key-id",
					KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
					KeyStatus:    policy.KeyStatus_KEY_STATUS_ACTIVE,
				},
			},
		},
	}, nil)

	key, err := keyIndexer.FindKeyByAlgorithm(context.Background(), string(ocrypto.RSA2048Key), false)
	s.Require().NoError(err)
	s.NotNil(key)
	s.Equal("test-key-id", string(key.ID()))

	key, err = keyIndexer.FindKeyByAlgorithm(context.Background(), string(ocrypto.RSA2048Key), true)
	s.Require().NoError(err)
	s.NotNil(key)
	s.Equal("test-legacy-key-id", string(key.ID()))
}

func TestNewPlatformKeyIndexTestSuite(t *testing.T) {
	suite.Run(t, new(KeyIndexTestSuite))
}
