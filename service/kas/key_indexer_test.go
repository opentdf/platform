package kas

import (
	"context"
	"encoding/json"
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

const (
	testKeyID     = "test-key-id"
	defaultKASURI = "https://default-kas.example.com"
	requestKASURI = "https://request-kas.example.com"
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

func (m *MockKeyAccessServerRegistryClient) ListKeyAccessServerGrants(context.Context, *kasregistry.ListKeyAccessServerGrantsRequest) (*kasregistry.ListKeyAccessServerGrantsResponse, error) { //nolint:staticcheck // Compatibility test for deprecated RPC.
	return nil, errors.New("not implemented")
}

func (m *MockKeyAccessServerRegistryClient) CreateKey(context.Context, *kasregistry.CreateKeyRequest) (*kasregistry.CreateKeyResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *MockKeyAccessServerRegistryClient) GetKey(ctx context.Context, req *kasregistry.GetKeyRequest) (*kasregistry.GetKeyResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	resp, ok := args.Get(0).(*kasregistry.GetKeyResponse)
	if !ok {
		return nil, args.Error(1)
	}
	return resp, args.Error(1)
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
				KeyId:        testKeyID,
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
	s.Equal(testKeyID, string(s.rsaKey.ID()))
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
	keysByURI := map[string][]*policy.KasKey{
		defaultKASURI: {
			{Key: &policy.AsymmetricKey{KeyId: "default-active-key"}},
			{Key: &policy.AsymmetricKey{KeyId: "default-legacy-key", Legacy: true}},
		},
		requestKASURI: {
			{Key: &policy.AsymmetricKey{KeyId: "request-active-key"}},
			{Key: &policy.AsymmetricKey{KeyId: "request-legacy-key", Legacy: true}},
		},
	}
	for _, test := range []struct {
		name        string
		fromKAO     bool
		opts        trust.ListKeyOptions
		expectedURI string
		expectedIDs []trust.KeyIdentifier
	}{
		{
			name:        "default URI with legacy filter",
			opts:        trust.ListKeyOptions{LegacyOnly: true},
			expectedURI: defaultKASURI,
			expectedIDs: []trust.KeyIdentifier{"default-legacy-key"},
		},
		{
			name:        "default URI without legacy filter",
			expectedURI: defaultKASURI,
			expectedIDs: []trust.KeyIdentifier{"default-active-key", "default-legacy-key"},
		},
		{
			name:        "disabled kao read - ignores request URI",
			opts:        trust.ListKeyOptions{KeyOptions: trust.KeyOptions{KASURI: requestKASURI}, LegacyOnly: true},
			expectedURI: defaultKASURI,
			expectedIDs: []trust.KeyIdentifier{"default-legacy-key"},
		},
		{
			name:        "enabled kao read - defaults empty URI",
			fromKAO:     true,
			opts:        trust.ListKeyOptions{LegacyOnly: true},
			expectedURI: defaultKASURI,
			expectedIDs: []trust.KeyIdentifier{"default-legacy-key"},
		},
		{
			name:        "request URI with legacy filter",
			fromKAO:     true,
			opts:        trust.ListKeyOptions{KeyOptions: trust.KeyOptions{KASURI: requestKASURI}, LegacyOnly: true},
			expectedURI: requestKASURI,
			expectedIDs: []trust.KeyIdentifier{"request-legacy-key"},
		},
		{
			name:        "request URI without legacy filter",
			fromKAO:     true,
			opts:        trust.ListKeyOptions{KeyOptions: trust.KeyOptions{KASURI: requestKASURI}},
			expectedURI: requestKASURI,
			expectedIDs: []trust.KeyIdentifier{"request-active-key", "request-legacy-key"},
		},
	} {
		s.Run(test.name, func() {
			mockClient := new(MockKeyAccessServerRegistryClient)
			log, buf := newBufferLogger()
			keyIndexer := NewPlatformKeyIndexer(&sdk.SDK{KeyAccessServerRegistry: mockClient}, defaultKASURI, test.fromKAO, log)

			response := &kasregistry.ListKeysResponse{}
			mockClient.On("ListKeys", mock.Anything, mock.MatchedBy(func(req *kasregistry.ListKeysRequest) bool {
				if req.GetKasUri() != test.expectedURI {
					return false
				}
				if test.opts.LegacyOnly {
					return req.Legacy != nil && req.GetLegacy()
				}
				return req.Legacy == nil
			})).Run(func(args mock.Arguments) {
				req, ok := args.Get(1).(*kasregistry.ListKeysRequest)
				s.Require().True(ok)
				for _, key := range keysByURI[req.GetKasUri()] {
					if !req.GetLegacy() || key.GetKey().GetLegacy() {
						response.KasKeys = append(response.KasKeys, key)
					}
				}
			}).Return(response, nil).Once()

			keys, err := keyIndexer.ListKeysWith(s.T().Context(), test.opts)
			s.Require().NoError(err)
			ids := make([]trust.KeyIdentifier, len(keys))
			for i, key := range keys {
				ids[i] = key.ID()
			}
			s.Equal(test.expectedIDs, ids)
			s.assertKeyIndexerLog(buf.Bytes(), test.expectedURI, keyIndexer)
			mockClient.AssertExpectations(s.T())
		})
	}
}

func (s *KeyIndexTestSuite) TestListKeys() {
	mockClient := new(MockKeyAccessServerRegistryClient)
	log, _ := newBufferLogger()
	keyIndexer := NewPlatformKeyIndexer(&sdk.SDK{KeyAccessServerRegistry: mockClient}, "", false, log)

	mockClient.On("ListKeys", mock.Anything, mock.MatchedBy(func(req *kasregistry.ListKeysRequest) bool {
		return !req.GetLegacy()
	})).Return(&kasregistry.ListKeysResponse{
		KasKeys: []*policy.KasKey{
			{
				Key: &policy.AsymmetricKey{
					KeyId: testKeyID,
				},
			},
		},
	}, nil)

	keys, err := keyIndexer.ListKeys(context.Background())
	s.Require().NoError(err)
	s.Len(keys, 1)
	s.Equal(testKeyID, string(keys[0].ID()))
}

func (s *KeyIndexTestSuite) TestFindKeyWith() {
	for _, test := range []struct {
		name        string
		fromKAO     bool
		kasURI      string
		expectedURI string
	}{
		{name: "enabled uses request KAS URI", fromKAO: true, kasURI: requestKASURI, expectedURI: requestKASURI},
		{name: "disabled ignores request KAS URI", kasURI: requestKASURI, expectedURI: defaultKASURI},
		{name: "enabled defaults empty KAS URI", fromKAO: true, expectedURI: defaultKASURI},
		{name: "disabled defaults empty KAS URI", expectedURI: defaultKASURI},
	} {
		s.Run(test.name, func() {
			mockClient := new(MockKeyAccessServerRegistryClient)
			log, buf := newBufferLogger()
			keyIndexer := NewPlatformKeyIndexer(&sdk.SDK{KeyAccessServerRegistry: mockClient}, defaultKASURI, test.fromKAO, log)

			response := &kasregistry.GetKeyResponse{}
			mockClient.On("GetKey", mock.Anything, mock.MatchedBy(func(req *kasregistry.GetKeyRequest) bool {
				return req.GetKey().GetUri() == test.expectedURI && req.GetKey().GetKid() == testKeyID
			})).Run(func(args mock.Arguments) {
				req, ok := args.Get(1).(*kasregistry.GetKeyRequest)
				s.Require().True(ok)
				response.KasKey = &policy.KasKey{
					KasUri: req.GetKey().GetUri(),
					Key:    &policy.AsymmetricKey{KeyId: req.GetKey().GetKid()},
				}
			}).Return(response, nil).Once()

			key, err := keyIndexer.FindKeyWith(s.T().Context(), trust.FindKeyOptions{KeyOptions: trust.KeyOptions{ID: trust.KeyIdentifier(testKeyID), KASURI: test.kasURI}})
			s.Require().NoError(err)
			s.Equal(testKeyID, string(key.ID()))
			adapter, ok := key.(*KeyAdapter)
			s.Require().True(ok)
			s.Equal(test.expectedURI, adapter.key.GetKasUri())
			s.assertKeyIndexerLog(buf.Bytes(), test.expectedURI, keyIndexer)
			mockClient.AssertExpectations(s.T())
		})
	}
}

func (s *KeyIndexTestSuite) TestFindKeyByIDUsesConfiguredURI() {
	mockClient := new(MockKeyAccessServerRegistryClient)
	log, _ := newBufferLogger()
	keyIndexer := NewPlatformKeyIndexer(&sdk.SDK{KeyAccessServerRegistry: mockClient}, defaultKASURI, true, log)
	mockClient.On("GetKey", mock.Anything, mock.MatchedBy(func(req *kasregistry.GetKeyRequest) bool {
		return req.GetKey().GetUri() == defaultKASURI && req.GetKey().GetKid() == testKeyID
	})).Return(&kasregistry.GetKeyResponse{KasKey: &policy.KasKey{
		Key: &policy.AsymmetricKey{KeyId: testKeyID},
	}}, nil).Once()

	key, err := keyIndexer.FindKeyByID(s.T().Context(), testKeyID)
	s.Require().NoError(err)
	s.Equal(trust.KeyIdentifier(testKeyID), key.ID())
	mockClient.AssertExpectations(s.T())
}

func (s *KeyIndexTestSuite) TestFindKeyByAlgorithm() {
	mockClient := new(MockKeyAccessServerRegistryClient)
	log, _ := newBufferLogger()
	keyIndexer := NewPlatformKeyIndexer(&sdk.SDK{KeyAccessServerRegistry: mockClient}, defaultKASURI, true, log)

	mockClient.On("ListKeys", mock.Anything, mock.MatchedBy(func(req *kasregistry.ListKeysRequest) bool {
		return req.GetKasUri() == defaultKASURI && req.GetKeyAlgorithm() == policy.Algorithm_ALGORITHM_RSA_2048 && (req.Legacy != nil && req.GetLegacy() == false)
	})).Return(&kasregistry.ListKeysResponse{
		KasKeys: []*policy.KasKey{
			{
				Key: &policy.AsymmetricKey{
					KeyId:        testKeyID,
					KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
					KeyStatus:    policy.KeyStatus_KEY_STATUS_ACTIVE,
				},
			},
		},
	}, nil)

	mockClient.On("ListKeys", mock.Anything, mock.MatchedBy(func(req *kasregistry.ListKeysRequest) bool {
		return req.GetKasUri() == defaultKASURI && req.GetKeyAlgorithm() == policy.Algorithm_ALGORITHM_RSA_2048 && req.Legacy == nil
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
					KeyId:        testKeyID,
					KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
					KeyStatus:    policy.KeyStatus_KEY_STATUS_ACTIVE,
				},
			},
		},
	}, nil)

	key, err := keyIndexer.FindKeyByAlgorithm(context.Background(), string(ocrypto.RSA2048Key), false)
	s.Require().NoError(err)
	s.NotNil(key)
	s.Equal(testKeyID, string(key.ID()))

	key, err = keyIndexer.FindKeyByAlgorithm(context.Background(), string(ocrypto.RSA2048Key), true)
	s.Require().NoError(err)
	s.NotNil(key)
	s.Equal("test-legacy-key-id", string(key.ID()))
}

func (s *KeyIndexTestSuite) assertKeyIndexerLog(data []byte, expectedURI string, keyIndexer *KeyIndexer) {
	s.T().Helper()
	var record map[string]any
	s.Require().NoError(json.Unmarshal(data, &record))
	s.Equal(expectedURI, record["kas_uri"])
	s.Equal(keyIndexer.String(), record["key_indexer"])
}

func TestNewPlatformKeyIndexTestSuite(t *testing.T) {
	suite.Run(t, new(KeyIndexTestSuite))
}
