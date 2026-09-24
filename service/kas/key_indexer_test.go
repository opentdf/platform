package kas

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/trust"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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
	rsaKey   trust.KeyDetails
	fixtures keyIndexFixtures
}

func (s *KeyIndexTestSuite) SetupTest() {
	s.fixtures = newKeyIndexFixtures()
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
	f := s.fixtures
	for _, tc := range []struct {
		name           string
		uri            string
		includeDefault bool
		wantKeys       []*policy.KasKey
		wantLegacyKeys []*policy.KasKey
		wantURIs       []string
	}{
		{
			name:           "requested registration",
			uri:            requestKASURI,
			wantKeys:       []*policy.KasKey{f.requestShared, f.requestLegacy, f.requestNonLegacy},
			wantLegacyKeys: []*policy.KasKey{f.requestShared, f.requestLegacy},
			wantURIs:       []string{requestKASURI},
		},
		{
			name:           "default registration",
			uri:            defaultKASURI,
			wantKeys:       []*policy.KasKey{f.defaultShared, f.defaultLegacy, f.defaultNonLegacy},
			wantLegacyKeys: []*policy.KasKey{f.defaultShared, f.defaultLegacy},
			wantURIs:       []string{defaultKASURI},
		},
		{
			name:           "implicit default",
			wantKeys:       []*policy.KasKey{f.defaultShared, f.defaultLegacy, f.defaultNonLegacy},
			wantLegacyKeys: []*policy.KasKey{f.defaultShared, f.defaultLegacy},
			wantURIs:       []string{defaultKASURI},
		},
		{
			name:     "empty registration",
			uri:      emptyKASURI,
			wantURIs: []string{emptyKASURI},
		},
		{
			name:           "preserve shared KIDs with requested keys first",
			uri:            requestKASURI,
			includeDefault: true,
			wantKeys:       []*policy.KasKey{f.requestShared, f.requestLegacy, f.requestNonLegacy, f.defaultShared, f.defaultLegacy, f.defaultNonLegacy},
			wantLegacyKeys: []*policy.KasKey{f.requestShared, f.requestLegacy, f.defaultShared, f.defaultLegacy},
			wantURIs:       []string{requestKASURI, defaultKASURI},
		},
		{
			name:           "empty registration includes defaults",
			uri:            emptyKASURI,
			includeDefault: true,
			wantKeys:       []*policy.KasKey{f.defaultShared, f.defaultLegacy, f.defaultNonLegacy},
			wantLegacyKeys: []*policy.KasKey{f.defaultShared, f.defaultLegacy},
			wantURIs:       []string{emptyKASURI, defaultKASURI},
		},
		{
			name:           "empty URI lists default once",
			includeDefault: true,
			wantKeys:       []*policy.KasKey{f.defaultShared, f.defaultLegacy, f.defaultNonLegacy},
			wantLegacyKeys: []*policy.KasKey{f.defaultShared, f.defaultLegacy},
			wantURIs:       []string{defaultKASURI},
		},
		{
			name:           "explicit default lists once",
			uri:            defaultKASURI,
			includeDefault: true,
			wantKeys:       []*policy.KasKey{f.defaultShared, f.defaultLegacy, f.defaultNonLegacy},
			wantLegacyKeys: []*policy.KasKey{f.defaultShared, f.defaultLegacy},
			wantURIs:       []string{defaultKASURI},
		},
	} {
		for _, legacy := range []bool{false, true} {
			s.Run(fmt.Sprintf("%s/legacy=%t", tc.name, legacy), func() {
				t := s.T()
				client := &testKeyRegistry{keysByURI: f.keysByURI}
				index := NewPlatformKeyIndexer(&sdk.SDK{KeyAccessServerRegistry: client}, defaultKASURI, logger.CreateTestLogger())
				keys, err := index.ListKeysWith(t.Context(), trust.ListKeyOptions{
					KeyOptions: trust.KeyOptions{KASURI: tc.uri},
					LegacyOnly: legacy, IncludeDefaultKAS: tc.includeDefault,
				})
				require.NoError(t, err)
				wantKeys := tc.wantKeys
				if legacy {
					wantKeys = tc.wantLegacyKeys
				}
				assertRegistryKeys(t, wantKeys, keys)
				client.assertListRequests(t, legacy, tc.wantURIs)
			})
		}
	}
}

func (s *KeyIndexTestSuite) TestListKeysWithErrors() {
	f := s.fixtures
	for _, tc := range []struct {
		name           string
		uri            string
		includeDefault bool
		errorsByURI    map[string]error
		wantKeys       []*policy.KasKey
		wantLegacyKeys []*policy.KasKey
		wantURIs       []string
		wantErrors     []error
	}{
		{
			name:        "requested registration failure",
			uri:         requestKASURI,
			errorsByURI: map[string]error{requestKASURI: errRegistryUnavailable},
			wantURIs:    []string{requestKASURI},
			wantErrors:  []error{errRegistryUnavailable},
		},
		{
			name:        "default registration failure",
			uri:         defaultKASURI,
			errorsByURI: map[string]error{defaultKASURI: errRegistryUnavailable},
			wantURIs:    []string{defaultKASURI},
			wantErrors:  []error{errRegistryUnavailable},
		},
		{
			name:        "implicit default failure",
			errorsByURI: map[string]error{defaultKASURI: errRegistryUnavailable},
			wantURIs:    []string{defaultKASURI},
			wantErrors:  []error{errRegistryUnavailable},
		},
		{
			name:        "empty registration failure",
			uri:         emptyKASURI,
			errorsByURI: map[string]error{emptyKASURI: errRegistryUnavailable},
			wantURIs:    []string{emptyKASURI},
			wantErrors:  []error{errRegistryUnavailable},
		},
		{
			name:           "preserve defaults on scoped error",
			uri:            requestKASURI,
			includeDefault: true,
			errorsByURI:    map[string]error{requestKASURI: errRegistryScoped},
			wantKeys:       []*policy.KasKey{f.defaultShared, f.defaultLegacy, f.defaultNonLegacy},
			wantLegacyKeys: []*policy.KasKey{f.defaultShared, f.defaultLegacy},
			wantURIs:       []string{requestKASURI, defaultKASURI},
		},
		{
			name:           "preserve scoped on default error",
			uri:            requestKASURI,
			includeDefault: true,
			errorsByURI:    map[string]error{defaultKASURI: errRegistryDefault},
			wantKeys:       []*policy.KasKey{f.requestShared, f.requestLegacy, f.requestNonLegacy},
			wantLegacyKeys: []*policy.KasKey{f.requestShared, f.requestLegacy},
			wantURIs:       []string{requestKASURI, defaultKASURI},
		},
		{
			name:           "both fail",
			uri:            requestKASURI,
			includeDefault: true,
			errorsByURI:    map[string]error{requestKASURI: errRegistryScoped, defaultKASURI: errRegistryDefault},
			wantURIs:       []string{requestKASURI, defaultKASURI},
			wantErrors:     []error{errRegistryScoped, errRegistryDefault},
		},
		{
			name:           "default error does not relist",
			uri:            defaultKASURI,
			includeDefault: true,
			errorsByURI:    map[string]error{defaultKASURI: errRegistryDefault},
			wantURIs:       []string{defaultKASURI},
			wantErrors:     []error{errRegistryDefault},
		},
	} {
		for _, legacy := range []bool{false, true} {
			s.Run(fmt.Sprintf("%s/legacy=%t", tc.name, legacy), func() {
				t := s.T()
				client := &testKeyRegistry{keysByURI: f.keysByURI, errorsByURI: tc.errorsByURI}
				index := NewPlatformKeyIndexer(&sdk.SDK{KeyAccessServerRegistry: client}, defaultKASURI, logger.CreateTestLogger())
				keys, err := index.ListKeysWith(t.Context(), trust.ListKeyOptions{
					KeyOptions: trust.KeyOptions{KASURI: tc.uri},
					LegacyOnly: legacy, IncludeDefaultKAS: tc.includeDefault,
				})
				if len(tc.wantErrors) == 0 {
					require.NoError(t, err)
				} else {
					for _, wantErr := range tc.wantErrors {
						require.ErrorIs(t, err, wantErr)
					}
					for uri := range tc.errorsByURI {
						require.ErrorContains(t, err, uri)
					}
				}
				wantKeys := tc.wantKeys
				if legacy {
					wantKeys = tc.wantLegacyKeys
				}
				assertRegistryKeys(t, wantKeys, keys)
				client.assertListRequests(t, legacy, tc.wantURIs)
			})
		}
	}
}

func (s *KeyIndexTestSuite) TestListKeys() {
	client := &testKeyRegistry{keysByURI: s.fixtures.keysByURI}
	index := NewPlatformKeyIndexer(&sdk.SDK{KeyAccessServerRegistry: client}, defaultKASURI, logger.CreateTestLogger())
	keys, err := index.ListKeys(s.T().Context())
	s.Require().NoError(err)
	assertRegistryKeys(s.T(), s.fixtures.keysByURI[defaultKASURI], keys)
	client.assertListRequests(s.T(), false, []string{defaultKASURI})
}

func (s *KeyIndexTestSuite) TestFindKeyWith() {
	f := s.fixtures
	for _, tc := range []struct {
		name        string
		uri         string
		kid         trust.KeyIdentifier
		errorsByURI map[string]error
		wantKey     *policy.KasKey
		wantURIs    []string
		wantErr     error
	}{
		{name: "requested key wins", uri: requestKASURI, kid: trust.KeyIdentifier(f.requestShared.GetKey().GetKeyId()), wantKey: f.requestShared, wantURIs: []string{requestKASURI}},
		{name: "missing requested key falls back", uri: requestKASURI, kid: trust.KeyIdentifier(f.defaultLegacy.GetKey().GetKeyId()), wantKey: f.defaultLegacy, wantURIs: []string{requestKASURI, defaultKASURI}},
		{name: "wrapped NotFound retries default", uri: requestKASURI, kid: trust.KeyIdentifier(f.requestShared.GetKey().GetKeyId()), errorsByURI: map[string]error{requestKASURI: fmt.Errorf("lookup: %w", errRegistryKeyNotFound)}, wantKey: f.defaultShared, wantURIs: []string{requestKASURI, defaultKASURI}},
		{name: "both missing", uri: requestKASURI, kid: "missing", wantURIs: []string{requestKASURI, defaultKASURI}, wantErr: errRegistryKeyNotFound},
		{name: "default failure returned", uri: requestKASURI, kid: trust.KeyIdentifier(f.defaultLegacy.GetKey().GetKeyId()), errorsByURI: map[string]error{defaultKASURI: errRegistryDenied}, wantURIs: []string{requestKASURI, defaultKASURI}, wantErr: errRegistryDenied},
		{name: "denied does not retry", uri: requestKASURI, kid: trust.KeyIdentifier(f.requestShared.GetKey().GetKeyId()), errorsByURI: map[string]error{requestKASURI: errRegistryDenied}, wantURIs: []string{requestKASURI}, wantErr: errRegistryDenied},
		{name: "transport error does not retry", uri: requestKASURI, kid: trust.KeyIdentifier(f.requestShared.GetKey().GetKeyId()), errorsByURI: map[string]error{requestKASURI: errRegistryUnavailable}, wantURIs: []string{requestKASURI}, wantErr: errRegistryUnavailable},
		{name: "internal error does not retry", uri: requestKASURI, kid: trust.KeyIdentifier(f.requestShared.GetKey().GetKeyId()), errorsByURI: map[string]error{requestKASURI: errRegistryInternal}, wantURIs: []string{requestKASURI}, wantErr: errRegistryInternal},
		{name: "empty URI uses default once", kid: trust.KeyIdentifier(f.defaultShared.GetKey().GetKeyId()), wantKey: f.defaultShared, wantURIs: []string{defaultKASURI}},
		{name: "empty URI miss", kid: "missing", wantURIs: []string{defaultKASURI}, wantErr: errRegistryKeyNotFound},
		{name: "explicit default miss", uri: defaultKASURI, kid: "missing", wantURIs: []string{defaultKASURI}, wantErr: errRegistryKeyNotFound},
	} {
		s.Run(tc.name, func() {
			t := s.T()
			client := &testKeyRegistry{keysByURI: f.keysByURI, errorsByURI: tc.errorsByURI}
			index := NewPlatformKeyIndexer(&sdk.SDK{KeyAccessServerRegistry: client}, defaultKASURI, logger.CreateTestLogger())
			key, err := index.FindKeyWith(t.Context(), tc.kid, trust.FindKeyOptions{KeyOptions: trust.KeyOptions{KASURI: tc.uri}})
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, key)
			} else {
				require.NoError(t, err)
				assertRegistryKeys(t, []*policy.KasKey{tc.wantKey}, []trust.KeyDetails{key})
			}
			client.assertGetRequests(t, tc.kid, tc.wantURIs)
		})
	}
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
					KeyId:        testKeyID,
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

func TestNewPlatformKeyIndexTestSuite(t *testing.T) {
	suite.Run(t, new(KeyIndexTestSuite))
}
