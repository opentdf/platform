package trust

import (
	"context"
	"crypto/elliptic"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type MockKeyManager struct {
	mock.Mock
}

func (m *MockKeyManager) Name() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockKeyManager) Decrypt(ctx context.Context, keyDetails KeyDetails, ciphertext []byte, ephemeralPublicKey []byte) (ProtectedKey, error) {
	args := m.Called(ctx, keyDetails, ciphertext, ephemeralPublicKey)
	if a0, ok := args.Get(0).(ProtectedKey); ok {
		return a0, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockKeyManager) DeriveKey(ctx context.Context, keyDetails KeyDetails, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) (ProtectedKey, error) {
	args := m.Called(ctx, keyDetails, ephemeralPublicKeyBytes, curve)
	if a0, ok := args.Get(0).(ProtectedKey); ok {
		return a0, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockKeyManager) GenerateECSessionKey(ctx context.Context, ephemeralPublicKey string) (Encapsulator, error) {
	args := m.Called(ctx, ephemeralPublicKey)
	if a0, ok := args.Get(0).(Encapsulator); ok {
		return a0, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockKeyManager) Close() {
	m.Called()
}

// MockKeyIndex is a mock implementation of the KeyIndex interface
type MockKeyIndex struct {
	mock.Mock
}

func (m *MockKeyIndex) FindKeyByAlgorithm(ctx context.Context, algorithm string, includeLegacy bool) (KeyDetails, error) {
	args := m.Called(ctx, algorithm, includeLegacy)
	if a0, ok := args.Get(0).(KeyDetails); ok {
		return a0, args.Error(1)
	}
	return &MockKeyDetails{}, args.Error(1)
}

func (m *MockKeyIndex) FindKeyByID(ctx context.Context, id KeyIdentifier) (KeyDetails, error) {
	args := m.Called(ctx, id)
	if a0, ok := args.Get(0).(KeyDetails); ok {
		return a0, args.Error(1)
	}
	return &MockKeyDetails{}, args.Error(1)
}

func (m *MockKeyIndex) ListKeys(ctx context.Context) ([]KeyDetails, error) {
	args := m.Called(ctx)
	if a0, ok := args.Get(0).([]KeyDetails); ok {
		return a0, args.Error(1)
	}
	return nil, args.Error(1)
}

// MockKeyDetails is a mock implementation of the KeyDetails interface
type MockKeyDetails struct {
	mock.Mock
}

func (m *MockKeyDetails) ID() KeyIdentifier {
	args := m.Called()
	if a0, ok := args.Get(0).(KeyIdentifier); ok {
		return a0
	}
	return KeyIdentifier("unknown")
}

func (m *MockKeyDetails) Algorithm() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockKeyDetails) IsLegacy() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockKeyDetails) ExportPrivateKey(_ context.Context) (*PrivateKey, error) {
	args := m.Called()
	if a0, ok := args.Get(0).(*PrivateKey); ok {
		return a0, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockKeyDetails) ExportPublicKey(ctx context.Context, format KeyType) (string, error) {
	args := m.Called(ctx, format)
	return args.String(0), args.Error(1)
}

func (m *MockKeyDetails) ExportCertificate(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	if a0, ok := args.Get(0).(string); ok {
		return a0, args.Error(1)
	}
	return "", args.Error(1)
}

func (m *MockKeyDetails) System() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockKeyDetails) ProviderConfig() *policy.KeyProviderConfig {
	args := m.Called()
	if a0, ok := args.Get(0).(*policy.KeyProviderConfig); ok {
		return a0
	}
	return nil
}

type MockProtectedKey struct {
	mock.Mock
}

func (m *MockProtectedKey) VerifyBinding(ctx context.Context, policy, binding []byte) error {
	args := m.Called(ctx, policy, binding)
	return args.Error(0)
}

func (m *MockProtectedKey) Export(encryptor Encapsulator) ([]byte, error) {
	args := m.Called(encryptor)
	if a0, ok := args.Get(0).([]byte); ok {
		return a0, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockProtectedKey) DecryptAESGCM(iv []byte, body []byte, tagSize int) ([]byte, error) {
	args := m.Called(iv, body, tagSize)
	if a0, ok := args.Get(0).([]byte); ok {
		return a0, args.Error(1)
	}
	return nil, args.Error(1)
}

type MockEncapsulator struct {
	mock.Mock
}

func (m *MockEncapsulator) Encrypt(data []byte) ([]byte, error) {
	args := m.Called(data)
	if a0, ok := args.Get(0).([]byte); ok {
		return a0, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockEncapsulator) PublicKeyInPemFormat() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockEncapsulator) EphemeralKey() []byte {
	args := m.Called()
	if a0, ok := args.Get(0).([]byte); ok {
		return a0
	}
	return nil
}

var _ Encapsulator = (*MockEncapsulator)(nil)

type DelegatingKeyServiceTestSuite struct {
	suite.Suite
	service      *DelegatingKeyService
	mockIndex    *MockKeyIndex
	mockManagerA *MockKeyManager
	mockManagerB *MockKeyManager
}

func (suite *DelegatingKeyServiceTestSuite) SetupTest() {
	suite.mockIndex = &MockKeyIndex{}
	suite.service = NewDelegatingKeyService(suite.mockIndex, logger.CreateTestLogger(), nil)
	suite.mockManagerA = &MockKeyManager{}
	suite.mockManagerB = &MockKeyManager{}
}

func (suite *DelegatingKeyServiceTestSuite) TestFindKeyByAlgorithm() {
	suite.mockIndex.On("FindKeyByAlgorithm", mock.Anything, "RSA", true).Return(&MockKeyDetails{}, nil)

	keyDetails, err := suite.service.FindKeyByAlgorithm(context.Background(), "RSA", true)
	suite.Require().NoError(err)
	suite.NotNil(keyDetails)
}

func (suite *DelegatingKeyServiceTestSuite) TestFindKeyByID() {
	suite.mockIndex.On("FindKeyByID", mock.Anything, KeyIdentifier("key1")).Return(&MockKeyDetails{}, nil)

	keyDetails, err := suite.service.FindKeyByID(context.Background(), KeyIdentifier("key1"))
	suite.Require().NoError(err)
	suite.NotNil(keyDetails)
}

func (suite *DelegatingKeyServiceTestSuite) TestListKeys() {
	suite.mockIndex.On("ListKeys", mock.Anything).Return([]KeyDetails{&MockKeyDetails{}}, nil)

	keys, err := suite.service.ListKeys(context.Background())
	suite.Require().NoError(err)
	suite.Len(keys, 1)
}

func (suite *DelegatingKeyServiceTestSuite) TestDecrypt() {
	mockKeyDetails := &MockKeyDetails{}
	mockKeyDetails.On("System").Return("mockManager")
	suite.mockIndex.On("FindKeyByID", mock.Anything, KeyIdentifier("key1")).Return(mockKeyDetails, nil)

	mockProtectedKey := &MockProtectedKey{}
	mockProtectedKey.On("DecryptAESGCM", mock.Anything, mock.Anything, mock.Anything).Return([]byte("decrypted"), nil)
	suite.mockManagerA.On("Decrypt", mock.Anything, mockKeyDetails, []byte("ciphertext"), []byte("ephemeralKey")).Return(mockProtectedKey, nil)

	suite.service.RegisterKeyManager("mockManager", func(_ *KeyManagerFactoryOptions) (KeyManager, error) {
		return suite.mockManagerA, nil
	})

	protectedKey, err := suite.service.Decrypt(context.Background(), KeyIdentifier("key1"), []byte("ciphertext"), []byte("ephemeralKey"))
	suite.Require().NoError(err)
	suite.NotNil(protectedKey)
}

func (suite *DelegatingKeyServiceTestSuite) TestDeriveKey() {
	mockKeyDetails := &MockKeyDetails{}
	mockKeyDetails.On("System").Return("mockManager")
	suite.mockIndex.On("FindKeyByID", mock.Anything, KeyIdentifier("key1")).Return(mockKeyDetails, nil)

	mockProtectedKey := &MockProtectedKey{}
	mockProtectedKey.On("Export", mock.Anything).Return([]byte("exported"), nil)
	suite.mockManagerA.On("DeriveKey", mock.Anything, mockKeyDetails, []byte("ephemeralKey"), elliptic.P256()).Return(mockProtectedKey, nil)

	suite.service.RegisterKeyManager("mockManager", func(_ *KeyManagerFactoryOptions) (KeyManager, error) {
		return suite.mockManagerA, nil
	})

	protectedKey, err := suite.service.DeriveKey(context.Background(), KeyIdentifier("key1"), []byte("ephemeralKey"), elliptic.P256())
	suite.Require().NoError(err)
	suite.NotNil(protectedKey)
}

func (suite *DelegatingKeyServiceTestSuite) TestGenerateECSessionKey() {
	suite.service.RegisterKeyManager("default", func(_ *KeyManagerFactoryOptions) (KeyManager, error) {
		return suite.mockManagerA, nil
	})
	suite.service.defaultMode = "default"
	suite.mockManagerA.On("GenerateECSessionKey", mock.Anything, "ephemeralPublicKey").Return(&MockEncapsulator{}, nil)

	encapsulator, err := suite.service.GenerateECSessionKey(context.Background(), "ephemeralPublicKey")
	suite.Require().NoError(err)
	suite.IsType(&MockEncapsulator{}, encapsulator)
}

func TestDelegatingKeyServiceTestSuite(t *testing.T) {
	suite.Run(t, new(DelegatingKeyServiceTestSuite))
}
