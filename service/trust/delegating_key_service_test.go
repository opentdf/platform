package trust

import (
	"context"
	"crypto/elliptic"
	"testing"

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

func (m *MockKeyManager) Decrypt(ctx context.Context, keyID KeyIdentifier, ciphertext []byte, ephemeralPublicKey []byte) (ProtectedKey, error) {
	args := m.Called(ctx, keyID, ciphertext, ephemeralPublicKey)
	return args.Get(0).(ProtectedKey), args.Error(1)
}

func (m *MockKeyManager) DeriveKey(ctx context.Context, kasKID KeyIdentifier, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) (ProtectedKey, error) {
	args := m.Called(ctx, kasKID, ephemeralPublicKeyBytes, curve)
	return args.Get(0).(ProtectedKey), args.Error(1)
}

func (m *MockKeyManager) GenerateECSessionKey(ctx context.Context, ephemeralPublicKey string) (Encapsulator, error) {
	args := m.Called(ctx, ephemeralPublicKey)
	return args.Get(0).(Encapsulator), args.Error(1)
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
	return args.Get(0).(KeyDetails), args.Error(1)
}

func (m *MockKeyIndex) FindKeyByID(ctx context.Context, id KeyIdentifier) (KeyDetails, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(KeyDetails), args.Error(1)
}

func (m *MockKeyIndex) ListKeys(ctx context.Context) ([]KeyDetails, error) {
	args := m.Called(ctx)
	return args.Get(0).([]KeyDetails), args.Error(1)
}

// MockKeyDetails is a mock implementation of the KeyDetails interface
type MockKeyDetails struct {
	mock.Mock
}

func (m *MockKeyDetails) ID() KeyIdentifier {
	args := m.Called()
	return args.Get(0).(KeyIdentifier)
}

func (m *MockKeyDetails) Algorithm() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockKeyDetails) IsLegacy() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockKeyDetails) ExportPublicKey(ctx context.Context, format KeyType) (string, error) {
	args := m.Called(ctx, format)
	return args.String(0), args.Error(1)
}

func (m *MockKeyDetails) ExportCertificate(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

func (m *MockKeyDetails) Mode() string {
	args := m.Called()
	return args.String(0)
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
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockProtectedKey) DecryptAESGCM(iv []byte, body []byte, tagSize int) ([]byte, error) {
	args := m.Called(iv, body, tagSize)
	return args.Get(0).([]byte), args.Error(1)
}

type DelegatingKeyServiceTestSuite struct {
	suite.Suite
	service      *DelegatingKeyService
	mockIndex    *MockKeyIndex
	mockManagerA *MockKeyManager
	mockManagerB *MockKeyManager
}

func (suite *DelegatingKeyServiceTestSuite) SetupTest() {
	suite.mockIndex = &MockKeyIndex{}
	suite.service = NewDelegatingKeyService(suite.mockIndex)
	suite.mockManagerA = &MockKeyManager{}
	suite.mockManagerB = &MockKeyManager{}
}

func (suite *DelegatingKeyServiceTestSuite) TestFindKeyByAlgorithm() {
	suite.mockIndex.On("FindKeyByAlgorithm", mock.Anything, "RSA", true).Return(&MockKeyDetails{}, nil)

	keyDetails, err := suite.service.FindKeyByAlgorithm(context.Background(), "RSA", true)
	suite.NoError(err)
	suite.NotNil(keyDetails)
}

func (suite *DelegatingKeyServiceTestSuite) TestFindKeyByID() {
	suite.mockIndex.On("FindKeyByID", mock.Anything, KeyIdentifier("key1")).Return(&MockKeyDetails{}, nil)

	keyDetails, err := suite.service.FindKeyByID(context.Background(), KeyIdentifier("key1"))
	suite.NoError(err)
	suite.NotNil(keyDetails)
}

func (suite *DelegatingKeyServiceTestSuite) TestListKeys() {
	suite.mockIndex.On("ListKeys", mock.Anything).Return([]KeyDetails{&MockKeyDetails{}}, nil)

	keys, err := suite.service.ListKeys(context.Background())
	suite.NoError(err)
	suite.Len(keys, 1)
}

func (suite *DelegatingKeyServiceTestSuite) TestDecrypt() {
	mockKeyDetails := &MockKeyDetails{}
	mockKeyDetails.On("Mode").Return("mockManager")
	suite.mockIndex.On("FindKeyByID", mock.Anything, KeyIdentifier("key1")).Return(mockKeyDetails, nil)

	mockProtectedKey := &MockProtectedKey{}
	mockProtectedKey.On("DecryptAESGCM", mock.Anything, mock.Anything, mock.Anything).Return([]byte("decrypted"), nil)
	suite.mockManagerA.On("Decrypt", mock.Anything, KeyIdentifier("key1"), []byte("ciphertext"), []byte("ephemeralKey")).Return(mockProtectedKey, nil)

	suite.service.RegisterKeyManager("mockManager", func() (KeyManager, error) {
		return suite.mockManagerA, nil
	})

	protectedKey, err := suite.service.Decrypt(context.Background(), KeyIdentifier("key1"), []byte("ciphertext"), []byte("ephemeralKey"))
	suite.NoError(err)
	suite.NotNil(protectedKey)
}

func (suite *DelegatingKeyServiceTestSuite) TestDeriveKey() {
	mockKeyDetails := &MockKeyDetails{}
	mockKeyDetails.On("Mode").Return("mockManager")
	suite.mockIndex.On("FindKeyByID", mock.Anything, KeyIdentifier("key1")).Return(mockKeyDetails, nil)

	mockProtectedKey := &MockProtectedKey{}
	mockProtectedKey.On("Export", mock.Anything).Return([]byte("exported"), nil)
	suite.mockManagerA.On("DeriveKey", mock.Anything, KeyIdentifier("key1"), []byte("ephemeralKey"), elliptic.P256()).Return(mockProtectedKey, nil)

	suite.service.RegisterKeyManager("mockManager", func() (KeyManager, error) {
		return suite.mockManagerA, nil
	})

	protectedKey, err := suite.service.DeriveKey(context.Background(), KeyIdentifier("key1"), []byte("ephemeralKey"), elliptic.P256())
	suite.NoError(err)
	suite.NotNil(protectedKey)
}

func (suite *DelegatingKeyServiceTestSuite) TestGenerateECSessionKey() {
	suite.service.RegisterKeyManager("default", func() (KeyManager, error) {
		return suite.mockManagerA, nil
	})
	suite.service.defaultMode = "default"
	suite.mockManagerA.On("GenerateECSessionKey", mock.Anything, "ephemeralPublicKey").Return(&MockKeyManager{}, nil)

	encapsulator, err := suite.service.GenerateECSessionKey(context.Background(), "ephemeralPublicKey")
	suite.NoError(err)
	suite.NotNil(encapsulator)
}

func TestDelegatingKeyServiceTestSuite(t *testing.T) {
	suite.Run(t, new(DelegatingKeyServiceTestSuite))
}
