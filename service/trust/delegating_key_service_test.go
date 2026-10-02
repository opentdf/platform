package trust

import (
	"context"
	"crypto/elliptic"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

func (m *MockKeyIndex) String() string {
	return "mockKeyIndex"
}

func (m *MockKeyIndex) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("Indexer", m.String()),
	)
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

func (m *MockKeyIndex) ListKeysWith(ctx context.Context, opts ListKeyOptions) ([]KeyDetails, error) {
	args := m.Called(ctx, opts)
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

func (m *MockKeyDetails) Algorithm() ocrypto.KeyType {
	args := m.Called()
	return ocrypto.KeyType(args.String(0))
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

func (m *MockEncapsulator) Encapsulate(dek ProtectedKey) ([]byte, error) {
	args := m.Called(dek)
	if a0, ok := args.Get(0).([]byte); ok {
		return a0, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockEncapsulator) Encrypt(data []byte) ([]byte, error) {
	args := m.Called(data)
	if a0, ok := args.Get(0).([]byte); ok {
		return a0, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockEncapsulator) PublicKeyAsPEM() (string, error) {
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

var _ ocrypto.Encapsulator = (*MockEncapsulator)(nil)

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

func (suite *DelegatingKeyServiceTestSuite) TestListKeysWith_Legacy() {
	legacyKey := &MockKeyDetails{}
	legacyKey.On("IsLegacy").Return(true)

	nonLegacyKey := &MockKeyDetails{}
	nonLegacyKey.On("IsLegacy").Return(false)

	suite.mockIndex.On("ListKeysWith", mock.Anything, ListKeyOptions{LegacyOnly: true}).Return([]KeyDetails{legacyKey}, nil)

	keys, err := suite.service.ListKeysWith(context.Background(), ListKeyOptions{LegacyOnly: true})
	suite.Require().NoError(err)
	suite.Len(keys, 1)
	suite.True(keys[0].IsLegacy())
}

func (suite *DelegatingKeyServiceTestSuite) TestDecrypt() {
	mockKeyDetails := &MockKeyDetails{}
	mockKeyDetails.On("ProviderConfig").Return(&policy.KeyProviderConfig{Manager: "mockManager", Name: "mock-01"})
	mockKeyDetails.On("System").Return("mockManager")
	suite.mockIndex.On("FindKeyByID", mock.Anything, KeyIdentifier("key1")).Return(mockKeyDetails, nil)

	mockProtectedKey := &MockProtectedKey{}
	mockProtectedKey.On("DecryptAESGCM", mock.Anything, mock.Anything, mock.Anything).Return([]byte("decrypted"), nil)
	suite.mockManagerA.On("Decrypt", mock.Anything, mockKeyDetails, []byte("ciphertext"), []byte("ephemeralKey")).Return(mockProtectedKey, nil)

	suite.service.RegisterKeyManagerCtx("mockManager", func(_ context.Context, _ *KeyManagerFactoryOptions) (KeyManager, error) {
		return suite.mockManagerA, nil
	})

	protectedKey, err := suite.service.Decrypt(context.Background(), KeyIdentifier("key1"), []byte("ciphertext"), []byte("ephemeralKey"))
	suite.Require().NoError(err)
	suite.NotNil(protectedKey)
}

func (suite *DelegatingKeyServiceTestSuite) TestDeriveKey() {
	mockKeyDetails := &MockKeyDetails{}
	mockKeyDetails.On("ProviderConfig").Return(&policy.KeyProviderConfig{Manager: "mockManager", Name: "mock-01"})
	mockKeyDetails.On("System").Return("mockManager")
	suite.mockIndex.On("FindKeyByID", mock.Anything, KeyIdentifier("key1")).Return(mockKeyDetails, nil)

	mockProtectedKey := &MockProtectedKey{}
	mockProtectedKey.On("Export", mock.Anything).Return([]byte("exported"), nil)
	suite.mockManagerA.On("DeriveKey", mock.Anything, mockKeyDetails, []byte("ephemeralKey"), elliptic.P256()).Return(mockProtectedKey, nil)

	suite.service.RegisterKeyManagerCtx("mockManager", func(_ context.Context, _ *KeyManagerFactoryOptions) (KeyManager, error) {
		return suite.mockManagerA, nil
	})

	protectedKey, err := suite.service.DeriveKey(context.Background(), KeyIdentifier("key1"), []byte("ephemeralKey"), elliptic.P256())
	suite.Require().NoError(err)
	suite.NotNil(protectedKey)
}

func (suite *DelegatingKeyServiceTestSuite) TestGenerateECSessionKey() {
	suite.service.RegisterKeyManagerCtx("default", func(_ context.Context, _ *KeyManagerFactoryOptions) (KeyManager, error) {
		return suite.mockManagerA, nil
	})
	suite.service.defaultMode = keyManagerDesignation{Manager: "default"}
	suite.mockManagerA.On("GenerateECSessionKey", mock.Anything, "ephemeralPublicKey").Return(&MockEncapsulator{}, nil)

	encapsulator, err := suite.service.GenerateECSessionKey(context.Background(), "ephemeralPublicKey")
	suite.Require().NoError(err)
	suite.IsType(&MockEncapsulator{}, encapsulator)
}

func TestDelegatingKeyServiceTestSuite(t *testing.T) {
	suite.Run(t, new(DelegatingKeyServiceTestSuite))
}

// failIfInvokedFactory returns a factory that fails the test if the
// DelegatingKeyService ever constructs a manager from it. SupportedAlgorithms
// must answer from registered metadata alone, never by invoking factories.
func failIfInvokedFactory(t *testing.T) KeyManagerFactoryCtx {
	t.Helper()
	return func(_ context.Context, _ *KeyManagerFactoryOptions) (KeyManager, error) {
		t.Fatalf("factory must not be invoked by SupportedAlgorithms")
		return nil, nil
	}
}

func TestDelegatingKeyService_SupportedAlgorithms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		register func(t *testing.T, d *DelegatingKeyService)
		want     []ocrypto.KeyType
	}{
		{
			name:     "no registrations returns empty",
			register: func(_ *testing.T, _ *DelegatingKeyService) {},
			want:     []ocrypto.KeyType{},
		},
		{
			name: "single registration",
			register: func(t *testing.T, d *DelegatingKeyService) {
				d.RegisterKeyManagerCtxWithAlgorithms("a", failIfInvokedFactory(t), []ocrypto.KeyType{"rsa:2048", "ec:secp256r1"})
			},
			want: []ocrypto.KeyType{"ec:secp256r1", "rsa:2048"},
		},
		{
			name: "two registrations, deduped and sorted",
			register: func(t *testing.T, d *DelegatingKeyService) {
				d.RegisterKeyManagerCtxWithAlgorithms("a", failIfInvokedFactory(t), []ocrypto.KeyType{"rsa:2048", "hpqt:xwing"})
				d.RegisterKeyManagerCtxWithAlgorithms("b", failIfInvokedFactory(t), []ocrypto.KeyType{"rsa:2048", "ec:secp256r1"})
			},
			want: []ocrypto.KeyType{"ec:secp256r1", "hpqt:xwing", "rsa:2048"},
		},
		{
			name: "registration without algorithms contributes nothing",
			register: func(t *testing.T, d *DelegatingKeyService) {
				d.RegisterKeyManagerCtxWithAlgorithms("a", failIfInvokedFactory(t), []ocrypto.KeyType{"rsa:2048"})
				d.RegisterKeyManagerCtx("b", failIfInvokedFactory(t))
			},
			want: []ocrypto.KeyType{"rsa:2048"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := NewDelegatingKeyService(&MockKeyIndex{}, logger.CreateTestLogger(), nil)
			tc.register(t, d)
			got := d.SupportedAlgorithms(context.Background())
			if got == nil {
				got = []ocrypto.KeyType{}
			}
			assert.Equal(t, tc.want, got)
			// Probing must never instantiate a manager — the cache stays empty.
			assert.Empty(t, d.managers, "SupportedAlgorithms must not populate the manager cache")
		})
	}
}

// TestDelegatingKeyService_SupportedAlgorithms_DoesNotInvokeFactories asserts
// the contract directly with a counter (in case the failIfInvokedFactory
// fast-path is ever bypassed via t.Run nesting).
func TestDelegatingKeyService_SupportedAlgorithms_DoesNotInvokeFactories(t *testing.T) {
	t.Parallel()

	var invocations atomic.Int32
	counting := func(_ context.Context, _ *KeyManagerFactoryOptions) (KeyManager, error) {
		invocations.Add(1)
		return &MockKeyManager{}, nil
	}

	d := NewDelegatingKeyService(&MockKeyIndex{}, logger.CreateTestLogger(), nil)
	d.RegisterKeyManagerCtxWithAlgorithms("a", counting, []ocrypto.KeyType{"rsa:2048"})
	d.RegisterKeyManagerCtxWithAlgorithms("b", counting, []ocrypto.KeyType{"ec:secp256r1"})

	_ = d.SupportedAlgorithms(context.Background())

	assert.Zero(t, invocations.Load(), "SupportedAlgorithms must not invoke any registered factory")
	assert.Empty(t, d.managers, "SupportedAlgorithms must not populate the manager cache")
}

// TestDelegatingKeyService_RegisterKeyManagerCtxWithAlgorithms_CopiesSlice
// guards against callers retaining/mutating the slice they pass at registration.
func TestDelegatingKeyService_RegisterKeyManagerCtxWithAlgorithms_CopiesSlice(t *testing.T) {
	t.Parallel()

	d := NewDelegatingKeyService(&MockKeyIndex{}, logger.CreateTestLogger(), nil)
	algs := []ocrypto.KeyType{"rsa:2048", "ec:secp256r1"}
	d.RegisterKeyManagerCtxWithAlgorithms("a", failIfInvokedFactory(t), algs)

	algs[0] = "tampered"

	got := d.SupportedAlgorithms(context.Background())
	want := []ocrypto.KeyType{"ec:secp256r1", "rsa:2048"}
	require.Equal(t, want, got, "registration must copy the algorithm slice")
}
